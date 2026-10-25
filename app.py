"""TrustVault: small, deliberately explicit document access service.

Run with `python app.py`. Files are encrypted before reaching disk. Every API
request rechecks the current session and document grant in SQLite.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get("TRUSTVAULT_DATA", ROOT / "data")).resolve()
DB_PATH = DATA / "trustvault.sqlite3"
FILES = DATA / "objects"
MAX_FILE = 10 * 1024 * 1024
ALLOWED = {".pdf", ".txt", ".csv", ".png", ".jpg", ".jpeg", ".docx", ".xlsx"}
DB_LOCK = threading.RLock()
KEY_ENV = "TRUSTVAULT_ENCRYPTION_KEY"
AUDIT_ENV = "TRUSTVAULT_AUDIT_KEY"


def _secret(env: str, filename: str) -> bytes:
    supplied = os.environ.get(env)
    if supplied:
        try:
            key = base64.urlsafe_b64decode(supplied + "=" * (-len(supplied) % 4))
        except Exception as exc:
            raise RuntimeError(f"{env} must be URL-safe base64") from exc
        if len(key) != 32:
            raise RuntimeError(f"{env} must decode to exactly 32 bytes")
        return key
    path = DATA / filename
    if path.exists():
        return path.read_bytes()
    key = secrets.token_bytes(32)
    DATA.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as f:
        f.write(key)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return key


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    con.execute("PRAGMA journal_mode = WAL")
    return con


@contextmanager
def db_context():
    con=db()
    try:
        with con:
            yield con
    finally:
        con.close()


def init_db() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    FILES.mkdir(parents=True, exist_ok=True)
    con = db()
    con.executescript((ROOT / "schema.sql").read_text(encoding="utf-8"))
    con.commit()
    # Deterministic demo accounts, replace immediately outside a local demo.
    if not con.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        for username, role, password in (
            ("admin", "admin", "Admin-demo-7qP!"),
            ("owner", "owner", "Owner-demo-8rK!"),
            ("viewer", "viewer", "Viewer-demo-9sM!"),
            ("other", "viewer", "Other-demo-4wN!"),
        ):
            salt = secrets.token_bytes(16)
            ph = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
            con.execute("INSERT INTO users VALUES (?,?,?,?,?,1)", (str(uuid.uuid4()),username,role,salt,ph))
        con.commit()
    con.close()


def audit(con: sqlite3.Connection, actor: str | None, action: str, document_id: str | None,
          target_user: str | None, outcome: str, detail: str) -> None:
    # HMAC-linked rows make edits/reordering detectable when the key is held separately.
    key = _secret(AUDIT_ENV, "audit.key")
    prior = con.execute("SELECT entry_hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
    previous = prior[0] if prior else "0" * 64
    payload = json.dumps([now(), actor, action, document_id, target_user, outcome, detail, previous],
                         ensure_ascii=False, separators=(",", ":"))
    at, *_ = json.loads(payload)
    digest = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
    con.execute("INSERT INTO audit(at,actor,action,document_id,target_user,outcome,detail,previous_hash,entry_hash) VALUES(?,?,?,?,?,?,?,?,?)",
                (at,actor,action,document_id,target_user,outcome,detail,previous,digest))


def password_hash(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)


def recovery_code() -> str:
    return secrets.token_urlsafe(24)


def recovery_hash(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def password_is_valid(value) -> bool:
    if not isinstance(value, str):
        return False
    try:
        size=len(value.encode("utf-8"))
    except UnicodeError:
        return False
    return 12 <= size <= 256


class Handler(BaseHTTPRequestHandler):
    server_version = "TrustVault/0.1"

    def log_message(self, fmt, *args):
        return

    def send_json(self, status: int, payload: object) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def body(self, limit: int = 65536) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("invalid Content-Length")
        if length < 0 or length > limit:
            raise OverflowError("request body too large")
        return self.rfile.read(length)

    def json_body(self) -> dict:
        raw = self.body()
        data = json.loads(raw or b"{}")
        if not isinstance(data, dict):
            raise ValueError("expected JSON object")
        return data

    def auth(self, con: sqlite3.Connection, write: bool = False):
        token = self.headers.get("Authorization", "")
        if not token.startswith("Bearer "):
            token = ""
        th = hashlib.sha256(token[7:].encode()).hexdigest() if token else ""
        row = con.execute("SELECT u.*,s.csrf FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires>? AND u.active=1",
                          (th, int(time.time()))).fetchone()
        if not row:
            route_parts=[p for p in urlparse(self.path).path.split("/") if p]
            document_id=route_parts[2] if len(route_parts)>=3 and route_parts[:2]==["api","documents"] else None
            if token or document_id:
                action="document_access" if document_id else "authentication"
                reason="invalid or expired bearer token" if token else "missing bearer token"
                audit(con, None, action, document_id, None, "denied", reason)
                con.commit()
            return None
        if write:
            origin = self.headers.get("Origin")
            host = self.headers.get("Host")
            if origin and urlparse(origin).netloc != host:
                audit(con, row["id"], "request", None, None, "denied", "origin check failed")
                con.commit()
                return None
            if not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), row["csrf"]):
                audit(con, row["id"], "request", None, None, "denied", "CSRF token missing or invalid")
                con.commit()
                return None
        return row

    def deny(self, con, user, action, doc_id, detail, status=404):
        audit(con, user["id"] if user else None, action, doc_id, None, "denied", detail)
        con.commit()
        self.send_json(status, {"error": "not found" if status == 404 else "forbidden"})

    def do_GET(self): self.route()
    def do_POST(self): self.route()
    def do_PUT(self): self.route()
    def do_DELETE(self): self.route()
    def do_PATCH(self): self.route()
    def do_HEAD(self): self.route()

    def route(self):
        path = urlparse(self.path).path
        parts = [p for p in path.split("/") if p]
        try:
            with DB_LOCK, db_context() as con:
                if path == "/api/health" and self.command == "GET":
                    return self.send_json(200, {"status": "ok"})
                if path in ("/", "/index.html", "/ui.js", "/style.css") and self.command == "GET":
                    filename={"/":"index.html","/index.html":"index.html","/ui.js":"ui.js","/style.css":"style.css"}[path]
                    content=(ROOT/"web"/filename).read_bytes()
                    content_type=mimetypes.guess_type(filename)[0] or "application/octet-stream"
                    self.send_response(200);self.send_header("Content-Type",content_type);self.send_header("Content-Length",str(len(content)))
                    self.send_header("Cache-Control","no-store");self.send_header("X-Content-Type-Options","nosniff")
                    self.send_header("Content-Security-Policy","default-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
                    self.end_headers();return self.wfile.write(content)
                if path == "/api/register" and self.command == "POST":
                    origin=self.headers.get("Origin")
                    if origin and urlparse(origin).netloc != self.headers.get("Host"):
                        audit(con,None,"registration",None,None,"denied","origin check failed")
                        con.commit();return self.send_json(403,{"error":"request denied"})
                    data=self.json_body()
                    username=str(data.get("username","")).strip().lower()
                    password=data.get("password")
                    valid_username=bool(re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,31}",username))
                    if not valid_username or not password_is_valid(password) or con.execute("SELECT 1 FROM users WHERE username=?",(username,)).fetchone():
                        audit(con,None,"registration",None,None,"denied","invalid account details or username unavailable")
                        con.commit();return self.send_json(400,{"error":"could not create account; check username and password rules"})
                    salt=secrets.token_bytes(16);user_id=str(uuid.uuid4());code=recovery_code()
                    con.execute("INSERT INTO users(id,username,role,salt,password_hash,active) VALUES(?,?,?,?,?,1)",(user_id,username,"viewer",salt,password_hash(password,salt)))
                    con.execute("INSERT INTO recovery_codes(user_id,code_hash,created_at) VALUES(?,?,?)",(user_id,recovery_hash(code),now()))
                    audit(con,None,"registration",None,user_id,"allowed","viewer account created; one-time recovery code issued")
                    con.commit();return self.send_json(201,{"ok":True,"username":username,"recovery_code":code})
                if path == "/api/password/reset" and self.command == "POST":
                    origin=self.headers.get("Origin")
                    if origin and urlparse(origin).netloc != self.headers.get("Host"):
                        audit(con,None,"password_reset",None,None,"denied","origin check failed")
                        con.commit();return self.send_json(403,{"error":"recovery request could not be completed"})
                    data=self.json_body();username=str(data.get("username","")).strip().lower()
                    supplied=data.get("recovery_code");new=data.get("new_password")
                    row=con.execute("SELECT u.id,u.active,rc.code_hash FROM users u LEFT JOIN recovery_codes rc ON rc.user_id=u.id WHERE u.username=?",(username,)).fetchone()
                    code_text=supplied if isinstance(supplied,str) and len(supplied)<=128 else ""
                    candidate=recovery_hash(code_text)
                    expected=row["code_hash"] if row and row["code_hash"] else "0"*64
                    code_ok=bool(row and row["active"] and row["code_hash"] and hmac.compare_digest(candidate,expected))
                    if not code_ok or not password_is_valid(new):
                        audit(con,None,"password_reset",None,row["id"] if row else None,"denied","recovery request could not be completed")
                        con.commit();return self.send_json(400,{"error":"recovery request could not be completed"})
                    salt=secrets.token_bytes(16);next_code=recovery_code()
                    con.execute("UPDATE users SET salt=?,password_hash=? WHERE id=?",(salt,password_hash(new,salt),row["id"]))
                    con.execute("DELETE FROM sessions WHERE user_id=?",(row["id"],))
                    con.execute("UPDATE recovery_codes SET code_hash=?,created_at=? WHERE user_id=?",(recovery_hash(next_code),now(),row["id"]))
                    audit(con,None,"password_reset",None,row["id"],"allowed","password reset; all sessions revoked; recovery code rotated")
                    con.commit();return self.send_json(200,{"ok":True,"recovery_code":next_code})
                if path == "/api/login" and self.command == "POST":
                    data = self.json_body()
                    user = con.execute("SELECT * FROM users WHERE username=? AND active=1", (str(data.get("username"," ")).strip().lower(),)).fetchone()
                    password_value=data.get("password", "")
                    try: password_size=len(password_value.encode("utf-8")) if isinstance(password_value,str) else 257
                    except UnicodeError: password_size=257
                    password=password_value if password_size<=256 else ""
                    ok = bool(user) and hmac.compare_digest(password_hash(password, user["salt"]), user["password_hash"])
                    if not ok:
                        audit(con, user["id"] if user else None, "login", None, None, "denied", "invalid credentials")
                        con.commit(); return self.send_json(401, {"error":"invalid credentials"})
                    raw = secrets.token_urlsafe(32); csrf = secrets.token_urlsafe(24)
                    con.execute("INSERT INTO sessions VALUES (?,?,?,?)", (hashlib.sha256(raw.encode()).hexdigest(),user["id"],csrf,int(time.time())+3600))
                    audit(con,user["id"],"login",None,None,"allowed","session created"); con.commit()
                    return self.send_json(200,{"token":raw,"csrf":csrf,"expires_in":3600,"user":{"id":user["id"],"username":user["username"],"role":user["role"]}})
                if path == "/api/logout" and self.command == "POST":
                    user=self.auth(con,True)
                    if not user: return self.send_json(401,{"error":"unauthorized"})
                    con.execute("DELETE FROM sessions WHERE user_id=? AND token_hash=?",(user["id"],hashlib.sha256(self.headers["Authorization"][7:].encode()).hexdigest()))
                    audit(con,user["id"],"logout",None,None,"allowed","session revoked"); con.commit(); return self.send_json(200,{"ok":True})
                user=self.auth(con, self.command in ("POST","PUT","DELETE","PATCH"))
                if not user: return self.send_json(401,{"error":"unauthorized"})
                if path == "/api/me" and self.command == "GET":
                    return self.send_json(200,{"id":user["id"],"username":user["username"],"role":user["role"]})
                if path == "/api/password" and self.command == "POST":
                    data=self.json_body()
                    current=data.get("current_password")
                    new=data.get("new_password")
                    valid_types=isinstance(current,str) and isinstance(new,str)
                    try: current_size=len(current.encode("utf-8")) if valid_types else 257
                    except UnicodeError: current_size=257
                    valid_size=valid_types and current_size<=256 and password_is_valid(new)
                    matches=valid_types and current_size<=256 and hmac.compare_digest(password_hash(current,user["salt"]),user["password_hash"])
                    if not matches or not valid_size:
                        audit(con,user["id"],"password_change",None,None,"denied","incorrect current password or new password outside 12-256 byte policy")
                        con.commit();return self.send_json(400,{"error":"current password incorrect or new password must be 12-256 bytes"})
                    salt=secrets.token_bytes(16)
                    con.execute("UPDATE users SET salt=?,password_hash=? WHERE id=?",(salt,password_hash(new,salt),user["id"]))
                    con.execute("DELETE FROM sessions WHERE user_id=?",(user["id"],))
                    code=recovery_code()
                    con.execute("INSERT INTO recovery_codes(user_id,code_hash,created_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET code_hash=excluded.code_hash,created_at=excluded.created_at",(user["id"],recovery_hash(code),now()))
                    audit(con,user["id"],"password_change",None,None,"allowed","password changed; all sessions revoked; recovery code rotated")
                    con.commit();return self.send_json(200,{"ok":True,"reauthentication_required":True,"recovery_code":code})
                if path == "/api/users" and self.command == "GET":
                    if user["role"]!="owner": return self.deny(con,user,"user_directory",None,"owner role required",403)
                    rows=con.execute("SELECT id,username,role FROM users WHERE active=1 ORDER BY username").fetchall()
                    return self.send_json(200,[dict(r) for r in rows])
                if path == "/api/documents" and self.command == "GET":
                    qs=parse_qs(urlparse(self.path).query)
                    clauses=["d.deleted=0"]; params=[]
                    clauses.append("(d.owner_id=? OR EXISTS(SELECT 1 FROM grants g WHERE g.document_id=d.id AND g.user_id=?))")
                    params += [user["id"],user["id"]]
                    for key,col in (("name","d.name"),("owner","u.username"),("category","d.category")):
                        val=qs.get(key,[""])[0]
                        if val: clauses.append(f"{col} LIKE ? ESCAPE '\\'"); params.append("%"+val.replace("%","\\%").replace("_","\\_")+"%")
                    for key,op in (("from",">="),("to","<=")):
                        val=qs.get(key,[""])[0]
                        if val: clauses.append(f"date(d.created_at) {op} date(?)"); params.append(val)
                    sql="SELECT d.id,d.name,d.category,d.owner_id,u.username owner,d.created_at,d.updated_at,d.size,d.mime,d.sha256,CASE WHEN d.owner_id=? THEN 'owner' ELSE g.permission END permission FROM documents d JOIN users u ON u.id=d.owner_id LEFT JOIN grants g ON g.document_id=d.id AND g.user_id=? WHERE "+" AND ".join(clauses)+" ORDER BY d.created_at DESC LIMIT 200"
                    rows=con.execute(sql,[user["id"],user["id"]]+params).fetchall()
                    return self.send_json(200,[dict(r) for r in rows])
                if parts[:2] == ["api","documents"] and len(parts)>=3:
                    doc_id=parts[2]
                    doc=con.execute("SELECT * FROM documents WHERE id=? AND deleted=0",(doc_id,)).fetchone()
                    grant=con.execute("SELECT permission FROM grants WHERE document_id=? AND user_id=?",(doc_id,user["id"])).fetchone()
                    owner=bool(doc and doc["owner_id"]==user["id"])
                    permitted=bool(doc and (owner or grant))
                    permission="edit" if owner or (grant and grant["permission"]=="edit") else ("read" if grant else "")
                    if not permitted:
                        return self.deny(con,user,"document_access",doc_id,"document absent, deleted, or no active grant")
                    if len(parts)==3 and self.command=="GET":
                        audit(con,user["id"],"document_read",doc_id,None,"allowed","metadata viewed"); con.commit()
                        return self.send_json(200,{"id":doc["id"],"name":doc["name"],"category":doc["category"],"owner_id":doc["owner_id"],"created_at":doc["created_at"],"updated_at":doc["updated_at"],"size":doc["size"],"mime":doc["mime"],"sha256":doc["sha256"],"permission":permission})
                    if len(parts)==4 and parts[3]=="content" and self.command=="GET":
                        audit(con,user["id"],"download",doc_id,None,"allowed","encrypted object decrypted for response"); con.commit()
                        try:
                            encrypted=(FILES/doc["stored_name"]).read_bytes()
                            plain=AESGCM(_secret(KEY_ENV,"encryption.key")).decrypt(encrypted[:12],encrypted[12:],doc_id.encode())
                        except Exception:
                            return self.send_json(500,{"error":"stored object unavailable"})
                        self.send_response(200); self.send_header("Content-Type",doc["mime"]); self.send_header("Content-Length",str(len(plain))); self.send_header("Content-Disposition",f"attachment; filename*=UTF-8''{__import__('urllib.parse').parse.quote(doc['name'])}"); self.send_header("Cache-Control","no-store"); self.send_header("X-Content-Type-Options","nosniff"); self.end_headers(); return self.wfile.write(plain)
                    if len(parts)==4 and parts[3]=="content" and self.command=="PUT":
                        if permission!="edit": return self.deny(con,user,"document_change",doc_id,"edit grant required",403)
                        raw=self.body(MAX_FILE)
                        if not raw: return self.send_json(400,{"error":"empty file"})
                        nonce=secrets.token_bytes(12); encrypted=nonce+AESGCM(_secret(KEY_ENV,"encryption.key")).encrypt(nonce,raw,doc_id.encode())
                        new_stored=f"{doc_id}-{uuid.uuid4()}.bin";tmp=FILES/(new_stored+".tmp");tmp.write_bytes(encrypted);tmp.replace(FILES/new_stored)
                        con.execute("UPDATE documents SET stored_name=?,size=?,sha256=?,updated_at=? WHERE id=?",(new_stored,len(raw),hashlib.sha256(raw).hexdigest(),now(),doc_id))
                        audit(con,user["id"],"change",doc_id,None,"allowed",f"file replaced; {len(raw)} bytes; sha256={hashlib.sha256(raw).hexdigest()}");con.commit()
                        return self.send_json(200,{"ok":True,"size":len(raw)})
                    if len(parts)==3 and self.command=="PUT":
                        if permission!="edit": return self.deny(con,user,"document_edit",doc_id,"edit grant required",403)
                        data=self.json_body(); name=valid_name(data.get("name",doc["name"]))
                        category=valid_category(data.get("category",doc["category"]))
                        con.execute("UPDATE documents SET name=?,category=?,updated_at=? WHERE id=?",(name,category,now(),doc_id))
                        audit(con,user["id"],"change",doc_id,None,"allowed","metadata updated");con.commit();return self.send_json(200,{"ok":True})
                    if len(parts)==3 and self.command=="DELETE":
                        if not owner: return self.deny(con,user,"document_delete",doc_id,"only owner may delete",403)
                        con.execute("UPDATE documents SET deleted=1,updated_at=? WHERE id=?",(now(),doc_id))
                        con.execute("DELETE FROM grants WHERE document_id=?",(doc_id,))
                        audit(con,user["id"],"deletion",doc_id,None,"allowed","soft delete; grants removed");con.commit();return self.send_json(200,{"ok":True})
                    if len(parts)==4 and parts[3]=="permissions" and self.command=="GET":
                        if not owner: return self.deny(con,user,"permission_list",doc_id,"owner only",403)
                        rows=con.execute("SELECT g.user_id,u.username,g.permission,g.granted_by,g.granted_at FROM grants g JOIN users u ON u.id=g.user_id WHERE g.document_id=? ORDER BY u.username",(doc_id,)).fetchall()
                        return self.send_json(200,[dict(r) for r in rows])
                    if len(parts)==4 and parts[3]=="permissions" and self.command in ("POST","DELETE"):
                        if not owner: return self.deny(con,user,"permission_change",doc_id,"owner only",403)
                        data=self.json_body(); target=con.execute("SELECT * FROM users WHERE id=? AND active=1",(str(data.get("user_id","")),)).fetchone()
                        if not target: return self.send_json(400,{"error":"unknown user"})
                        if target["id"]==doc["owner_id"]: return self.send_json(400,{"error":"owner retains access"})
                        if self.command=="POST":
                            perm=data.get("permission")
                            if perm not in ("read","edit"): return self.send_json(400,{"error":"permission must be read or edit"})
                            con.execute("INSERT INTO grants VALUES (?,?,?,?,?) ON CONFLICT(document_id,user_id) DO UPDATE SET permission=excluded.permission,granted_by=excluded.granted_by,granted_at=excluded.granted_at",(doc_id,target["id"],perm,user["id"],now()))
                            action="grant";detail=f"{perm} granted to {target['username']}"
                        else:
                            con.execute("DELETE FROM grants WHERE document_id=? AND user_id=?",(doc_id,target["id"]))
                            action="revoke";detail=f"grant removed for {target['username']}"
                        audit(con,user["id"],action,doc_id,target["id"],"allowed",detail);con.commit();return self.send_json(200,{"ok":True})
                if path == "/api/documents" and self.command=="POST":
                    if user["role"] != "owner":
                        return self.deny(con,user,"upload",None,"owner role required",403)
                    name=valid_name(self.headers.get("X-File-Name",""));category=valid_category(self.headers.get("X-Category","uncategorized"))
                    raw=self.body(MAX_FILE)
                    if not raw: return self.send_json(400,{"error":"empty file"})
                    ext=Path(name).suffix.lower()
                    if ext not in ALLOWED: return self.send_json(415,{"error":"file type not allowed"})
                    mime=mimetypes.guess_type(name)[0] or "application/octet-stream"
                    if mime.startswith(("text/html","image/svg")): return self.send_json(415,{"error":"active content not allowed"})
                    did=str(uuid.uuid4()); stored=f"{did}.bin"; nonce=secrets.token_bytes(12)
                    ciphertext=nonce+AESGCM(_secret(KEY_ENV,"encryption.key")).encrypt(nonce,raw,did.encode())
                    tmp=FILES/(stored+".tmp"); dest=FILES/stored
                    tmp.write_bytes(ciphertext);tmp.replace(dest)
                    con.execute("INSERT INTO documents(id,name,category,owner_id,created_at,updated_at,stored_name,size,sha256,mime) VALUES(?,?,?,?,?,?,?,?,?,?)",(did,name,category,user["id"],now(),now(),stored,len(raw),hashlib.sha256(raw).hexdigest(),mime))
                    audit(con,user["id"],"upload",did,None,"allowed",f"encrypted upload; {len(raw)} bytes; sha256={hashlib.sha256(raw).hexdigest()}");con.commit()
                    return self.send_json(201,{"id":did,"name":name,"size":len(raw)})
                if path == "/api/admin/activity" and self.command=="GET":
                    if user["role"]!="admin": return self.deny(con,user,"admin_activity",None,"admin role required",403)
                    qs=parse_qs(urlparse(self.path).query); limit=min(max(int(qs.get("limit",["100"])[0]),1),500)
                    rows=con.execute("SELECT a.seq,a.at,a.actor,u.username actor_name,a.action,a.document_id,d.name document_name,a.target_user,t.username target_name,a.outcome,a.detail,a.previous_hash,a.entry_hash FROM audit a LEFT JOIN users u ON u.id=a.actor LEFT JOIN users t ON t.id=a.target_user LEFT JOIN documents d ON d.id=a.document_id ORDER BY a.seq DESC LIMIT ?",(limit,)).fetchall()
                    return self.send_json(200,[dict(r) for r in rows])
                if path == "/api/admin/audit/verify" and self.command=="GET":
                    if user["role"]!="admin": return self.deny(con,user,"audit_verify",None,"admin role required",403)
                    rows=con.execute("SELECT * FROM audit ORDER BY seq").fetchall(); previous="0"*64; key=_secret(AUDIT_ENV,"audit.key")
                    for r in rows:
                        payload=json.dumps([r["at"],r["actor"],r["action"],r["document_id"],r["target_user"],r["outcome"],r["detail"],previous],ensure_ascii=False,separators=(",",":"))
                        expected=hmac.new(key,payload.encode(),hashlib.sha256).hexdigest()
                        if r["previous_hash"]!=previous or not hmac.compare_digest(r["entry_hash"],expected): return self.send_json(200,{"valid":False,"broken_at_seq":r["seq"]})
                        previous=r["entry_hash"]
                    return self.send_json(200,{"valid":True,"entries":len(rows)})
                if parts[:2]==["api","documents"] and len(parts)>=3:
                    return self.deny(con,user,"document_operation",parts[2],f"unsupported operation: {self.command} {path}",404)
                return self.send_json(404,{"error":"not found"})
        except OverflowError as e: return self.send_json(413,{"error":str(e)})
        except (ValueError, json.JSONDecodeError) as e: return self.send_json(400,{"error":str(e)})
        except (sqlite3.Error, OSError) as e:
            return self.send_json(500,{"error":"internal server error"})


def valid_name(value) -> str:
    name=str(value).strip()
    if not name or len(name)>180 or name in (".","..") or any(c in name for c in "\\/\x00\r\n"):
        raise ValueError("invalid filename")
    if Path(name).suffix.lower() not in ALLOWED: raise ValueError("file type not allowed")
    return name


def valid_category(value) -> str:
    value=str(value).strip()
    if not value or len(value)>80 or any(ord(c)<32 for c in value): raise ValueError("invalid category")
    return value


if __name__ == "__main__":
    init_db()
    host=os.environ.get("TRUSTVAULT_HOST","127.0.0.1")
    port=int(os.environ.get("PORT","8000"))
    print(f"TrustVault listening on http://{host}:{port}")
    ThreadingHTTPServer((host,port),Handler).serve_forever()
