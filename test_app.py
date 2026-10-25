"""Integration tests exercise the actual HTTP authorization boundary."""
import json
import os
import tempfile
import io
import unittest
from email.message import Message

import app


class TrustVaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (app.ROOT/"work").mkdir(exist_ok=True)
        cls.tmp=tempfile.TemporaryDirectory(dir=app.ROOT/"work")
        app.DATA=app.Path(cls.tmp.name)
        app.DB_PATH=app.DATA/"db.sqlite3"
        app.FILES=app.DATA/"objects"
        for key in (app.KEY_ENV,app.AUDIT_ENV): os.environ.pop(key,None)
        app.init_db()
        cls.tokens={}
        con=app.db()
        for r in con.execute("SELECT id,username FROM users"):
            cls.tokens[r["username"]]=r["id"]
        con.close()
        cls.login("owner","Owner-demo-8rK!"); cls.login("viewer","Viewer-demo-9sM!")
        cls.login("other","Other-demo-4wN!"); cls.login("admin","Admin-demo-7qP!")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def login(cls,name,password):
        out=cls.call("POST","/api/login",{"username":name,"password":password},auth=False)
        cls.tokens[name]={"id":out["user"]["id"],"token":out["token"],"csrf":out["csrf"]}

    @classmethod
    def call(cls,method,path,data=None,who=None,auth=True,raw=None,headers=None,expected=None):
        h=dict(headers or {})
        if auth and who:
            s=cls.tokens[who];h["Authorization"]="Bearer "+s["token"]
            if method in ("POST","PUT","DELETE","PATCH"): h["X-CSRF-Token"]=s["csrf"]
        if data is not None:
            raw=json.dumps(data).encode();h["Content-Type"]="application/json"
        request=object.__new__(app.Handler)
        request.path=path;request.command=method;request.headers=Message()
        for k,v in h.items(): request.headers[k]=v
        if raw is not None: request.headers["Content-Length"]=str(len(raw))
        request.rfile=io.BytesIO(raw or b"");request.wfile=io.BytesIO();request.response_code=None
        request.send_response=lambda status,*args:setattr(request,"response_code",status)
        request.send_header=lambda *args:None
        request.end_headers=lambda:None
        def send_json(status,payload):
            request.response_code=status;request.result=payload
        request.send_json=send_json
        request.route()
        if expected is not None: assert request.response_code==expected,(request.response_code,getattr(request,"result",None))
        if hasattr(request,"result"): return request.result
        return request.wfile.getvalue()

    def upload(self):
        out=self.call("POST","/api/documents",who="owner",raw=b"classified salary detail",headers={"X-File-Name":"salary.txt","X-Category":"HR"},expected=201)
        return out["id"]

    def grant(self,doc,who="viewer",permission="read"):
        target=self.tokens[who]["id"]
        return self.call("POST",f"/api/documents/{doc}/permissions",{"user_id":target,"permission":permission},who="owner",expected=200)

    def test_ungranted_user_cannot_list_read_download_change_or_delete_document(self):
        doc=self.upload()
        self.assertNotIn(doc,[r["id"] for r in self.call("GET","/api/documents",who="other")])
        self.call("GET",f"/api/documents/{doc}",who="other",expected=404)
        self.call("GET",f"/api/documents/{doc}/content",who="other",expected=404)
        self.call("PUT",f"/api/documents/{doc}",{"name":"stolen.txt"},who="other",expected=404)
        self.call("DELETE",f"/api/documents/{doc}",who="other",expected=404)
        self.call("PATCH",f"/api/documents/{doc}",who="other",expected=404)
        self.assertTrue((app.FILES/(doc+".bin")).exists())

    def test_grant_and_revoke_take_effect_on_same_token_immediately(self):
        doc=self.upload();self.grant(doc)
        self.assertEqual(self.call("GET",f"/api/documents/{doc}",who="viewer")["name"],"salary.txt")
        self.call("GET",f"/api/documents/{doc}/content",who="viewer",expected=200)
        self.call("DELETE",f"/api/documents/{doc}/permissions",{"user_id":self.tokens["viewer"]["id"]},who="owner",expected=200)
        self.call("GET",f"/api/documents/{doc}/content",who="viewer",expected=404)

    def test_read_grant_cannot_edit_but_edit_grant_can_change_metadata(self):
        doc=self.upload();self.grant(doc)
        self.call("PUT",f"/api/documents/{doc}",{"name":"salary2.txt"},who="viewer",expected=403)
        self.grant(doc,permission="edit")
        self.call("PUT",f"/api/documents/{doc}",{"name":"salary2.txt"},who="viewer",expected=200)
        self.call("PUT",f"/api/documents/{doc}/content",who="viewer",raw=b"revised file",expected=200)
        self.assertEqual(self.call("GET",f"/api/documents/{doc}/content",who="viewer",expected=200),b"revised file")

    def test_validation_and_csrf(self):
        self.call("POST","/api/documents",who="owner",raw=b"bad",headers={"X-File-Name":"payload.html"},expected=400)
        self.call("POST","/api/documents",raw=b"bad",headers={"Authorization":"Bearer "+self.tokens["owner"]["token"],"X-File-Name":"payload.txt","X-CSRF-Token":"wrong"},expected=401)
        self.call("GET","/api/users",who="viewer",expected=403)

    def test_password_change_checks_current_password_and_revokes_every_session(self):
        con=app.db();row=con.execute("SELECT id,salt,password_hash FROM users WHERE username='other'").fetchone()
        original_salt,original_hash=row["salt"],row["password_hash"];con.close()
        old_session=self.tokens["other"].copy()
        try:
            self.call("POST","/api/password",{"current_password":"wrong","new_password":"a-strong-new-password"},who="other",expected=400)
            self.call("POST","/api/password",{"current_password":"Other-demo-4wN!","new_password":"short"},who="other",expected=400)
            self.call("POST","/api/password",{"current_password":"Other-demo-4wN!","new_password":"a-strong-new-password"},who="other",expected=200)
            self.call("GET","/api/me",headers={"Authorization":"Bearer "+old_session["token"]},auth=False,expected=401)
            self.call("POST","/api/login",{"username":"other","password":"Other-demo-4wN!"},auth=False,expected=401)
            signed_in=self.call("POST","/api/login",{"username":"other","password":"a-strong-new-password"},auth=False,expected=200)
            self.tokens["other"]={"id":signed_in["user"]["id"],"token":signed_in["token"],"csrf":signed_in["csrf"]}
            events=self.call("GET","/api/admin/activity",who="admin")
            changes=[e for e in events if e["action"]=="password_change"]
            self.assertTrue(any(e["outcome"]=="denied" for e in changes))
            self.assertTrue(any(e["outcome"]=="allowed" for e in changes))
            self.assertTrue(self.call("GET","/api/admin/audit/verify",who="admin")["valid"])
        finally:
            # Keep the shared test fixture deterministic while retaining a valid token.
            con=app.db();con.execute("UPDATE users SET salt=?,password_hash=? WHERE id=?",(original_salt,original_hash,row["id"]));con.commit();con.close()
            if self.tokens["other"].get("token")==old_session["token"]:
                self.login("other","Other-demo-4wN!")

    def test_public_registration_creates_viewer_only_and_no_document_access(self):
        doc=self.upload();username="new-"+app.uuid.uuid4().hex[:10];password="new-account-password-123"
        try:
            result=self.call("POST","/api/register",{"username":username,"password":password},auth=False,expected=201)
            con=app.db();row=con.execute("SELECT id,role FROM users WHERE username=?",(username,)).fetchone();stored=con.execute("SELECT code_hash FROM recovery_codes WHERE user_id=?",(row["id"],)).fetchone();con.close()
            self.assertEqual(row["role"],"viewer");self.assertNotEqual(stored["code_hash"],result["recovery_code"]);self.assertEqual(stored["code_hash"],app.recovery_hash(result["recovery_code"]))
            signed=self.call("POST","/api/login",{"username":username,"password":password},auth=False,expected=200)
            self.tokens[username]={"id":signed["user"]["id"],"token":signed["token"],"csrf":signed["csrf"]}
            self.assertEqual(signed["user"]["role"],"viewer")
            self.assertNotIn(doc,[r["id"] for r in self.call("GET","/api/documents",who=username)])
            self.call("GET",f"/api/documents/{doc}/content",who=username,expected=404)
            self.call("POST","/api/documents",who=username,raw=b"not allowed",headers={"X-File-Name":"x.txt"},expected=403)
            duplicate=self.call("POST","/api/register",{"username":username,"password":password},auth=False,expected=400)
            self.assertIn("error",duplicate)
        finally:
            con=app.db();uid=con.execute("SELECT id FROM users WHERE username=?",(username,)).fetchone()
            if uid:
                con.execute("DELETE FROM sessions WHERE user_id=?",(uid["id"],));con.execute("DELETE FROM recovery_codes WHERE user_id=?",(uid["id"],));con.execute("DELETE FROM grants WHERE user_id=? OR granted_by=?",(uid["id"],uid["id"]));con.execute("DELETE FROM users WHERE id=?",(uid["id"],));con.commit()
            con.close();self.tokens.pop(username,None)

    def test_recovery_code_is_single_use_rotated_and_revokes_all_sessions(self):
        username="recover-"+app.uuid.uuid4().hex[:10];password="initial-account-password"
        try:
            registration=self.call("POST","/api/register",{"username":username,"password":password},auth=False,expected=201)
            first_code=registration["recovery_code"]
            first=self.call("POST","/api/login",{"username":username,"password":password},auth=False,expected=200)
            second=self.call("POST","/api/login",{"username":username,"password":password},auth=False,expected=200)
            self.tokens[username]={"id":second["user"]["id"],"token":second["token"],"csrf":second["csrf"]}
            bad=self.call("POST","/api/password/reset",{"username":username,"recovery_code":"wrong-code","new_password":"replacement-password-123"},auth=False,expected=400)
            self.assertEqual(bad["error"],"recovery request could not be completed")
            changed=self.call("POST","/api/password/reset",{"username":username,"recovery_code":first_code,"new_password":"replacement-password-123"},auth=False,expected=200)
            self.assertNotEqual(changed["recovery_code"],first_code)
            self.call("GET","/api/me",headers={"Authorization":"Bearer "+first["token"]},auth=False,expected=401)
            self.call("GET","/api/me",headers={"Authorization":"Bearer "+second["token"]},auth=False,expected=401)
            self.call("POST","/api/login",{"username":username,"password":password},auth=False,expected=401)
            self.call("POST","/api/password/reset",{"username":username,"recovery_code":first_code,"new_password":"another-new-password"},auth=False,expected=400)
            logged=self.call("POST","/api/login",{"username":username,"password":"replacement-password-123"},auth=False,expected=200)
            self.assertEqual(logged["user"]["role"],"viewer")
            events=self.call("GET","/api/admin/activity",who="admin")
            self.assertTrue(any(e["action"]=="password_reset" and e["outcome"]=="denied" for e in events))
            self.assertTrue(any(e["action"]=="password_reset" and e["outcome"]=="allowed" for e in events))
        finally:
            con=app.db();uid=con.execute("SELECT id FROM users WHERE username=?",(username,)).fetchone()
            if uid:
                con.execute("DELETE FROM sessions WHERE user_id=?",(uid["id"],));con.execute("DELETE FROM recovery_codes WHERE user_id=?",(uid["id"],));con.execute("DELETE FROM grants WHERE user_id=? OR granted_by=?",(uid["id"],uid["id"]));con.execute("DELETE FROM users WHERE id=?",(uid["id"],));con.commit()
            con.close();self.tokens.pop(username,None)
    def test_admin_audit_contains_refused_attempt_and_chain_verifies(self):
        doc=self.upload();self.call("GET",f"/api/documents/{doc}",who="other",expected=404)
        rows=self.call("GET","/api/admin/activity",who="admin")
        self.assertTrue(any(r["action"]=="document_access" and r["outcome"]=="denied" and r["document_id"]==doc for r in rows))
        self.assertTrue(self.call("GET","/api/admin/audit/verify",who="admin")["valid"])
        con=app.db();con.execute("UPDATE audit SET detail='changed' WHERE seq=(SELECT min(seq) FROM audit)");con.commit();con.close()
        self.assertFalse(self.call("GET","/api/admin/audit/verify",who="admin")["valid"])

    def test_admin_has_no_implicit_document_access_and_anonymous_attempt_is_recorded(self):
        doc=self.upload()
        self.call("GET",f"/api/documents/{doc}/content",who="admin",expected=404)
        self.call("GET",f"/api/documents/{doc}/content",auth=False,expected=401)
        rows=self.call("GET","/api/admin/activity",who="admin")
        self.assertTrue(any(r["document_id"]==doc and r["outcome"]=="denied" and r["actor"] is None for r in rows))

    def test_deleted_document_is_not_reachable_by_a_former_grantee(self):
        doc=self.upload();self.grant(doc)
        self.call("DELETE",f"/api/documents/{doc}",who="owner",expected=200)
        self.call("GET",f"/api/documents/{doc}/content",who="viewer",expected=404)


if __name__=="__main__": unittest.main(verbosity=2)
