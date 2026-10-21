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
