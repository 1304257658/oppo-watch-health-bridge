import http.client,json,threading,unittest
from urllib.parse import urlencode
from unittest.mock import patch
import loopback_form as form

class GateTests(unittest.TestCase):
    def fields(self,g):return {k:[v] for k,v in {**form.DUMMY,'csrf':g.csrf,'consent':'READ OPPO ONCE'}.items()}
    def test_fake_submission_one_use_no_network(self):
        g=form.Gate()
        with patch('socket.socket',side_effect=AssertionError('no_network')):
            status,result=g.submit(self.fields(g))
        self.assertEqual(status,200);self.assertTrue(result['records_present']);self.assertEqual(result['mode'],'dry-run')
        self.assertEqual(g.submit(self.fields(g))[0],410)
        self.assertNotIn('FAKE-',json.dumps(result))
    def test_reject_any_non_dummy_and_consume(self):
        for key in form.DUMMY:
            g=form.Gate();fields=self.fields(g);fields[key]=['OTHER-SYNTHETIC-CANARY']
            self.assertEqual(g.submit(fields)[0],400);self.assertTrue(g.used)
    def test_expiry(self):
        now=[0];g=form.Gate(lambda:now[0]);now[0]=300
        self.assertEqual(g.submit(self.fields(g))[0],410)
    def test_csrf_missing_duplicate_and_extra(self):
        for kind in ['missing','duplicate','extra','wrong']:
            g=form.Gate();f=self.fields(g)
            if kind=='missing':del f['csrf']
            if kind=='duplicate':f['token']*=2
            if kind=='extra':f['extra']=['x']
            if kind=='wrong':f['csrf']=['wrong']
            self.assertNotEqual(g.submit(f)[0],200);self.assertFalse(g.used)
    def test_consent_required_and_no_retry(self):
        g=form.Gate();f=self.fields(g);f['consent']=['yes']
        self.assertEqual(g.submit(f)[0],403);self.assertTrue(g.used)

class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.server=form.Server();self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':0.01},daemon=True);self.thread.start()
    def tearDown(self):self.server.shutdown();self.thread.join();self.server.server_close()
    def call(self,path='/',method='GET',body=None,headers=None):
        conn=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=3)
        conn.request(method,path,body=body,headers=headers or {});r=conn.getresponse();result=(r.status,dict(r.getheaders()),r.read());conn.close();return result
    def submit(self,**overrides):
        fields={**form.DUMMY,'csrf':self.server.gate.csrf,'consent':'READ OPPO ONCE'}
        headers={'Origin':self.server.origin,'Content-Type':'application/x-www-form-urlencoded'};headers.update(overrides)
        return self.call('/submit','POST',urlencode(fields),headers)
    def test_host_and_cross_site_get_rejected(self):
        self.assertEqual(self.call(headers={'Host':'evil.invalid'})[0],403)
        self.assertEqual(self.call(headers={'Sec-Fetch-Site':'cross-site'})[0],403)
    def test_form_security_headers_no_secret_values(self):
        status,headers,body=self.call();self.assertEqual(status,200)
        self.assertEqual(headers['X-Frame-Options'],'DENY');self.assertIn('no-store',headers['Cache-Control'])
        self.assertIn("default-src 'none'",headers['Content-Security-Policy'])
        self.assertNotIn(b'value="FAKE-CANARY-TOKEN"',body)
    def test_wrong_origin_content_type_and_host(self):
        self.assertEqual(self.submit(Origin='https://evil.invalid')[0],403)
        self.assertEqual(self.submit(**{'Content-Type':'application/json'})[0],400)
        self.assertEqual(self.submit(Host='localhost:'+str(self.server.server_port))[0],403)
        self.assertFalse(self.server.gate.used)
    def test_http_success_and_repeat(self):
        status,headers,body=self.submit();self.assertEqual(status,200);self.assertEqual(json.loads(body)['mode'],'dry-run')
        self.assertNotIn(b'FAKE-',body);self.assertEqual(self.submit()[0],410)
    def test_queries_and_unknown_methods_rejected(self):
        self.assertEqual(self.call('/?token=CANARY')[0],404)
        self.assertEqual(self.call('/submit?x=1','POST','x',{'Origin':self.server.origin})[0],404)
        self.assertEqual(self.call('/','PUT')[0],501)
    def test_transfer_encoding_and_oversize_rejected(self):
        self.assertEqual(self.submit(**{'Transfer-Encoding':'chunked'})[0],400)
        self.assertEqual(self.call('/submit','POST','x'*(form.MAX_BODY+1),{'Origin':self.server.origin,'Content-Type':'application/x-www-form-urlencoded'})[0],400)

if __name__=='__main__':unittest.main()
