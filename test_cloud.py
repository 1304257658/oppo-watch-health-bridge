import json,os,ssl,unittest
from unittest.mock import patch
import core,cloud_main
from test_reader import Connection,material

class CloudTests(unittest.TestCase):
    def test_default_and_live_gate_have_no_network(self):
        with patch('socket.socket',side_effect=AssertionError('network_forbidden')):
            self.assertEqual(cloud_main.dispatch([]).outcome,'dry_run_ok')
            self.assertEqual(cloud_main.dispatch(['--live']).outcome,'setup_failed')
    def test_direct_transport_ignores_proxy_environment(self):
        Connection.calls=[]
        with patch.dict(os.environ,{'HTTPS_PROXY':'https://evil.invalid:443','HTTP_PROXY':'http://evil.invalid:80'}),patch('http.client.HTTPSConnection',Connection):
            core.read_once(material(),core.Transport(connection_factory=lambda *a,**k:core.http.client.HTTPSConnection(*a,**k)))
        self.assertEqual(Connection.calls[0].args,(core.HOST,443))
    def test_transport_rejects_body_scope_substitution(self):
        with patch('http.client.HTTPSConnection',side_effect=AssertionError('network_forbidden')):
            with self.assertRaises(ValueError):core.Transport(connection_factory=lambda *a,**k:core.http.client.HTTPSConnection(*a,**k)).send(core.URL,core.START,core.END,{},b'{}')
    def test_transport_cannot_send_twice(self):
        Connection.calls=[];wire=core.Transport(connection_factory=lambda *a,**k:core.http.client.HTTPSConnection(*a,**k))
        with patch('http.client.HTTPSConnection',Connection):
            self.assertEqual(core.read_once(material(),wire).outcome,'ok')
            self.assertEqual(core.read_once(material(),wire).outcome,'scope_invalid')
        self.assertEqual(len(Connection.calls),1)
    def test_failed_attempt_not_retried(self):
        wire=core.Transport(connection_factory=lambda *a,**k:core.http.client.HTTPSConnection(*a,**k))
        with patch('http.client.HTTPSConnection',side_effect=OSError('private-error')) as conn:
            self.assertEqual(core.read_once(material(),wire).outcome,'network_error')
            self.assertEqual(core.read_once(material(),wire).outcome,'scope_invalid')
            self.assertEqual(conn.call_count,1)
    def test_tls_minimum_and_verification(self):
        context=core.tls_context()
        self.assertGreaterEqual(context.minimum_version,ssl.TLSVersion.TLSv1_2)
        self.assertEqual(context.verify_mode,ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
    def test_unknown_argument_never_echoed(self):
        self.assertNotIn('FAKE-SECRET',cloud_main.dispatch(['FAKE-SECRET']).safe_json())

if __name__=='__main__':unittest.main()
