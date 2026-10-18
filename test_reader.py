import contextlib,hashlib,hmac,base64,io,json,os,pathlib,ssl,sys,unittest
from unittest.mock import patch
import core,main

CANARY='FAKE-CANARY-DO-NOT-PRINT'
def material():return core.Material(CANARY,'FAKE-DEVICE','1732499446015')
class Response:
    status=200
    def read(self,n):return b'{"errorCode":0,"body":{"resultList":[{"private":"FAKE-CANARY-DO-NOT-PRINT"}]}}'
class Connection:
    calls=[];response=Response()
    def __init__(self,*args,**kwargs):self.args=args;self.kwargs=kwargs;Connection.calls.append(self)
    def set_debuglevel(self,value):self.debug=value
    def set_tunnel(self,*args):self.tunnel=args
    def request(self,*args,**kwargs):self.request_args=args;self.request_kw=kwargs
    def getresponse(self):return self.response
    def close(self):self.closed=True
class FakeSession:
    def __init__(self,raw=None):self.raw=raw if raw is not None else {'status':'ready','token':CANARY,'token_auth_id':'FAKE-DEVICE','app_key_version':'1732499446015'};self.recovery_ok=False;self.closed=False
    def open(self):pass
    def read_cache(self):return self.raw
    def close(self):self.closed=True;self.recovery_ok=True
class FakeWire:
    calls=0
    def send(self,*args):self.calls+=1;return 200,b'{"errorCode":0,"body":{"resultList":[]}}'

class ReaderTests(unittest.TestCase):
    def test_default_never_opens_network_or_process(self):
        with patch('socket.socket',side_effect=AssertionError('network_forbidden')),patch('subprocess.Popen',side_effect=AssertionError('process_forbidden')):
            self.assertEqual(main.dispatch([]).outcome,'dry_run_ok')
        self.assertNotIn('frida',sys.modules)
    def test_scope_rejects_alternate_targets(self):
        for url in ['http://'+core.HOST+core.PATH,core.URL+'/',core.URL+'?x=1',core.URL+'#x','https://evil.invalid'+core.PATH,'https://u@'+core.HOST+core.PATH]:
            with self.subTest(url=url),self.assertRaises(ValueError):core.validate_scope(url,core.START,core.END)
    def test_scope_rejects_expansion_and_boolean(self):
        for a,b in [(core.START-1,core.END),(core.START,core.END+1),(False,core.END),(core.START,True),(core.END,core.START)]:
            with self.assertRaises(ValueError):core.validate_scope(core.URL,a,b)
    def test_no_request_on_invalid_scope(self):
        m=material();wire=FakeWire();r=core.read_once(m,wire,url='https://evil.invalid')
        self.assertEqual((r.outcome,wire.calls),('scope_invalid',0));self.assertFalse(any(m.token))
    def test_fixed_10_minute_interval(self):self.assertEqual(core.END-core.START+1,600000)
    def test_header_injection_is_rejected(self):
        for token,device,version in [('a\r\nb','x','1'),('x','a\nb','1'),('x','y','1\n'),('', 'x','1')]:
            with self.assertRaises(ValueError):core.Material(token,device,version)
    def test_material_repr_redacted(self):self.assertNotIn(CANARY,repr(material()))
    def test_signature_canonical_body(self):
        m=material();body=b'{"startTimestamp":1,"endTimestamp":2}'
        headers=core.headers_for(m,body,nonce='0'*32,timestamp=123)
        signed={k:headers[k] for k in ['appid','app-package','app-version','nonce','timestamp','token','token-auth-id','os-type','lang','risk-sign']}
        canonical='&'.join(f'{k}={v}' for k,v in sorted(signed.items())).encode()+body
        expected=base64.b64encode(hmac.new(core.signing_key(),canonical,hashlib.sha256).digest()).decode()
        self.assertEqual(headers['signature'],expected);m.destroy()
    def test_result_never_exposes_response_values(self):
        r=core.classify(200,Response().read(1024));self.assertTrue(r.records_present);self.assertNotIn(CANARY,r.safe_json())
    def test_business_error_is_numeric_only(self):
        r=core.classify(200,json.dumps({'errorCode':10103,'errorMessage':CANARY,'body':CANARY}))
        self.assertEqual(r.business_status,10103);self.assertNotIn(CANARY,r.safe_json())
    def test_schema_fail_closed(self):
        for obj in [{'errorCode':False,'body':[]},{'errorCode':0,'body':{'unknown':[]}},{'errorCode':CANARY},{'errorCode':10**20}]:
            self.assertEqual(core.classify(200,json.dumps(obj)).outcome,'protocol_error')
    def test_bad_json_redacted(self):self.assertNotIn(CANARY,core.classify(200,CANARY.encode()).safe_json())
    def test_no_redirect_following(self):
        class Redirect(Response):
            status=302
            def read(self,n):raise AssertionError('must_not_read')
        Connection.calls=[]
        with patch.object(Connection,'response',Redirect()),patch('http.client.HTTPSConnection',Connection):
            r=core.read_once(material(),core.Transport(connection_factory=lambda *a,**k:core.http.client.HTTPSConnection(*a,**k)))
        self.assertEqual(r.outcome,'redirect_blocked');self.assertEqual(len(Connection.calls),1)
    def test_exact_direct_host_path_and_tls(self):
        Connection.calls=[]
        with patch('http.client.HTTPSConnection',Connection):r=core.read_once(material(),core.Transport(connection_factory=lambda *a,**k:core.http.client.HTTPSConnection(*a,**k)))
        conn=Connection.calls[0]
        self.assertEqual(conn.args,(core.HOST,443));self.assertFalse(hasattr(conn,'tunnel'))
        self.assertEqual(conn.request_args,('POST',core.PATH));self.assertEqual(conn.debug,0);self.assertTrue(conn.closed)
        self.assertEqual(conn.kwargs['context'].verify_mode,ssl.CERT_REQUIRED);self.assertTrue(conn.kwargs['context'].check_hostname)
        self.assertEqual(r.outcome,'ok')
    def test_tls_key_logging_env_ignored(self):
        path=pathlib.Path('/tmp/cloud-reader-keylog-must-not-exist.txt')
        self.assertFalse(path.exists())
        with patch.dict(os.environ,{'SSLKEYLOGFILE':str(path)}):ctx=core.tls_context()
        self.assertIsNone(ctx.keylog_filename);self.assertFalse(path.exists())
    def test_oversized_response(self):
        class Oversized(Response):
            def read(self,n):return b'x'*n
        with patch.object(Connection,'response',Oversized()),patch('http.client.HTTPSConnection',Connection):r=core.read_once(material(),core.Transport(connection_factory=lambda *a,**k:core.http.client.HTTPSConnection(*a,**k)))
        self.assertEqual(r.outcome,'response_too_large')
    def test_error_redaction_and_material_wipe(self):
        class Fail:
            def send(self,*args):raise RuntimeError(CANARY)
        m=material();r=core.read_once(m,Fail());self.assertEqual(r.outcome,'network_error');self.assertFalse(any(m.token));self.assertNotIn(CANARY,r.safe_json())
    def test_live_gate_noninteractive(self):
        r=main.dispatch(['--live'],interactive=lambda:False,executor=lambda:self.fail('executed'))
        self.assertEqual(r.outcome,'interactive_required')
    def test_live_gate_declined(self):
        r=main.dispatch(['--live'],interactive=lambda:True,confirm=lambda _:CANARY,executor=lambda:self.fail('executed'),write=lambda _:None)
        self.assertEqual(r.outcome,'declined');self.assertNotIn(CANARY,r.safe_json())
    def test_live_gate_requires_exact_phrase(self):
        for reply in ['yes','READ OPPO ONCE ','','read oppo once']:
            r=main.dispatch(['--live'],interactive=lambda:True,confirm=lambda _:reply,executor=lambda:self.fail('executed'),write=lambda _:None)
            self.assertEqual(r.outcome,'declined')
    def test_confirmed_gate_calls_only_fake_executor(self):
        with patch.object(main,'quiet_sensitive_phase',contextlib.nullcontext):
            r=main.dispatch(['--live'],interactive=lambda:True,confirm=lambda _:'READ OPPO ONCE',executor=lambda:core.Result('live','ok'),write=lambda _:None)
        self.assertEqual(r.outcome,'ok')
    def test_unknown_arguments_not_echoed(self):
        r=main.dispatch(['--live',CANARY]);self.assertEqual(r.outcome,'invalid_arguments');self.assertNotIn(CANARY,r.safe_json())
    def test_valid_fake_session_clears_raw_and_recovers(self):
        session=FakeSession();raw=session.raw
        r=main.execute_live(lambda:session,FakeWire)
        self.assertEqual(raw,{});self.assertEqual(r.outcome,'ok');self.assertTrue(r.recovery_ok);self.assertTrue(session.closed)
    def test_bad_cache_never_sends(self):
        for raw in [{'status':'cache_unavailable'},{'status':'ready','token':CANARY,'extra':'x'}]:
            session=FakeSession(raw);r=main.execute_live(lambda:session,lambda:self.fail('network_factory_called'))
            self.assertTrue(session.closed);self.assertNotIn(CANARY,r.safe_json())
    def test_setup_exception_still_recovers(self):
        session=FakeSession()
        def fail():raise RuntimeError(CANARY)
        session.open=fail
        r=main.execute_live(lambda:session,FakeWire);self.assertTrue(session.closed);self.assertEqual(r.outcome,'setup_failed');self.assertNotIn(CANARY,r.safe_json())
    def test_interrupt_still_recovers(self):
        session=FakeSession()
        def fail():raise KeyboardInterrupt()
        session.read_cache=fail
        r=main.execute_live(lambda:session,FakeWire);self.assertTrue(session.closed);self.assertEqual(r.outcome,'setup_failed')
    def test_recovery_failure_never_reports_success(self):
        session=FakeSession();session.close=lambda:None
        r=main.execute_live(lambda:session,FakeWire);self.assertEqual(r.outcome,'recovery_failed');self.assertFalse(r.recovery_ok)
    def test_result_whitelist_rejects_secret_text(self):
        with self.assertRaises(ValueError):core.Result('live',CANARY).safe_json()
        with self.assertRaises(ValueError):core.Result('live','ok',business_status=CANARY).safe_json()
    def test_sensitive_phase_suppresses_python_output(self):
        # Only synthetic canary is printed; native fd suppression is also active.
        stdout=io.StringIO();stderr=io.StringIO()
        with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
            with main.quiet_sensitive_phase():print(CANARY);print(CANARY,file=sys.stderr)
        self.assertNotIn(CANARY,stdout.getvalue()+stderr.getvalue())

    def test_each_setup_stage_never_reads_cache(self):
        setup=core.STAGES-{'cache_read','material_validate','transport_create','request','complete'}
        for stage in setup:
            session=FakeSession();session.stage=stage
            session.open=lambda:(_ for _ in ()).throw(RuntimeError(CANARY))
            session.read_cache=lambda:self.fail('cache_read_during_setup_failure')
            r=main.execute_live(lambda:session,lambda:self.fail('transport_during_setup_failure'))
            self.assertEqual(r.diagnostic_stage,stage)
            self.assertFalse(r.cache_read_started);self.assertFalse(r.request_attempted)
            self.assertTrue(r.recovery_ok);self.assertNotIn(CANARY,r.safe_json())

    def test_cache_rpc_failure_reports_started(self):
        session=FakeSession()
        session.read_cache=lambda:(_ for _ in ()).throw(RuntimeError(CANARY))
        r=main.execute_live(lambda:session,FakeWire)
        self.assertEqual(r.diagnostic_stage,'cache_read');self.assertTrue(r.cache_read_started)
        self.assertFalse(r.request_attempted)

    def test_invalid_material_is_after_read_before_request(self):
        session=FakeSession({'status':'ready','token':'bad\n','token_auth_id':'fake','app_key_version':'1'})
        r=main.execute_live(lambda:session,FakeWire)
        self.assertEqual(r.diagnostic_stage,'material_validate');self.assertTrue(r.cache_read_started)
        self.assertFalse(r.request_attempted);self.assertEqual(session.raw,{})

    def test_transport_construction_failure_not_request(self):
        r=main.execute_live(FakeSession,lambda:(_ for _ in ()).throw(RuntimeError(CANARY)))
        self.assertEqual(r.diagnostic_stage,'transport_create');self.assertTrue(r.cache_read_started)
        self.assertFalse(r.request_attempted)

    def test_request_attempt_flag_survives_interrupt(self):
        class Interrupt:
            def send(self,*args):raise KeyboardInterrupt()
        r=main.execute_live(FakeSession,Interrupt)
        self.assertEqual(r.diagnostic_stage,'request');self.assertTrue(r.cache_read_started)
        self.assertTrue(r.request_attempted);self.assertTrue(r.recovery_ok)

    def test_completed_fake_request_flags(self):
        r=main.execute_live(FakeSession,FakeWire)
        self.assertEqual(r.diagnostic_stage,'complete');self.assertTrue(r.request_attempted)

    def test_diagnostics_reject_untrusted_text(self):
        with self.assertRaises(ValueError):core.Result('live','setup_failed',diagnostic_stage=CANARY).safe_json()
        with self.assertRaises(ValueError):core.Result('live','setup_failed',cache_read_started=CANARY).safe_json()
        session=FakeSession();session.stage=CANARY
        session.open=lambda:(_ for _ in ()).throw(RuntimeError(CANARY))
        r=main.execute_live(lambda:session,FakeWire)
        self.assertEqual(r.diagnostic_stage,'session_open');self.assertNotIn(CANARY,r.safe_json())

if __name__=='__main__':unittest.main()
