import contextlib,dataclasses,json,os,pathlib,sys
from core import Result,Material,Transport,URL,START,END,STAGES,dry_run,read_once

NOTICE=f'''公开离线参考：此文件只保留交互门禁和模拟会话测试。
未包含模拟器会话实现、厂商签名材料或可用真实认证流程。
不要输入真实凭证。正式入口为 cloud_main.py；真实模式保持关闭。
'''

def interactive_console():
    if os.name!='nt' or not sys.stdin.isatty() or not sys.stdout.isatty():return False
    import ctypes,msvcrt
    mode=ctypes.c_uint32()
    return all(ctypes.windll.kernel32.GetConsoleMode(ctypes.c_void_p(msvcrt.get_osfhandle(stream.fileno())),ctypes.byref(mode))
               for stream in [sys.stdin,sys.stdout])

@contextlib.contextmanager
def quiet_sensitive_phase():
    # Suppress both Python and native-library diagnostics during acquisition/use.
    sys.stdout.flush();sys.stderr.flush()
    saved=[os.dup(1),os.dup(2)]
    sink=os.open(os.devnull,os.O_WRONLY)
    try:
        os.dup2(sink,1);os.dup2(sink,2)
        with open(os.devnull,'w') as null,contextlib.redirect_stdout(null),contextlib.redirect_stderr(null):yield
    finally:
        os.dup2(saved[0],1);os.dup2(saved[1],2)
        for fd in [sink,*saved]:os.close(fd)

def execute_live(session_factory=None,transport_factory=None):
    if session_factory is None:
        raise RuntimeError('public_snapshot_emulator_adapter_not_included')
    session=session_factory();material=None;raw=None
    result=Result('live','setup_failed')
    stage='session_open';cache_started=False;request_attempted=False
    class ObservedTransport:
        def __init__(self,inner):self.inner=inner
        def send(self,*args,**kwargs):
            nonlocal request_attempted
            request_attempted=True
            return self.inner.send(*args,**kwargs)
    try:
        session.open()
        stage='cache_read';cache_started=True
        raw=session.read_cache()
        if type(raw)!=dict or raw.get('status')!='ready':
            result=Result('live','cache_unavailable')
        elif set(raw)!={'status','token','token_auth_id','app_key_version'}:
            result=Result('live','mapping_unavailable')
        else:
            stage='material_validate'
            material=Material(raw['token'],raw['token_auth_id'],raw['app_key_version'])
            raw.clear();raw=None
            stage='transport_create'
            transport=ObservedTransport((transport_factory or Transport)())
            stage='request'
            result=read_once(material,transport)
            stage='complete'
    except BaseException:
        if stage=='session_open':
            candidate=getattr(session,'stage',None)
            if candidate in STAGES:stage=candidate
        result=Result('live','setup_failed')
    finally:
        if isinstance(raw,dict):raw.clear()
        if material is not None:material.destroy()
        try:session.close()
        except BaseException:pass
    recovered=getattr(session,'recovery_ok',False) is True
    return dataclasses.replace(result,outcome=result.outcome if recovered else 'recovery_failed',recovery_ok=recovered,
        diagnostic_stage=stage,cache_read_started=cache_started,request_attempted=request_attempted)

def dispatch(argv,*,interactive=interactive_console,confirm=input,executor=execute_live,write=print):
    if argv in ([],['--dry-run']):return dry_run()
    if argv!=['--live']:return Result('dry-run','invalid_arguments')
    if not interactive():return Result('live','interactive_required')
    write(NOTICE)
    if confirm('本人同意上述一次读取，请键入 READ OPPO ONCE：')!='READ OPPO ONCE':return Result('live','declined')
    with quiet_sensitive_phase():return executor()

if __name__=='__main__':
    try:result=dispatch(sys.argv[1:]);print(result.safe_json())
    except BaseException:print(Result('live' if sys.argv[1:]==['--live'] else 'dry-run','setup_failed').safe_json())
