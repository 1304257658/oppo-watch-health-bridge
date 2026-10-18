"""User-operated loopback preparation. Only fixed dummy credentials are accepted.
Real credential intake is intentionally unavailable pending precise approval.
"""
import hmac,html,json,secrets,time
from http.server import BaseHTTPRequestHandler,HTTPServer
from urllib.parse import parse_qs
from core import Material,FakeTransport,read_once,Result,URL

DUMMY={'token':'FAKE-CANARY-TOKEN','device':'FAKE-DEVICE','version':'1732499446015'}
MAX_BODY=18000
TTL=300

class Gate:
    def __init__(self,clock=time.monotonic):
        self.clock=clock;self.deadline=clock()+TTL;self.csrf=secrets.token_urlsafe(32);self.nonce=secrets.token_urlsafe(24);self.used=False
    def active(self):return not self.used and self.clock()<self.deadline
    def submit(self,fields):
        if not self.active():return 410,{'outcome':'closed'}
        if set(fields)!={'csrf','token','device','version','consent'} or any(len(v)!=1 for v in fields.values()):return 400,{'outcome':'invalid_arguments'}
        if not hmac.compare_digest(fields['csrf'][0],self.csrf):return 403,{'outcome':'declined'}
        # Consume immediately after authenticating form submission, even on error.
        self.used=True
        if fields['consent']!=['READ OPPO ONCE']:return 403,{'outcome':'declined'}
        if any(fields[k]!=[v] for k,v in DUMMY.items()):return 400,{'outcome':'dummy_values_required'}
        material=Material(fields['token'][0],fields['device'][0],fields['version'][0])
        result=read_once(material,FakeTransport(),mode='dry-run')
        return 200,{'mode':'dry-run','outcome':result.outcome,'http_status':result.http_status,
                    'business_status':result.business_status,'records_present':result.records_present}


def page(gate):
    return ('''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>OPPO 云端离线演练</title>
<meta name="referrer" content="no-referrer"><h1>仅假数据演练：不要输入真实凭证</h1>
<p>当前接收方仅为此云端电脑的回环程序（127.0.0.1）。本版本不会向 OPPO 或其他网站发送请求。</p>
<p>后续真实读取必须另行明确批准并完成安全交接。本版本不提供真实模式。</p>
<p>拟批准的官方接收方：'''+html.escape(URL)+'''</p>
<p>拟读取范围：2026-10-17 12:00:00 至 12:09:59.999（UTC+08:00），仅返回步数记录是否存在。
只允许一次请求，不刷新授权、不保存或回显凭证，不显示健康明细。当前展示的结果为模拟结果。</p>
<p>本页面自程序启动五分钟后失效；一次提交后即关闭，错误也不能重试。程序不记录请求或表单内容。输入只在处理该次请求的内存中短暂使用；处理结束释放引用，进程随即退出。不保证内存副本擦除。
浏览器、远程桌面及系统内存可能保留输入，本程序不能保证安全擦除。</p>
<form method="post" action="/submit" autocomplete="off">
<input type="hidden" name="csrf" value="'''+html.escape(gate.csrf,quote=True)+'''">
<label>健康 token（仅填 FAKE-CANARY-TOKEN）<input type="password" name="token" autocomplete="off" required></label><br>
<label>token-auth-id / deviceId（仅填 FAKE-DEVICE）<input type="password" name="device" autocomplete="off" required></label><br>
<label>公开 app-key-version（仅填 1732499446015）<input name="version" autocomplete="off" required></label><br>
<label><input type="checkbox" name="consent" value="READ OPPO ONCE" required>我只提交以上假数据并运行一次离线演练</label><br>
<button type="submit">运行一次假数据演练</button></form>
<script nonce="'''+html.escape(gate.nonce,quote=True)+'''">
const f=document.querySelector('form');
const clear=()=>{for(const n of ['token','device','version'])f.elements[n].value='';};
window.addEventListener('pagehide',clear);
f.addEventListener('submit',async e=>{
 e.preventDefault(); let body=new URLSearchParams(new FormData(f)).toString(); clear();
 f.querySelector('button').disabled=true;
 try { const response=await fetch('/submit',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body,cache:'no-store',credentials:'omit',redirect:'error'});
 body=null; const result=await response.text(); document.body.textContent=result;
 } catch (_) { body=null; document.body.textContent='请求结束，未能确认结果。请勿重复提交。'; }
});
</script></html>''').encode()

class Server(HTTPServer):
    allow_reuse_address=False
    def __init__(self,port=0,gate=None):
        super().__init__(('127.0.0.1',port),Handler)
        self.gate=gate or Gate();self.origin='http://127.0.0.1:'+str(self.server_port)
        self.timeout=1
    def handle_error(self,request,client_address):pass
    def get_request(self):
        sock,addr=super().get_request();sock.settimeout(3);return sock,addr

class Handler(BaseHTTPRequestHandler):
    server_version='';sys_version=''
    def log_message(self,*args):pass
    def log_error(self,*args):pass
    def send_error(self,code,message=None,explain=None):self.respond(code,{'outcome':'invalid_arguments'})
    def respond(self,status,obj,html_body=False):
        body=obj if html_body else json.dumps(obj,separators=(',',':')).encode()
        self.send_response(status)
        for k,v in {'Content-Type':'text/html; charset=utf-8' if html_body else 'application/json',
            'Content-Length':str(len(body)),'Cache-Control':'no-store, max-age=0','Pragma':'no-cache',
            'Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY',
            'Content-Security-Policy':"default-src 'none'; connect-src 'self'; script-src 'nonce-"+self.server.gate.nonce+"'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            'Connection':'close'}.items():self.send_header(k,v)
        self.end_headers();self.wfile.write(body);self.close_connection=True
    def valid_host(self):
        return self.client_address[0]=='127.0.0.1' and self.headers.get_all('Host')==[self.server.origin[7:]]
    def do_GET(self):
        if not self.valid_host() or self.headers.get('Sec-Fetch-Site') not in (None,'none','same-origin'):
            return self.respond(403,{'outcome':'declined'})
        if self.path!='/':return self.respond(404,{'outcome':'not_found'})
        if not self.server.gate.active():return self.respond(410,{'outcome':'closed'})
        self.respond(200,page(self.server.gate),True)
    def do_POST(self):
        if not self.valid_host() or self.headers.get_all('Origin')!=[self.server.origin] or self.headers.get('Sec-Fetch-Site') not in (None,'same-origin'):
            return self.respond(403,{'outcome':'declined'})
        if self.path!='/submit':return self.respond(404,{'outcome':'not_found'})
        if self.headers.get('Transfer-Encoding') is not None or self.headers.get_all('Content-Type')!=['application/x-www-form-urlencoded']:
            return self.respond(400,{'outcome':'invalid_arguments'})
        lengths=self.headers.get_all('Content-Length')
        if not lengths or len(lengths)!=1 or not lengths[0].isdigit() or not 1<=int(lengths[0])<=MAX_BODY:
            return self.respond(400,{'outcome':'invalid_arguments'})
        raw=None;fields=None
        try:
            raw=self.rfile.read(int(lengths[0]))
            if len(raw)!=int(lengths[0]):raise ValueError()
            fields=parse_qs(raw.decode('ascii'),keep_blank_values=True,strict_parsing=True,max_num_fields=5,errors='strict')
            status,result=self.server.gate.submit(fields)
            self.respond(status,result)
        except Exception:self.respond(400,{'outcome':'invalid_arguments'})
        finally:
            if fields is not None:fields.clear()
            raw=None


def main():
    import sys
    if sys.argv[1:]:
        print('{"outcome":"invalid_arguments","mode":"dry-run"}');return
    with Server() as server:
        print('Dummy-only user form: '+server.origin+'/',flush=True)
        while server.gate.active():server.handle_request()

if __name__=='__main__':main()


def main():
    import sys
    if sys.argv[1:]:
        print('{"outcome":"invalid_arguments","mode":"dry-run"}');return
    with Server() as server:
        print('Dummy-only form: '+server.origin+'/',flush=True)
        while server.gate.active():server.handle_request()

if __name__=='__main__':main()
