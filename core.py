"""Bounded one-request protocol. No credential persistence or arbitrary URL input."""
import base64,datetime,hashlib,hmac,http.client,json,re,secrets,ssl,time
from dataclasses import dataclass

HOST='sport.health.heytapmobi.com'
PATH='/sporthealth/v5/c2s/sport/steps/pullStepsDetailData'
URL='https://'+HOST+PATH
START=int(datetime.datetime(2026,10,17,12,tzinfo=datetime.timezone(datetime.timedelta(hours=8))).timestamp()*1000)
END=START+10*60*1000-1
MAX_RESPONSE=512*1024
OUTCOMES={'dry_run_ok','ok','declined','interactive_required','invalid_arguments','scope_invalid',
          'cache_unavailable','protocol_error','redirect_blocked','network_error','setup_failed',
          'mapping_unavailable','response_too_large','recovery_failed'}
STAGES={'session_open','asset_check','client_import','device_name','initial_security',
        'target_process','forward_check','root','policy_baseline','server_upload',
        'server_version','server_start','listener_check','forward_create','device_connect',
        'attach','loader_create','loader_load','chunk_transfer','java_probe',
        'cache_read','material_validate','transport_create','request','complete'}

@dataclass(frozen=True)
class Result:
    mode:str
    outcome:str
    http_status:int|None=None
    business_status:int|None=None
    records_present:bool|None=None
    recovery_ok:bool|None=None
    diagnostic_stage:str|None=None
    cache_read_started:bool|None=None
    request_attempted:bool|None=None
    def safe_json(self):
        if self.mode not in {'dry-run','live'} or self.outcome not in OUTCOMES:raise ValueError('invalid_result')
        if self.http_status is not None and (type(self.http_status)!=int or not 100<=self.http_status<=599):raise ValueError('invalid_result')
        if self.business_status is not None and (type(self.business_status)!=int or abs(self.business_status)>9999999):raise ValueError('invalid_result')
        if self.diagnostic_stage is not None and self.diagnostic_stage not in STAGES:raise ValueError('invalid_result')
        if any(v is not None and type(v)!=bool for v in [self.records_present,self.recovery_ok,self.cache_read_started,self.request_attempted]):raise ValueError('invalid_result')
        return json.dumps(self.__dict__,ensure_ascii=True)

class Material:
    def __init__(self,token,device,key_version):
        if type(token)!=str or not re.fullmatch(r'[!-~]{1,16384}',token):raise ValueError('invalid_material')
        if type(device)!=str or not re.fullmatch(r'[!-~]{1,1024}',device):raise ValueError('invalid_material')
        if type(key_version)!=str or not re.fullmatch(r'\d{1,20}',key_version):raise ValueError('invalid_material')
        self.token=bytearray(token,'ascii');self.device=bytearray(device,'ascii');self.key_version=key_version
    def __repr__(self):return '<Material redacted>'
    def destroy(self):
        for data in (self.token,self.device):data[:]=b'\0'*len(data)

def validate_scope(url,start,end):
    if url!=URL or type(start)!=int or type(end)!=int or (start,end)!=(START,END):raise ValueError('scope_invalid')

def signing_key():
    # Deliberately synthetic. No APK-derived key or decoding material is shipped.
    return b'SYNTHETIC-OFFLINE-HMAC-FIXTURE-NOT-A-VENDOR-KEY'


def headers_for(material,body,nonce=None,timestamp=None):
    fields={'appid':'SYNTHETIC-OFFLINE-APP-ID','app-package':'com.heytap.health','app-version':'6094200',
            'nonce':nonce or secrets.token_hex(16),'timestamp':str(timestamp if timestamp is not None else int(time.time()*1000)),
            'token':material.token.decode('ascii'),'token-auth-id':material.device.decode('ascii'),
            'os-type':'1','lang':'zh-CN','risk-sign':'2'}
    canonical='&'.join(k+'='+fields[k] for k in sorted(fields)).encode()+body
    signature=base64.b64encode(hmac.new(signing_key(),canonical,hashlib.sha256).digest()).decode()
    fields.update({'signature':signature,'Content-Type':'application/json; charset=UTF-8',
        'User-Agent':'okhttp/4.9.3.7','app-key-version':material.key_version,
        'versionName':'6.9.42_4b2ba32_261012','t-route-tag':'','Accept-Encoding':'identity'})
    return fields

def tls_context():
    # Avoid create_default_context's SSLKEYLOGFILE environment handling.
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version=ssl.TLSVersion.TLSv1_2
    ctx.load_default_certs()
    return ctx

class Transport:
    # Public snapshot: no default network factory. Tests inject fake connections.
    # A transport instance permits at most one attempt, including failures.
    # Direct TLS deliberately ignores HTTP(S)_PROXY and SSLKEYLOGFILE.
    def __init__(self,connection_factory=None):
        self._used=False;self._connection_factory=connection_factory
    def send(self,url,start,end,headers,body):
        validate_scope(url,start,end)
        expected=json.dumps({'startTimestamp':START,'endTimestamp':END},separators=(',',':')).encode()
        if body!=expected or self._used:raise ValueError('scope_invalid')
        self._used=True
        if self._connection_factory is None:raise RuntimeError('public_snapshot_network_disabled')
        conn=self._connection_factory(HOST,443,timeout=20,context=tls_context())
        conn.set_debuglevel(0)
        try:
            conn.request('POST',PATH,body=body,headers=headers)
            response=conn.getresponse()
            if 300<=response.status<400:return response.status,b''
            payload=response.read(MAX_RESPONSE+1)
            if len(payload)>MAX_RESPONSE:raise OverflowError('response_too_large')
            return response.status,payload
        finally:conn.close()

def classify(status,payload,mode='live'):
    if type(status)!=int or not 100<=status<=599:return Result(mode,'protocol_error')
    if 300<=status<400:return Result(mode,'redirect_blocked',status)
    if status!=200:return Result(mode,'protocol_error',status)
    try:
        obj=json.loads(payload)
        code=obj.get('errorCode') if type(obj)==dict else None
        if type(code)!=int or abs(code)>9999999:return Result(mode,'protocol_error',status)
        if code!=0:return Result(mode,'protocol_error',status,code)
        body=obj.get('body')
        rows=body.get('resultList') if type(body)==dict else body
        if type(rows)!=list:return Result(mode,'protocol_error',status,code)
        return Result(mode,'ok',status,code,bool(rows))
    except Exception:return Result(mode,'protocol_error',status)

def read_once(material,transport,*,url=URL,start=START,end=END,mode='live'):
    hdr=None
    try:
        validate_scope(url,start,end)
        body=json.dumps({'startTimestamp':start,'endTimestamp':end},separators=(',',':')).encode()
        hdr=headers_for(material,body)
        status,payload=transport.send(url,start,end,hdr,body)
        return classify(status,payload,mode)
    except ValueError:return Result(mode,'scope_invalid')
    except OverflowError:return Result(mode,'response_too_large')
    except Exception:return Result(mode,'network_error')
    finally:
        if hdr is not None:hdr.clear()
        material.destroy()

class FakeTransport:
    def send(self,url,start,end,headers,body):
        if headers['token']!='FAKE-CANARY-TOKEN':raise ValueError('synthetic_only')
        return 200,b'{"errorCode":0,"body":{"resultList":[{"synthetic":true}]}}'

def dry_run():
    r=read_once(Material('FAKE-CANARY-TOKEN','FAKE-DEVICE','1732499446015'),FakeTransport(),mode='dry-run')
    return Result('dry-run','dry_run_ok' if r.outcome=='ok' else r.outcome,r.http_status,r.business_status,r.records_present)
