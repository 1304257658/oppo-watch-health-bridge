'use strict';
/* Candidate only. Runtime deliberately disabled pending controller/security review.
 * No network, file writer, hooks, heap enumeration or credential diagnostics.
 * Node exports below are solely for synthetic tests. */
const RUNTIME_CAPTURE_ENABLED = false;
const FORMAT = 'oppo.business-cache-snapshot/1';
const EXPECTED = Object.freeze({package_name: 'com.heytap.health', version_code: '6094200',
  version_name: '6.9.42_4b2ba32_261012'});
const CLASSES = Object.freeze({
  holder: 'com.heytap.health.base.base.GlobalApplicationHolder',
  sdk: 'com.heytap.health.account.sdk.AccountSdk',
  response: 'com.platform.usercenter.account.ams.ipc.AcAuthResponse',
  system: 'com.oplus.accountsdk.service.common.cache.AcIdLocalCacheUtils',
  open: 'com.oplus.accountsdk.open.util.cache.AcOpenLocalCacheUtils'
});
const GETTERS = Object.freeze({access_token: 'getAccessToken', refresh_token: 'getRefreshToken',
  access_exp_ms: 'getAccessTokenExp', refresh_exp_ms: 'getRefreshTokenExp',
  access_advance_s: 'getAccessTokenRfAdv', refresh_advance_s: 'getRefreshTokenRfAdv',
  pkg_sign: 'getPkgSign', device_id: 'getDeviceId', host: 'getHost'});
const ERRORS = new Set(['RUNTIME_DISABLED', 'BUSY_OR_CONSUMED', 'JAVA_UNAVAILABLE',
  'CLASS_NOT_LOADED', 'LOADER_MISMATCH', 'CONTEXT_MISSING', 'VERSION_MISMATCH',
  'NOT_INITIALIZED', 'BRANCH_MISSING', 'APP_ID_MISSING', 'CACHE_INSTANCE_MISSING',
  'CACHE_MISSING', 'RESPONSE_TYPE_MISMATCH', 'FIELD_MISSING', 'INVALID_INTEGER',
  'STATE_CHANGED', 'CACHE_CHANGED', 'CLOCK_INVALID', 'MAIN_THREAD', 'RUNTIME_INCOMPATIBLE',
  'DEFAULT_LOADER_UNAVAILABLE', 'CONTEXT_LOADER_UNAVAILABLE', 'LOADER_UNRELATED',
  'IDENTITY_API_UNAVAILABLE', 'LOADER_CHAIN_INVALID', 'CLASS_AMBIGUOUS',
  'CLASS_IDENTITY_MISMATCH', 'CLASS_LOADER_OUTSIDE_CONTEXT', 'ENUMERATION_INCOMPLETE',
  'FACTORY_LOADER_MISMATCH', 'CACHE_SIGNATURE_MISMATCH']);
const STAGES = new Set(['bootstrap', 'loaded_classes', 'holder', 'context', 'version',
  'sdk', 'state', 'cache_class', 'response_class', 'cache_signature', 'cache_read', 'response']);
function errorResult(e) {
  const result = {ok: false, error: e instanceof CaptureError && ERRORS.has(e.code) ? e.code : 'RUNTIME_INCOMPATIBLE'};
  if (e instanceof CaptureError && STAGES.has(e.stage) && typeof e.cacheReadStarted === 'boolean')
    result.diagnostic = {stage: e.stage, cache_read_started: e.cacheReadStarted};
  return result;
}
class CaptureError extends Error { constructor(code) { super(code); this.code = code; } }
function fail(code) { throw new CaptureError(code); }
function textRequired(v, allowEmpty = false) {
  if (typeof v !== 'string' || (!allowEmpty && v.length === 0)) fail('FIELD_MISSING');
  return v;
}
function integer(v, positive = false) {
  // Decimal strings preserve Java Long precision; never guess seconds vs milliseconds.
  if (typeof v !== 'string' || !/^(0|[1-9][0-9]*)$/.test(v) || v.length > 19 ||
      (v.length === 19 && v > '9223372036854775807') || (positive && v === '0')) fail('INVALID_INTEGER');
  return v;
}
function state(s) {
  if (!s || s.package_name !== EXPECTED.package_name || s.version_code !== EXPECTED.version_code ||
      s.version_name !== EXPECTED.version_name) fail('VERSION_MISMATCH');
  if (s.initialized !== true || s.initializing !== false) fail('NOT_INITIALIZED');
  if (s.branch !== 'system' && s.branch !== 'open') fail('BRANCH_MISSING');
  if (typeof s.app_id !== 'string' || !s.app_id) fail('APP_ID_MISSING');
  return {package_name: s.package_name, version_code: s.version_code, version_name: s.version_name,
    initialized: true, initializing: false, branch: s.branch, app_id: s.app_id};
}
function fields(reader) {
  const out = {};
  for (const [key, getter] of Object.entries(GETTERS)) {
    const v = reader(getter);
    out[key] = key.endsWith('_ms') ? integer(v, true) :
      key.endsWith('_s') ? integer(v) : textRequired(v, key === 'host');
  }
  return out;
}
function capture(adapter) {
  const before = state(adapter.state());
  const reader = adapter.cache(before.branch, before.app_id);
  if (typeof reader !== 'function') fail('CACHE_MISSING');
  const start = adapter.clock();
  const first = fields(reader);
  const second = fields(reader); // Same response object; no second disk/cache fetch.
  const end = adapter.clock();
  if (JSON.stringify(first) !== JSON.stringify(second)) fail('CACHE_CHANGED');
  if (JSON.stringify(before) !== JSON.stringify(state(adapter.state()))) fail('STATE_CHANGED');
  for (const c of [start, end]) {
    if (!c) fail('CLOCK_INVALID');
    integer(c.wall_ms, true); integer(c.elapsed_ms);
  }
  const compare = (a, b) => a.length !== b.length ? a.length - b.length : (a < b ? -1 : a > b ? 1 : 0);
  if (compare(end.elapsed_ms, start.elapsed_ms) < 0 || compare(end.wall_ms, start.wall_ms) < 0) fail('CLOCK_INVALID');
  return {schema: FORMAT, app: {package_name: before.package_name,
    version_code: before.version_code, version_name: before.version_name,
    app_id: before.app_id, branch: before.branch}, credentials: {
    access_token: first.access_token, refresh_token: first.refresh_token,
    access_exp_ms: first.access_exp_ms, refresh_exp_ms: first.refresh_exp_ms,
    access_advance_s: first.access_advance_s, refresh_advance_s: first.refresh_advance_s},
    original_binding: {pkg_sign: first.pkg_sign, device_id: first.device_id, host: first.host},
    clock_sample: {before: start, after: end, semantics: 'wall-and-boot-elapsed-sampled-sequentially-not-server-offset'},
    provenance: {cache_class: CLASSES[before.branch], cache_method: 'loadAuthResponseCache(Context,String)',
      response_class: CLASSES.response, app_id_source: CLASSES.sdk + '.appId',
      cache_key: 'app_id', apk_hash_verified_on_device: false, id_token_excluded: true},
    readiness: {http_ready: false, missing: ['company_receiver_contract', 'secure_local_controller',
      'encrypted_storage_integration', 'runtime_permission_confirmation', 'runtime_apk_identity',
      'oaep_provider_parameters', 'authorized_signing_configuration', 'envParam_requirements',
      'DUID_requirements', 'trace_requirements', 'server_time_mapping',
      ...(first.host === '' ? ['host_resolution'] : [])]}};
}
function safeCapture(adapter) {
  try { return {ok: true, snapshot: capture(adapter)}; }
  catch (e) { return errorResult(e); }
}
// JNI identity; never Java equals(), JS wrapper identity or object stringification.
function sameJava(a, b) {
  if (a === null || b === null) return a === null && b === null;
  if (!a || !b || typeof a.$isSameObject !== 'function') fail('IDENTITY_API_UNAVAILABLE');
  const result = a.$isSameObject(b);
  if (typeof result !== 'boolean') fail('IDENTITY_API_UNAVAILABLE');
  return result;
}
function loaderChain(loader) {
  const chain = [];
  for (let cur = loader; cur !== null; cur = cur.getParent()) {
    if (!cur || chain.length >= 32 || chain.some(x => sameJava(x, cur))) fail('LOADER_CHAIN_INVALID');
    chain.push(cur);
  }
  return chain;
}
function javaAdapter(J = Java) {
  let stage = 'bootstrap';
  let cacheReadStarted = false;
  function at(next, fn) {
    stage = next;
    try { return fn(); }
    catch (e) {
      const safe = new CaptureError(e instanceof CaptureError && ERRORS.has(e.code) ? e.code : 'RUNTIME_INCOMPATIBLE');
      safe.stage = stage; safe.cacheReadStarted = cacheReadStarted; throw safe;
    }
  }
  // Called only inside Java.perform. Null is a precise stop, never a loader search.
  const defaultLoader = at('bootstrap', () => {
    const loader = J.classFactory.loader;
    if (!loader) fail('DEFAULT_LOADER_UNAVAILABLE');
    return loader;
  });
  const records = at('loaded_classes', () => {
    const found = new Map();
    const wanted = new Set(Object.values(CLASSES));
    const Class = J.use('java.lang.Class');
    let complete = false;
    J.enumerateLoadedClasses({onMatch(name, handle) {
      if (!wanted.has(name)) return;
      const c = J.retain(J.cast(handle, Class));
      const list = found.get(name) || [];
      if (!list.some(x => sameJava(x, c))) list.push(c);
      found.set(name, list);
    }, onComplete() { complete = true; }});
    if (!complete) fail('ENUMERATION_INCOMPLETE');
    return found;
  });
  function checkedUse(factory, name, allowedLoader) {
    const candidates = records.get(name) || [];
    if (!candidates.length) fail('CLASS_NOT_LOADED');
    const ancestors = loaderChain(allowedLoader);
    const eligible = candidates.filter(c => {
      const defining = c.getClassLoader();
      return defining !== null && ancestors.some(x => sameJava(x, defining));
    });
    if (!eligible.length) fail('CLASS_LOADER_OUTSIDE_CONTEXT');
    // Shadowed same-name classes on a chain are ambiguous: do not guess precedence.
    if (eligible.length !== 1) fail('CLASS_AMBIGUOUS');
    const wrapper = factory.use(name);
    if (!sameJava(wrapper.class, eligible[0])) fail('CLASS_IDENTITY_MISMATCH');
    return wrapper;
  }
  const Holder = at('holder', () => checkedUse(J.classFactory, CLASSES.holder, defaultLoader));
  const context = at('context', () => {
    const value = Holder.getAppContext();
    if (!value) fail('CONTEXT_MISSING');
    return value;
  });
  const str = v => v === null || v === undefined ? null : String(v.toString());
  function version() {
    const pkg = str(context.getPackageName());
    if (pkg !== EXPECTED.package_name) fail('VERSION_MISMATCH');
    const manager = context.getPackageManager();
    const info = manager.getPackageInfo.overload('java.lang.String', 'int').call(manager, pkg, 0);
    const result = {package_name: pkg, version_code: str(info.getLongVersionCode()), version_name: str(info.versionName.value)};
    if (result.version_code !== EXPECTED.version_code || result.version_name !== EXPECTED.version_name) fail('VERSION_MISMATCH');
    return result;
  }
  at('version', version);
  const contextLoader = at('context', () => {
    const loader = context.getClassLoader();
    if (!loader) fail('CONTEXT_LOADER_UNAVAILABLE');
    const dc = loaderChain(defaultLoader), cc = loaderChain(loader);
    // A shared ancestor alone is insufficient (siblings must be rejected).
    if (!dc.some(x => sameJava(x, loader)) && !cc.some(x => sameJava(x, defaultLoader))) fail('LOADER_UNRELATED');
    return loader;
  });
  const factory = at('context', () => {
    const f = J.ClassFactory.get(contextLoader);
    if (!sameJava(f.loader, contextLoader)) fail('FACTORY_LOADER_MISMATCH');
    const rebound = checkedUse(f, CLASSES.holder, contextLoader);
    if (!sameJava(rebound.class, Holder.class) || !sameJava(rebound.getAppContext(), context)) fail('CLASS_IDENTITY_MISMATCH');
    return f;
  });
  at('context', () => {
    const Looper = J.use('android.os.Looper');
    const current = Looper.myLooper();
    if (current && sameJava(current, Looper.getMainLooper())) fail('MAIN_THREAD');
  });
  const Sdk = at('sdk', () => checkedUse(factory, CLASSES.sdk, contextLoader));
  const System = J.use('java.lang.System');
  const Clock = J.use('android.os.SystemClock');
  return {
    state() { return at('state', () => {
      if (!sameJava(context.getClassLoader(), contextLoader) || !sameJava(Holder.getAppContext(), context)) fail('STATE_CHANGED');
      const info = version();
      const instance = Sdk.INSTANCE.value;
      if (!instance) fail('NOT_INITIALIZED');
      const branchFlag = instance.isUseIDSdk();
      if (typeof branchFlag !== 'boolean') fail('BRANCH_MISSING');
      return {...info, initialized: Sdk.isInitialized(), initializing: Sdk.isInitializing(),
        branch: branchFlag ? 'system' : 'open', app_id: str(Sdk.appId.value)};
    }); },
    cache(branch, appId) {
      const Cache = at('cache_class', () => checkedUse(factory, CLASSES[branch], contextLoader));
      const Response = at('response_class', () => checkedUse(factory, CLASSES.response, contextLoader));
      const existing = at('cache_class', () => {
        const value = Cache.sInstance.value;
        if (!value) fail('CACHE_INSTANCE_MISSING');
        if (!sameJava(value.getClass(), Cache.class)) fail('CLASS_IDENTITY_MISMATCH');
        return value;
      });
      const read = at('cache_signature', () => {
        // Verify declared return Class identity before reading any cached credentials.
        const methods = Cache.class.getMethods();
        let matches = 0;
        for (let i = 0; i < methods.length; i++) {
          const m = methods[i];
          if (str(m.getName()) !== 'loadAuthResponseCache') continue;
          const params = m.getParameterTypes();
          if (params.length !== 2 || str(params[0].getName()) !== 'android.content.Context' ||
              str(params[1].getName()) !== 'java.lang.String') continue;
          if (!sameJava(m.getReturnType(), Response.class)) fail('CACHE_SIGNATURE_MISMATCH');
          matches++;
        }
        if (matches !== 1) fail('CACHE_SIGNATURE_MISMATCH');
        for (const getter of Object.values(GETTERS)) Response[getter].overload();
        return existing.loadAuthResponseCache.overload('android.content.Context', 'java.lang.String');
      });
      const response = at('cache_read', () => {
        cacheReadStarted = true;
        return read.call(existing, context, appId);
      });
      return at('response', () => {
        if (!response) fail('CACHE_MISSING');
        // Object type check only: all loader relationship prechecks ran before read.
        if (!sameJava(response.getClass(), Response.class)) fail('RESPONSE_TYPE_MISMATCH');
        const typed = J.cast(response, Response);
        return getter => at('response', () => str(typed[getter].overload().call(typed)));
      });
    },
    clock() { return {wall_ms: str(System.currentTimeMillis()), elapsed_ms: str(Clock.elapsedRealtime())}; }
  };
}
let attempted = false;
function readSnapshot() {
  if (!RUNTIME_CAPTURE_ENABLED) return Promise.resolve({ok: false, error: 'RUNTIME_DISABLED'});
  if (attempted) return Promise.resolve({ok: false, error: 'BUSY_OR_CONSUMED'});
  attempted = true; // A failed attempt also consumes the instance; no automatic replay.
  if (typeof Java === 'undefined' || !Java.available) return Promise.resolve({ok: false, error: 'JAVA_UNAVAILABLE'});
  return new Promise(resolve => {
    try { Java.perform(() => {
      try { resolve(safeCapture(javaAdapter())); }
      catch (_) { resolve(errorResult(_)); }
    }); } catch (_) { resolve({ok: false, error: 'RUNTIME_INCOMPATIBLE'}); }
  });
}
if (typeof rpc !== 'undefined') rpc.exports = {
  describe() { return {schema: FORMAT, runtime_enabled: RUNTIME_CAPTURE_ENABLED, expected: EXPECTED, http_ready: false}; },
  readsnapshot: readSnapshot
};
if (typeof module !== 'undefined') module.exports = {capture, safeCapture, readSnapshot, GETTERS, EXPECTED, CLASSES, CaptureError, javaAdapter, sameJava, loaderChain, errorResult};
