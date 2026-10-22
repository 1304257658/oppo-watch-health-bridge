'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const {safeCapture, readSnapshot, GETTERS, EXPECTED, CLASSES, CaptureError} = require('./agent');
function fixture(branch = 'open') {
  const values = {getAccessToken: 'SYNTHETIC_ACCESS_ONLY', getRefreshToken: 'SYNTHETIC_REFRESH_ONLY',
    getAccessTokenExp: '1800000000000', getRefreshTokenExp: '1900000000000',
    getAccessTokenRfAdv: '60', getRefreshTokenRfAdv: '120', getPkgSign: 'SYNTHETIC_BINDING',
    getDeviceId: 'SYNTHETIC_DEVICE', getHost: ''};
  const s = {...EXPECTED, initialized: true, initializing: false, branch, app_id: 'SYNTHETIC_APP'};
  const calls = []; let clock = 0;
  const adapter = {state: () => ({...s}), cache(b, a) {
    calls.push(['cache', b, a]); return getter => {calls.push(['getter', getter]); return values[getter];};
  }, clock: () => ({wall_ms: String(1700000000000 + clock), elapsed_ms: String(1000 + clock++)})};
  return {values, s, calls, adapter};
}
for (const branch of ['system', 'open']) test('synthetic complete cache: ' + branch, () => {
  const f = fixture(branch); const r = safeCapture(f.adapter);
  assert.equal(r.ok, true); assert.equal(r.snapshot.app.branch, branch);
  assert.equal(r.snapshot.provenance.cache_class, CLASSES[branch]);
  assert.equal(r.snapshot.credentials.refresh_token, f.values.getRefreshToken);
  assert.equal(r.snapshot.original_binding.host, '');
  assert.equal(r.snapshot.readiness.http_ready, false);
  assert(r.snapshot.readiness.missing.includes('host_resolution'));
  assert.equal(f.calls.filter(c => c[0] === 'cache').length, 1);
  assert.equal(f.calls.filter(c => c[0] === 'getter').length, 18);
  assert(!JSON.stringify(r).includes('id_token"'));
});
for (const [name, patch, error] of [
  ['wrong package', {package_name: 'other'}, 'VERSION_MISMATCH'],
  ['wrong version', {version_code: '1'}, 'VERSION_MISMATCH'],
  ['wrong version name', {version_name: 'other'}, 'VERSION_MISMATCH'],
  ['uninitialized', {initialized: false}, 'NOT_INITIALIZED'],
  ['initializing', {initializing: true}, 'NOT_INITIALIZED'],
  ['missing branch', {branch: null}, 'BRANCH_MISSING'],
  ['missing appId', {app_id: ''}, 'APP_ID_MISSING']
]) test(name + ' fails before cache', () => {
  const f = fixture(); Object.assign(f.s, patch);
  assert.deepEqual(safeCapture(f.adapter), {ok: false, error}); assert.equal(f.calls.length, 0);
});
for (const getter of Object.values(GETTERS)) test('missing ' + getter + ' fails without partial secrets', () => {
  const f = fixture(); f.values[getter] = null; const r = safeCapture(f.adapter);
  assert.equal(r.ok, false); assert.deepEqual(Object.keys(r).sort(), ['error', 'ok']);
});
test('missing cache', () => {
  const f = fixture(); f.adapter.cache = () => null;
  assert.deepEqual(safeCapture(f.adapter), {ok: false, error: 'CACHE_MISSING'});
});
for (const v of ['-1', '1.5', '1e12', '01', '9223372036854775808', 1700000000000, '0'])
  test('invalid expiry rejected: ' + String(v), () => {
    const f = fixture(); f.values.getAccessTokenExp = v;
    assert.deepEqual(safeCapture(f.adapter), {ok: false, error: 'INVALID_INTEGER'});
  });
test('64-bit string precision retained', () => {
  const f = fixture(); f.values.getRefreshTokenExp = '9223372036854775807';
  assert.equal(safeCapture(f.adapter).snapshot.credentials.refresh_exp_ms, '9223372036854775807');
});
test('no default for missing advance; zero is retained', () => {
  const f = fixture(); f.values.getAccessTokenRfAdv = '0';
  assert.equal(safeCapture(f.adapter).snapshot.credentials.access_advance_s, '0');
});
test('SDK changes rejected', () => {
  const f = fixture(); let n = 0;
  f.adapter.state = () => ({...f.s, app_id: n++ ? 'DIFFERENT' : f.s.app_id});
  assert.deepEqual(safeCapture(f.adapter), {ok: false, error: 'STATE_CHANGED'});
});
test('response mutation rejected', () => {
  const f = fixture(); let n = 0;
  f.adapter.cache = () => getter => getter === 'getAccessToken' ? String(n++) : f.values[getter];
  assert.deepEqual(safeCapture(f.adapter), {ok: false, error: 'CACHE_CHANGED'});
});
test('clock rollback rejected', () => {
  const f = fixture(); let n = 2;
  f.adapter.clock = () => ({wall_ms: '1700000000000', elapsed_ms: String(n--)});
  assert.deepEqual(safeCapture(f.adapter), {ok: false, error: 'CLOCK_INVALID'});
});
test('runtime exception text and unknown error code never leave adapter', () => {
  const f = fixture(); f.adapter.cache = () => {throw new Error('SYNTHETIC_SECRET_EXCEPTION');};
  assert.deepEqual(safeCapture(f.adapter), {ok: false, error: 'RUNTIME_INCOMPATIBLE'});
  f.adapter.cache = () => {throw new CaptureError('SYNTHETIC_SECRET_EXCEPTION');};
  assert.deepEqual(safeCapture(f.adapter), {ok: false, error: 'RUNTIME_INCOMPATIBLE'});
});
test('runtime disabled without touching Java', async () => {
  assert.deepEqual(await readSnapshot(), {ok: false, error: 'RUNTIME_DISABLED'});
});
test('Frida RPC registration, describe and disabled call with synthetic VM globals', async () => {
  const context = {rpc: {exports: {}}, Java: new Proxy({}, {get() {throw Error('MUST_NOT_TOUCH_JAVA');}})};
  vm.createContext(context); vm.runInContext(fs.readFileSync(__dirname + '/agent.js', 'utf8'), context);
  assert.equal(context.rpc.exports.describe().runtime_enabled, false);
  assert.equal((await context.rpc.exports.readsnapshot()).error, 'RUNTIME_DISABLED');
});
test('no agent emission, writes, active token APIs or excluded getters', () => {
  const source = fs.readFileSync(__dirname + '/agent.js', 'utf8');
  for (const pattern of [/\bsend\s*\(/, /console\./, /\brequire\s*\(/, /getIdToken\s*\(/,
    /getDUID\s*\(/, /getEnvParams\s*\(/, /getAccountToken\s*\(/, /\.refresh\s*\(/,
    /\.login\s*\(/, /\.getAppK\s*\(/, /\.init\s*\(/]) assert(!pattern.test(source));
});
test('nonempty cached host preserved without inference', () => {
  const f = fixture(); f.values.getHost = 'SYNTHETIC_HOST_VALUE';
  const r = safeCapture(f.adapter); assert.equal(r.ok, true);
  assert.equal(r.snapshot.original_binding.host, 'SYNTHETIC_HOST_VALUE');
  assert(!r.snapshot.readiness.missing.includes('host_resolution'));
});
test('schema shape includes all returned fields and rejects undeclared properties', () => {
  const schema = JSON.parse(fs.readFileSync(__dirname + '/schema.json', 'utf8'));
  function shape(s, v) {
    if (Object.hasOwn(s, 'const')) assert.deepEqual(v, s.const);
    if (s.enum) assert(s.enum.includes(v));
    if (s.type === 'object') {
      assert.deepEqual(Object.keys(v).sort(), s.required.slice().sort());
      assert.equal(s.additionalProperties, false);
      for (const k of s.required) shape(s.properties[k], v[k]);
    } else if (s.type === 'array') {
      assert(Array.isArray(v)); assert(v.length >= (s.minItems || 0));
      if (s.uniqueItems) assert.equal(new Set(v).size, v.length);
      for (const i of v) shape(s.items, i);
    } else if (s.type === 'string') {
      assert.equal(typeof v, 'string');
      if (s.minLength) assert(v.length >= s.minLength);
      if (s.maxLength) assert(v.length <= s.maxLength);
      if (s.pattern) assert(new RegExp(s.pattern).test(v));
    }
  }
  for (const host of ['', 'SYNTHETIC_HOST_VALUE']) {
    const f = fixture(); f.values.getHost = host;
    shape(schema.oneOf[0], safeCapture(f.adapter));
  }
  shape(schema.oneOf[1], {ok: false, error: 'RUNTIME_DISABLED'});
});
