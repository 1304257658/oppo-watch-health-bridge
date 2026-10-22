'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const {javaAdapter, safeCapture, errorResult, CLASSES, EXPECTED, GETTERS, sameJava} = require('./agent');
function identity(id, methods = {}) {
  return {id, ...methods, $isSameObject(other) { return this.id === other.id; },
    equals() {throw Error('equals must not be called');}, toString() {throw Error('object must not be stringified');}};
}
function bridge(options = {}) {
  const root = identity('root', {getParent: () => null});
  const app = identity('app', {getParent: () => root});
  const child = identity('child', {getParent: () => app});
  const sibling = identity('sibling', {getParent: () => root});
  const clone = obj => obj === null ? null : {...obj};
  const defaultLoader = options.nullDefault ? null : options.defaultChild ? child : app;
  const contextLoader = options.siblingContext ? sibling : options.childContext ? child : app;
  const defined = {};
  for (const name of Object.values(CLASSES)) defined[name] = app;
  if (options.parentResponse) defined[CLASSES.response] = root;
  if (options.siblingResponse) defined[CLASSES.response] = sibling;
  if (options.siblingSdk) defined[CLASSES.sdk] = sibling;
  let cacheCalls = 0; const factoryUses = [];
  const classes = {}, wrappers = {};
  const overload = fn => ({overload: () => ({call: (_self, ...args) => fn(...args)})});
  for (const name of Object.values(CLASSES)) {
    classes[name] = identity('class:' + name, {getClassLoader: () => clone(defined[name]), getName: () => name});
    wrappers[name] = {class: clone(classes[name])};
  }
  const info = {getLongVersionCode: () => EXPECTED.version_code, versionName: {value: options.wrongVersion ? 'other' : EXPECTED.version_name}};
  const manager = {getPackageInfo: overload(() => info)};
  const context = identity('context', {getClassLoader: () => options.nullContextLoader ? null : clone(contextLoader),
    getPackageName: () => options.wrongPackage ? 'other' : EXPECTED.package_name, getPackageManager: () => manager});
  wrappers[CLASSES.holder].getAppContext = () => options.noContext ? null : clone(context);
  wrappers[CLASSES.sdk] = {...wrappers[CLASSES.sdk], INSTANCE: {value: {isUseIDSdk: () => options.system === true}},
    isInitialized: () => options.uninitialized ? false : true, isInitializing: () => false, appId: {value: 'SYNTHETIC_APP'}};
  const response = {getClass: () => options.badResponse ? classes[CLASSES.sdk] : clone(classes[CLASSES.response])};
  const values = {getAccessToken: 'SYNTHETIC_ACCESS', getRefreshToken: 'SYNTHETIC_REFRESH',
    getAccessTokenExp: '1800000000000', getRefreshTokenExp: '1900000000000',
    getAccessTokenRfAdv: '10', getRefreshTokenRfAdv: '20', getPkgSign: 'SYNTHETIC_SIGN', getDeviceId: 'SYNTHETIC_DEVICE', getHost: ''};
  for (const g of Object.values(GETTERS)) {
    response[g] = overload(() => values[g]); wrappers[CLASSES.response][g] = response[g];
  }
  for (const name of [CLASSES.system, CLASSES.open]) {
    const c = classes[name];
    c.getMethods = () => [{getName: () => 'loadAuthResponseCache',
      getParameterTypes: () => [{getName: () => 'android.content.Context'}, {getName: () => 'java.lang.String'}],
      getReturnType: () => clone(classes[options.badSignature ? CLASSES.sdk : CLASSES.response])}];
    wrappers[name].class = clone(c);
    wrappers[name].sInstance = {value: {getClass: () => clone(c), loadAuthResponseCache: overload(() => {cacheCalls++; return response;})}};
  }
  const platform = {'java.lang.Class': {}, 'android.os.Looper': {myLooper: () => null},
    'java.lang.System': {currentTimeMillis: () => '1700000000000'}, 'android.os.SystemClock': {elapsedRealtime: () => '1000'}};
  const makeFactory = loader => ({loader: clone(loader), use(name) {
    factoryUses.push(name);
    if (options.wrongResolvedClass && name === CLASSES.response) return {...wrappers[name], class: classes[CLASSES.sdk]};
    return wrappers[name];
  }});
  const J = {classFactory: makeFactory(defaultLoader), ClassFactory: {get: loader => {
    if (options.badFactory) return makeFactory(sibling);
    return makeFactory(loader);
  }}, use: name => platform[name], cast: x => x, retain: x => clone(x), enumerateLoadedClasses(callbacks) {
    for (const name of Object.values(CLASSES)) {
      if (options.missing === name) continue;
      callbacks.onMatch(name, clone(classes[name]));
      if (options.duplicateWrappers) callbacks.onMatch(name, clone(classes[name]));
      if (options.ambiguous && name === CLASSES.response)
        callbacks.onMatch(name, identity('shadow', {getClassLoader: () => root}));
    }
    if (!options.incomplete) callbacks.onComplete();
  }};
  if (options.noIdentity) for (const c of Object.values(classes)) delete c.$isSameObject;
  return {J, calls: () => cacheCalls, factoryUses};
}
function run(b) {try {return safeCapture(javaAdapter(b.J));} catch (e) {return errorResult(e);}}
for (const [label, options] of [
  ['same loader distinct wrappers', {}], ['parent-defined response', {parentResponse: true}],
  ['context child of default', {childContext: true, parentResponse: true}],
  ['default child of context', {defaultChild: true}], ['duplicate class wrappers', {duplicateWrappers: true}],
  ['system branch', {system: true, parentResponse: true}]
]) test(label, () => {const b = bridge(options); const r = run(b); assert.equal(r.ok, true, JSON.stringify(r)); assert.equal(b.calls(), 1);});
for (const [label, options, error, stage] of [
  ['null default', {nullDefault: true}, 'DEFAULT_LOADER_UNAVAILABLE', 'bootstrap'],
  ['null context loader', {nullContextLoader: true}, 'CONTEXT_LOADER_UNAVAILABLE', 'context'],
  ['sibling context', {siblingContext: true}, 'LOADER_UNRELATED', 'context'],
  ['wrong package', {wrongPackage: true}, 'VERSION_MISMATCH', 'version'],
  ['wrong version', {wrongVersion: true}, 'VERSION_MISMATCH', 'version'],
  ['missing context', {noContext: true}, 'CONTEXT_MISSING', 'context'],
  ['sibling response', {siblingResponse: true}, 'CLASS_LOADER_OUTSIDE_CONTEXT', 'response_class'],
  ['sibling SDK', {siblingSdk: true}, 'CLASS_LOADER_OUTSIDE_CONTEXT', 'sdk'],
  ['missing holder', {missing: CLASSES.holder}, 'CLASS_NOT_LOADED', 'holder'],
  ['missing response', {missing: CLASSES.response}, 'CLASS_NOT_LOADED', 'response_class'],
  ['missing cache class', {missing: CLASSES.open}, 'CLASS_NOT_LOADED', 'cache_class'],
  ['different resolved class', {wrongResolvedClass: true}, 'CLASS_IDENTITY_MISMATCH', 'response_class'],
  ['shadowed same name', {ambiguous: true}, 'CLASS_AMBIGUOUS', 'response_class'],
  ['incomplete enumeration', {incomplete: true}, 'ENUMERATION_INCOMPLETE', 'loaded_classes'],
  ['factory wrong loader', {badFactory: true}, 'FACTORY_LOADER_MISMATCH', 'context'],
  ['wrong declared return class', {badSignature: true}, 'CACHE_SIGNATURE_MISMATCH', 'cache_signature']
]) test(label + ' stops before cache', () => {
  const b = bridge(options); const r = run(b);
  assert.deepEqual(r, {ok: false, error, diagnostic: {stage, cache_read_started: false}});
  assert.equal(b.calls(), 0);
});
test('missing response must not attempt factory.use for it', () => {
  const b = bridge({missing: CLASSES.response}); run(b);
  assert(!b.factoryUses.includes(CLASSES.response)); assert.equal(b.calls(), 0);
});
test('uninitialized SDK stops before cache', () => {
  const b = bridge({uninitialized: true}); assert.equal(run(b).error, 'NOT_INITIALIZED'); assert.equal(b.calls(), 0);
});
test('post-read object mismatch is clearly distinguished', () => {
  const b = bridge({badResponse: true});
  assert.deepEqual(run(b), {ok: false, error: 'RESPONSE_TYPE_MISMATCH', diagnostic: {stage: 'response', cache_read_started: true}});
  assert.equal(b.calls(), 1);
});
test('same Java object different wrappers, no equals fallback', () => {
  assert.equal(sameJava(identity('a'), identity('a')), true);
  assert.equal(sameJava(identity('a'), identity('b')), false);
  assert.throws(() => sameJava({}, {}), /IDENTITY_API_UNAVAILABLE/);
});
test('exception values never escape fixed diagnostic stage', () => {
  const b = bridge(); b.J.ClassFactory.get = () => {throw Error('SYNTHETIC_SECRET_EXCEPTION');};
  const r = run(b); assert.equal(r.error, 'RUNTIME_INCOMPATIBLE');
  assert.equal(r.diagnostic.stage, 'context'); assert(!JSON.stringify(r).includes('SYNTHETIC'));
});
test('single permitted attempt, failure consumed; perform callback boundary respected', async () => {
  // Synthetic VM only; never writes or enables the delivered source file.
  const source = fs.readFileSync(__dirname + '/agent.js', 'utf8').replace('const RUNTIME_CAPTURE_ENABLED = false;', 'const RUNTIME_CAPTURE_ENABLED = true;');
  const b = bridge({nullDefault: true}); let queued;
  b.J.available = true; b.J.perform = fn => {queued = fn;};
  const c = {rpc: {exports: {}}, Java: b.J}; vm.createContext(c); vm.runInContext(source, c);
  const pending = c.rpc.exports.readsnapshot();
  assert.equal((await c.rpc.exports.readsnapshot()).error, 'BUSY_OR_CONSUMED');
  assert.equal(b.calls(), 0); queued();
  assert.equal((await pending).error, 'DEFAULT_LOADER_UNAVAILABLE');
  assert.equal((await c.rpc.exports.readsnapshot()).error, 'BUSY_OR_CONSUMED');
});
test('cyclic loader chain fails before cache', () => {
  const b = bridge(); b.J.classFactory.loader.getParent = () => b.J.classFactory.loader;
  assert.equal(run(b).error, 'LOADER_CHAIN_INVALID'); assert.equal(b.calls(), 0);
});
test('bridge without identity API fails before cache', () => {
  const b = bridge(); delete b.J.classFactory.loader.$isSameObject;
  assert.equal(run(b).error, 'IDENTITY_API_UNAVAILABLE'); assert.equal(b.calls(), 0);
});
