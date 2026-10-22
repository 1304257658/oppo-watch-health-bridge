# Disabled business-cache reader candidate

This independently scoped research component reads an already initialized app's business cache through a candidate Frida RPC adapter. It is not a Windows controller, a production credential importer, or an authentication/refresh client. Runtime capture is disabled in the shipped source. No real credentials are included.

The four code/schema/test files are unchanged from the reviewed loader-preflight-2 candidate. This directory deliberately excludes archive copies, prior source versions, private handoff records, decompiled sources and device diagnostics. It does not replace the repository's existing offline scaffold.

## Offline tests

From this directory, using an existing Node.js 18+ installation (validated with v24.19.0):

```sh
node --check agent.js
node --test test_agent.js test_loaders.js
```

No npm dependencies or device connection are required. Tests inject synthetic objects and secrets; they do not execute Frida, JNI or Android. A VM test enables an in-memory source copy solely against its fake Java bridge. The shipped file remains disabled.

## Read contract

`describe()` reports the expected application/version and disabled runtime state. `readsnapshot()` returns `RUNTIME_DISABLED` by default. If a separately reviewed controller eventually authorizes execution, the candidate permits one attempt per agent instance; failures also consume that attempt. No automatic retries are allowed.

The intermediate schema is `oppo.business-cache-snapshot/1`, not the downstream Windows bootstrap or HTTP contract. On success it carries:

- `app`: fixed package/version, initialized business `app_id`, and `system`/`open` branch.
- `credentials`: access/refresh tokens, expiry values in milliseconds and advance values in seconds. Integer values are decimal strings preserving Java Long precision.
- `original_binding`: original cached `pkg_sign`, `device_id` and `host`. Empty host is retained and flagged as unresolved, never replaced with a guessed endpoint.
- `clock_sample`: sequential wall-clock and boot-elapsed samples before/after getter reads. These are not server time offsets or transferable Windows monotonic timestamps.
- `provenance` and `readiness`: fixed source metadata; `http_ready` remains false and on-device APK hash verification remains false.

Failures contain a fixed error code and may include `diagnostic.stage` and `diagnostic.cache_read_started`. The latter records an attempted cache invocation, not successful acquisition. Never log a complete successful RPC result. Schema validation alone does not enforce the Java Long upper bound, branch/cache-class pairing, or the precise missing-requirements list; receiving software must implement those checks explicitly.

The reader excludes idToken because the observed cache-save path modifies it. It does not export vendor signing material, collect RiskProbe/envParam, generate DUID, or initiate login, authorization or refresh. Missing initialization, instance, class, branch, binding or complete token metadata causes failure. Access-token-only material cannot satisfy this complete snapshot contract.

## Loader change

The earlier equality-only check rejected classes legitimately defined by a parent loader. This candidate anchors the fixed loaded Holder to its existing Context, validates package/version, and uses that Context's ClassFactory. Default and Context loaders must be identical or in a parent/child relationship; sibling loaders sharing an ancestor are rejected.

Only the five fixed business class names are retained from loaded-class enumeration. Each selected class must already have a unique eligible definition on the permitted ancestor chain; the resolved Class identity must match it. No arbitrary loader selection or heap scanning is performed. Object identity uses the bridge's `$isSameObject`, not overridable Java `equals()` or JavaScript wrapper identity. Missing identity support fails closed.

Cache class, response class, cache instance identity, declared cache-method return type and getter availability are checked before `loadAuthResponseCache`. A null default loader still stops with `DEFAULT_LOADER_UNAVAILABLE`; this change improves diagnosis rather than claiming to repair every possible initialization problem. It stays inside `Java.perform`, which may defer execution. A controller must discard late results after timeout and must not replay blindly.

Observed static cache reads may update in-process cache bookkeeping and register a FileObserver. ClassFactory resolution and the running app may have their own side effects; this is not a claim of zero runtime side effects or whole-app network isolation. Double getter sampling detects some changes but is not a cross-process atomic snapshot. Actual Android/Frida compatibility remains unverified.

Official API references:

- https://frida.re/docs/javascript-api/#java
- https://github.com/frida/frida-java-bridge/blob/main/lib/class-factory.js
- https://github.com/frida/frida-java-bridge/blob/main/lib/env.js

## Windows controller integration checklist

The current Windows controller is not included or integrated. Preserve its latest Java bridge loading, 4–10 digit passphrase, dynamic PID and recovery-launcher fixes; do not replace it with the earlier scaffold.

1. Review the current controller source and its exact bridge version and one-time authorization flow.
2. Update agent bytes, schema handling and controller hash allowlist together. Agent SHA256: `4a83a177f20aea1ee93e619c6461cc91163616b1f8af20be0f6542b62969e89a`; schema SHA256: `2b5c4447a2b09e2147d2fdd44b00fd87d32b3997f13b76c442fbca49b9bbd41e`. Hash original UTF-8/LF bytes including final newline. Review any authorized in-memory payload transformation separately; this component does not implement one.
3. Accept only the fixed error/stage vocabulary. Integrate secure local RPC handling, encrypted atomic storage, binding checks, secret-free diagnostics, timeout disposal, one-attempt consumption and verified restoration. Do not convert `cache_read_started` into a success flag.
4. Test the complete controller/bridge/reader pairing with synthetic inputs and retain a paired rollback version before any separately authorized device validation.
5. Keep unknown OAEP/provider, signing configuration, environment requirements, DUID, trace, host resolution and server-clock mapping as unresolved requirements. A readable snapshot is not proof of HTTP readiness or independent long-term renewal.

No live attachment/acquisition command is provided. Publication and synthetic tests do not establish successful token acquisition or renewal. The repository's SECURITY.md and NOTICE.md continue to apply.
