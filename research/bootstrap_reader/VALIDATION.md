# Validation

Validated on 2026-10-22 in an isolated cloud checkout based on repository commit `164aef9a96723979775f8e7b4b295f32cea323e9`.

- `node --check research/bootstrap_reader/agent.js`: passed.
- `node --test research/bootstrap_reader/test_agent.js research/bootstrap_reader/test_loaders.js`: 67 passed, 0 failed, 0 skipped (Node v24.19.0).
- `python -m unittest -q` from repository root: 58 passed.
- JSON Schema Draft 2020-12 structural validation: passed.

Reader tests are entirely synthetic. Existing Python tests use simulated inputs/connections and local loopback tests. No real account, token acquisition, Android, JNI, Frida session or renewal request was tested. No Windows controller integration is included. Runtime capture remains disabled.

Publication scope is only the reader, schema, synthetic tests, this validation note, integration README and checksums. No APK, decompiled source, vendor secret, real credential, credential archive, device output or private handoff notes are included.
