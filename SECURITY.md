# Security and privacy

This public snapshot is synthetic/offline research. Do not submit real credentials to its forms or add them to its configuration.

Never commit access/refresh tokens, account identifiers, device identifiers, health records, APKs, app databases, packet captures, raw diagnostics, private keys or screenshots of authenticated sessions. Do not put those in issues, pull requests, CI logs, environment setup scripts or test artifacts either.

The real-network factory and emulator adapter are absent by default, and vendor signing material has been replaced with synthetic fixtures. Adding a real integration requires independent review, explicit authorization, secure user-controlled authentication, narrow recipients/scope, revocation and lifecycle controls. Do not expose the loopback test form publicly or assume it is a production secret receiver.

Mutable buffers are overwritten as a best effort. Python, browser and operating-system memory erasure is not guaranteed. This is not a secure vault.

If you discover an issue, report the minimal non-sensitive reproduction. Do not post live tokens or personal health records as evidence. If a secret was accidentally committed, revoke it and follow the hosting provider's secret-removal procedure; deleting the current file alone is insufficient.
