# Security policy

## Trust boundary

Nightflyer treats the machine running the game as untrusted. The client
accepts only Ed25519-signed leases, statuses, decisions, and key transitions,
verified against keys pinned in the application configuration before any
claim is read. Responses must bind to the per-request proof JTI, the
installation key's thumbprint, and the application's system ID; exact member
profiles and strict JSON parsing reject substituted or extended objects.

Installation keys are P-256 keys. On Windows they live in the CNG key stores
and are created non-exportable, preferring the TPM-backed Platform Crypto
Provider; persistent state is DPAPI-protected per user, atomically replaced,
and signed by that key. On macOS and Linux, memory sessions use a software
key and persistent sessions require an adapter backed by a platform key store;
there is no plaintext fallback. All client-generated randomness (proof JTIs,
retry jitter) comes from a cryptographic random number generator.

Transport security is HTTPS with certificate validation, refused redirects,
bounded response bodies, and idempotent in-flight retries that resend the
exact same bytes. The package's Ed25519 verifier and strict JSON reader are
vendored and dependency-free; the engine is only used for HTTP delivery and
never trusted for protocol decisions.

## Accepted limitations

- A lease's offline grace period is real authority: a device that stays
  offline cannot be revoked until the signed expiry elapses. Choose
  `requestedOfflineSeconds` accordingly and call `TickAsync` while protected
  work runs.
- Software-only persistence cannot detect every coordinated rollback of both
  an old signed state snapshot and the OS clock. `RequireOnlineAfterReboot`
  narrows this at the cost of requiring connectivity after each boot.
- The non-exportable CNG installation key and DPAPI state store are Windows
  features. Elsewhere, the protection of persistent state is exactly the
  protection of the adapter you provide.
- Unity player behavior varies by scripting backend and target platform;
  validate the flows you rely on in your own player build before shipping.
  Cryptographic operations use the runtime's
  `System.Security.Cryptography`; the vendored Ed25519 verification is pure C#.
- Nightflyer raises the bar for casual piracy but is not tamper protection:
  a determined attacker with full control of the machine can patch the
  client. Combine it with engine-side hardening appropriate to your threat
  model.
