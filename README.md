# System Locker Nightflyer — Unity

Official Unity client (2022.3 LTS+) for System Locker Nightflyer, an offline
authorization lease protocol for desktop software. Nightflyer proves possession
of an installation P-256 key on every request and accepts only Ed25519-signed
leases, statuses, decisions, and key transitions from locally pinned keys.

Nightflyer requires a System Locker account and a configured Nightflyer system.
Initial authorization and periodic server checks need an internet connection;
a valid cached lease can authorize offline play until its signed expiry. Any
System Locker service charges are separate from this package.

## Install

Unity Package Manager → **Add package from git URL**:

```
https://github.com/systemlocker/System-Locker-Nightflyer-Unity.git
```

Until the Unity Asset Store listing is live, install from the Git URL above.
The package has no external dependencies: Ed25519 verification and the strict
JSON reader/writer used for protocol traffic are included.

## Quickstart

```csharp
using System.Collections.Generic;
using SystemLocker.Nightflyer;

var config = new NightflyerConfig("abcdefghijklmnopqrst", new Dictionary<string, string>
{
    ["YOUR_KID"] = "YOUR_BASE64URL_ED25519_KEY",
});
// Keep this session for as long as protected game code can run.
_session = NightflyerAuthorizationSession.CreateMemory(config);

var result = await _session.EasyAuthorizeAsync(
    new NightflyerBinding(Application.version, "", myHwid),
    requestedOfflineSeconds: 86400,
    licenseKey: enteredKey); // Omit after the key has been retained.

if (result.CanProceed)
    StartProtectedWork(result.Lease!);
else if (result.ShouldPromptForKey)
    ShowLicenseKeyPrompt();
```

Do not create the session in a short-lived local scope: disposing a
memory-only session ends its lease. The sample keeps its bootstrap object and
session alive across scene loads, and exposes `SubmitLicenseKey` for a UI button.
Call `TickAsync()` periodically while protected game code is active so due
leases renew, then call `ShutdownAsync()` during an orderly shutdown.

The `Samples~/NightflyerQuickstart` folder (importable from the Package
Manager) shows the same flow as a MonoBehaviour bootstrap that gates a scene.

Networking runs over `UnityWebRequest` (installed automatically at engine
startup). Redirects are refused and response bodies are capped at 1 MiB while
streaming, matching the protocol's transport rules. The public API is
asynchronous; call it from a coroutine (as in the sample), an `async void`
event handler, or a background thread — never block the main thread on it, and
prefer `ShutdownAsync()` before `Dispose()` when quitting.

## EasyAuthorize and persistent startup

`EasyAuthorizeAsync()` is the recommended startup API. With a newly entered key
it requests a fresh lease. Without one, it loads protected state, renews a due
lease or calls `SynchronizeStatusAsync()` for a strict status check, finishes
any exact pending end request, and requests a new lease with the retained key
when the old lease is inactive, ended, or expired.

The result makes application policy explicit: `CanProceed`, `IsOffline`,
`CredentialPresent`, `ShouldPromptForKey`, `RetryAfter`, and a typed
`RecommendedAction`. A `NetworkUnavailable` result with `CanProceed == true`
means the online check did not finish but the existing signed offline lease is
still usable. The application can continue and retry after the reported delay.

If a developer **unbinds** a lease, the old lease is reported as revoked and
surfaces locally as `Inactive`; this is not a permanent ban on the installation
or key. `EasyAuthorizeAsync()` immediately tries to obtain a new lease with the
retained key. A signed `KEY_NOT_FOUND` result clears the retained key and sets
`ShouldPromptForKey`; other denials retain it while still allowing the user to
enter a replacement.

## Persistence by platform

- **Windows**: `OpenPersistent` with a `WindowsDpapiStateStore` works out of
  the box. State is protected with per-user DPAPI, atomically replaced, and
  signed by a separately stored, non-exportable CNG installation key (Platform
  Crypto Provider when the device has one). The record contains the lease, time
  checkpoint, retained license key, authenticated signing-key transition
  history, and status high-water marks.
- **macOS / Linux**: memory-only sessions work everywhere with a software
  P-256 installation key. For persistent sessions, provide an
  `INightflyerStateStore` backed by Keychain or Secret Service and a key
  provider backed by a platform key store; the package intentionally has no
  plaintext-file fallback.

The retained license key lets an inactive installation request a fresh lease
without asking the user to type it again. Nightflyer erases it only after the
server returns the definitive signed `KEY_NOT_FOUND` result.

## What the client enforces

- HTTPS-only endpoints, refused redirects, and a fresh ES256 installation proof.
- Canonical request binding and access-token binding for renewal, status, and end.
- Ed25519 verification before token claims are consumed, with fixed JWS types
  and strict point/encoding checks (small-order and non-canonical values are
  rejected).
- Exact lease, status, and transition profiles; a status or decision cannot be
  substituted for a lease.
- Request-JTI, system, installation-thumbprint, expiry, and key-transition checks.
- Installation-key-signed state, replayable server-signed key transitions,
  persisted high-water marks, revocation enforcement, and per-boot time checks.
- A renewal state machine with cross-process installation coordination,
  terminal end tombstones, and offline-on-network-failure behavior.

## Offline time and travel

A valid cached lease can be used without connectivity, including while
traveling. During the same OS boot, lease time advances from verified server
UTC using an elapsed-time clock that includes sleep. Time-zone changes and
wall-clock corrections do not shorten or extend the signed lease lifetime.

After a reboot, a persisted lease remains usable by default when UTC is
consistent with the installation-key-signed high-water checkpoint. Set
`RequireOnlineAfterReboot = true` when a deployment prefers the stronger
policy of requiring one signed online response after every OS boot.
Software-only storage cannot detect every coordinated rollback of both an old
signed state snapshot and the OS clock. A successful signed online response
repairs a bad local time checkpoint but does not extend an existing lease's
signed expiry. Memory-only sessions are not persisted across application or OS
restarts.

## Security addendum

> [!WARNING]
> Watch this repository (Watch → Custom → Releases) and update your
> dependency when a release ships: releases regularly add security
> enhancements.

Pinned server keys are a developer-provided trust root. The session persists
the signed transition chain rather than a derived key-ring snapshot, then
replays it from those roots on every open. The session rejects revoked keys,
devices, grants, rollback, and stale leases. It uses the signed server-time
anchor plus a suspend-aware monotonic clock within a boot. Nightflyer cannot
immediately revoke a device that is offline, and even though it increases
resilience to cracking, it is not a substitute for proper obfuscation and
other protections. See SECURITY.md for the trust boundary and the
engine-specific limitations.
