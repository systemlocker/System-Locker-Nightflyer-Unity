using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SystemLocker.Nightflyer
{
    /// <summary>Developer-facing result of the lease state machine. Applications should check this regularly, not only at startup.</summary>
    public enum AuthorizationState
    {
        AuthorizedOnline,
        AuthorizedOffline,
        RenewalDue,
        Expired,
        Ending,
        Ended,
        Inactive,
        AuthModeInUse,
        ProtocolUpgradeRequired,
        ClockUntrusted,
        DeviceChanged,
        AuthDenied,
        StorageUnavailable,
        NetworkUnavailable,
        ProtocolFailure,
        InstallationInUse,
    }

    public sealed record AuthorizationSnapshot(AuthorizationState State, Lease? Lease, string? Diagnostic);

    /// <summary>The application response recommended by <see cref="NightflyerAuthorizationSession.EasyAuthorizeAsync"/>.</summary>
    public enum EasyAuthorizationAction
    {
        None,
        ContinueOffline,
        RetryOnline,
        RequestLicenseKey,
        UpdateClient,
        CheckClock,
        RepairProtectedStorage,
        ResolveDeviceBinding,
        ResolveAuthenticationMode,
        WaitForInstallation,
        ContactDeveloper,
    }

    /// <summary>A policy-ready authorization result that keeps the underlying state-machine snapshot available.</summary>
    public sealed record EasyAuthorizationResult(
        AuthorizationSnapshot Snapshot,
        bool CanProceed,
        bool IsOffline,
        bool CredentialPresent,
        bool ShouldPromptForKey,
        EasyAuthorizationAction RecommendedAction,
        TimeSpan? RetryAfter)
    {
        public AuthorizationState State => Snapshot.State;
        public Lease? Lease => Snapshot.Lease;
        public string? Diagnostic => Snapshot.Diagnostic;
    }

    public sealed record NightflyerBinding(string Version, string Digest, string SlHwid);

    /// <summary>Storage boundary for persistent Nightflyer state. Implementations must provide authenticated, per-user protection.</summary>
    public interface INightflyerStateStore
    {
        byte[]? Load();
        void Save(ReadOnlySpan<byte> value);
        void Delete();
    }

    /// <summary>Optional stable identity used to serialize first-open state creation across processes.</summary>
    public interface INightflyerStateStoreIdentity
    {
        string LockIdentity { get; }
    }

    /// <summary>
    /// Windows-only, per-user DPAPI state store. Writes are flushed and atomically
    /// replaced while a LockFileEx-backed FileStream lock serializes file access.
    /// </summary>
    public sealed class WindowsDpapiStateStore : INightflyerStateStore, INightflyerStateStoreIdentity
    {
        private const int MaxStateBytes = 1_048_576;
        // DPAPI adds implementation-defined framing around the plaintext. Keep a
        // separate file limit so a maximum-size valid state remains readable.
        private const int MaxProtectedStateBytes = MaxStateBytes * 2;
        private const int CryptprotectUiForbidden = 0x1;
        private const int MovefileReplaceExisting = 0x1;
        private const int MovefileWriteThrough = 0x8;
        private readonly string _path;
        private readonly string _lockPath;

        public WindowsDpapiStateStore(string path)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                throw new PlatformNotSupportedException("Persistent Nightflyer storage needs a platform key-store adapter on this operating system.");
            _path = Path.GetFullPath(path);
            _lockPath = _path + ".lock";
        }

        public string LockIdentity => _path;

        public byte[]? Load() => WithFileLock(() =>
        {
            if (!File.Exists(_path)) return null;
            var encrypted = File.ReadAllBytes(_path);
            try
            {
                if (encrypted.Length is 0 or > MaxProtectedStateBytes)
                    throw new NightflyerException(NightflyerFailure.InvalidState, "Protected Nightflyer state has an invalid size.");
                var plain = Unprotect(encrypted);
                if (plain.Length is > 0 and <= MaxStateBytes) return plain;
                CryptographicOperations.ZeroMemory(plain);
                throw new NightflyerException(NightflyerFailure.InvalidState, "Protected Nightflyer state has an invalid payload size.");
            }
            finally { CryptographicOperations.ZeroMemory(encrypted); }
        });

        public void Save(ReadOnlySpan<byte> value)
        {
            if (value.Length is 0 or > MaxStateBytes)
                throw new NightflyerException(NightflyerFailure.LocalFailure, "Nightflyer state has an invalid size.");
            var plain = value.ToArray();
            try
            {
                WithFileLock(() =>
                {
                    var protectedValue = Protect(plain);
                    var directory = Path.GetDirectoryName(_path)!;
                    var temporary = Path.Combine(directory, $".{Path.GetFileName(_path)}.{Guid.NewGuid():N}.tmp");
                    try
                    {
                        using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                        {
                            stream.Write(protectedValue);
                            stream.Flush(flushToDisk: true);
                        }
                        if (!MoveFileEx(temporary, _path, MovefileReplaceExisting | MovefileWriteThrough))
                            throw new NightflyerException(NightflyerFailure.LocalFailure, "Windows could not atomically replace protected Nightflyer state.");
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(protectedValue);
                        if (File.Exists(temporary)) File.Delete(temporary);
                    }
                    return 0;
                });
            }
            finally { CryptographicOperations.ZeroMemory(plain); }
        }

        public void Delete() => WithFileLock(() =>
        {
            if (File.Exists(_path)) File.Delete(_path);
            return 0;
        });

        private T WithFileLock<T>(Func<T> action)
        {
            var directory = Path.GetDirectoryName(_path)!;
            Directory.CreateDirectory(directory);
            using var stream = new FileStream(_lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite);
            if (stream.Length == 0) { stream.WriteByte(0); stream.Flush(flushToDisk: true); }
            stream.Lock(0, 1);
            try { return action(); }
            finally { stream.Unlock(0, 1); }
        }

        private static byte[] Protect(byte[] value) => Crypt(false, value);
        private static byte[] Unprotect(byte[] value) => Crypt(true, value);

        private static byte[] Crypt(bool unprotect, byte[] value)
        {
            var input = DataBlob.From(value);
            DataBlob output = default;
            try
            {
                var ok = unprotect
                    ? CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, CryptprotectUiForbidden, ref output)
                    : CryptProtectData(ref input, "System Locker Nightflyer", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, CryptprotectUiForbidden, ref output);
                if (!ok) throw new NightflyerException(NightflyerFailure.LocalFailure, "Windows could not protect Nightflyer state for this user.");
                if (output.Count is 0 or > MaxProtectedStateBytes)
                    throw new NightflyerException(NightflyerFailure.LocalFailure, "Windows returned protected Nightflyer state with an invalid size.");
                var result = new byte[checked((int)output.Count)];
                Marshal.Copy(output.Pointer, result, 0, result.Length);
                return result;
            }
            finally
            {
                input.FreeInput();
                output.FreeOutput();
                CryptographicOperations.ZeroMemory(value);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DataBlob
        {
            public uint Count;
            public IntPtr Pointer;

            public static DataBlob From(byte[] value)
            {
                var pointer = Marshal.AllocHGlobal(value.Length);
                Marshal.Copy(value, 0, pointer, value.Length);
                return new DataBlob { Count = checked((uint)value.Length), Pointer = pointer };
            }

            public void FreeInput()
            {
                if (Pointer == IntPtr.Zero) return;
                ZeroUnmanagedMemory(Pointer, checked((int)Count));
                Marshal.FreeHGlobal(Pointer);
                Pointer = IntPtr.Zero;
            }

            public void FreeOutput()
            {
                if (Pointer == IntPtr.Zero) return;
                var pointer = Pointer;
                Pointer = IntPtr.Zero;
                try
                {
                    // A successful DPAPI call is bounded above before this cleanup.
                    // Do not let a nonsensical native length make cleanup unsafe or
                    // hide the original interop error.
                    if (Count <= MaxProtectedStateBytes) ZeroUnmanagedMemory(pointer, (int)Count);
                }
                finally { LocalFree(pointer); }
            }
        }

        private static unsafe void ZeroUnmanagedMemory(IntPtr pointer, int count)
        {
            if (pointer == IntPtr.Zero || count <= 0) return;
            // CryptographicOperations supplies the managed runtime's supported
            // non-elidable wipe without depending on a macro-only Win32 symbol.
            CryptographicOperations.ZeroMemory(new Span<byte>(pointer.ToPointer(), count));
        }

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptProtectData(ref DataBlob input, string description, IntPtr optionalEntropy, IntPtr reserved, IntPtr prompt, int flags, ref DataBlob output);

        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptUnprotectData(ref DataBlob input, IntPtr description, IntPtr optionalEntropy, IntPtr reserved, IntPtr prompt, int flags, ref DataBlob output);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool MoveFileEx(string existingFile, string newFile, int flags);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);
    }

    public sealed class NightflyerAuthorizationSession : IDisposable
    {
        private const int StateVersion = 4;
        private const int LegacyStateVersion = 3;
        private const int LockPollMilliseconds = 50;
        private static readonly ConcurrentDictionary<string, byte> MemoryOwners = new(StringComparer.Ordinal);

        private readonly NightflyerConfig _config;
        private readonly INightflyerStateStore? _store;
        private readonly INightflyerInstallationKeyProvider? _keyProvider;
        private readonly IInstallationKey _key;
        private readonly bool _ownsKey;
        private readonly INightflyerTransport? _transport;
        private NightflyerClient _client;
        private readonly Mutex _installationMutex;
        private readonly SemaphoreSlim _gate = new(1, 1);
        private readonly bool _persistent;
        private readonly string _installationLockName;
        private readonly LifetimeMutexLease? _memoryMutexLease;
        private PersistedState _state;
        private bool _disposed;
        private bool _forgotten;

        private NightflyerAuthorizationSession(
            NightflyerConfig config,
            IInstallationKey key,
            bool ownsKey,
            INightflyerInstallationKeyProvider? keyProvider,
            INightflyerStateStore? store,
            PersistedState state,
            INightflyerTransport? transport)
        {
            // Snapshot the application's roots. A mutable dictionary supplied by
            // the caller must not be able to redefine trust during a later reload.
            _config = CreateClientConfig(config,
                config.TrustedSigningKeys.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal));
            _key = key;
            _ownsKey = ownsKey;
            _keyProvider = keyProvider;
            _store = store;
            _persistent = store is not null;
            _state = state;
            _transport = transport;
            _client = new NightflyerClient(_config, key, transport);
            _client.RestoreTrustedSigningKeyTransitions(state.KeyTransitions, state.KeysetSequence);

            _installationLockName = LockName("Installation", config.SystemId, key.Thumbprint);
            _installationMutex = new Mutex(false, _installationLockName);
            if (!_persistent)
            {
                if (!MemoryOwners.TryAdd(_installationLockName, 0))
                {
                    _client.Dispose();
                    _installationMutex.Dispose();
                    throw new NightflyerException(NightflyerFailure.InvalidState, "Another memory-only Nightflyer session owns this installation.");
                }
                try
                {
                    _memoryMutexLease = new LifetimeMutexLease(_installationMutex, config.InstallationLockTimeout);
                }
                catch
                {
                    MemoryOwners.TryRemove(_installationLockName, out _);
                    _client.Dispose();
                    _installationMutex.Dispose();
                    throw;
                }
            }
        }

        public static NightflyerAuthorizationSession CreateMemory(
            NightflyerConfig config,
            IInstallationKey? key = null,
            INightflyerTransport? transport = null)
        {
            if (key is not null)
                return new NightflyerAuthorizationSession(config, key, false, null, null, NewState(config, key, ""), transport);
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var provider = new WindowsNcryptInstallationKeyProvider();
                var handle = provider.OpenOrCreateStable(config.SystemId);
                return new NightflyerAuthorizationSession(config, handle.Key, true, provider, null, NewState(config, handle.Key, handle.Reference), transport);
            }

            // Non-Windows callers can supply a Keychain/Secret Service-backed key.
            // This explicit fallback is ephemeral and therefore a new device after restart.
            var ephemeral = new EcdsaInstallationKey();
            return new NightflyerAuthorizationSession(config, ephemeral, true, null, null, NewState(config, ephemeral, ""), transport);
        }

        public static NightflyerAuthorizationSession OpenPersistent(
            NightflyerConfig config,
            INightflyerStateStore store,
            INightflyerTransport? transport = null)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                throw new PlatformNotSupportedException("Persistent Nightflyer mode requires an explicit platform key provider on this operating system.");
            return OpenPersistent(config, store, new WindowsNcryptInstallationKeyProvider(), transport);
        }

        public static NightflyerAuthorizationSession OpenPersistent(
            NightflyerConfig config,
            INightflyerStateStore store,
            INightflyerInstallationKeyProvider keyProvider,
            INightflyerTransport? transport = null)
        {
            if (config is null) throw new ArgumentNullException(nameof(config));
            if (store is null) throw new ArgumentNullException(nameof(store));
            if (keyProvider is null) throw new ArgumentNullException(nameof(keyProvider));

            var identity = store is INightflyerStateStoreIdentity identified
                ? identified.LockIdentity
                : store.GetType().AssemblyQualifiedName ?? store.GetType().FullName ?? "custom";
            using var bootstrap = new Mutex(false, LockName("Bootstrap", config.SystemId, identity));
            if (!WaitForMutex(bootstrap, config.InstallationLockTimeout, CancellationToken.None))
                throw new NightflyerException(NightflyerFailure.InvalidState, "Another process is opening this Nightflyer state.");
            try
            {
                var bytes = AccessProtectedStorage(store.Load);
                PersistedState state;
                InstallationKeyHandle handle;
                var created = bytes is null;
                if (bytes is null)
                {
                    handle = keyProvider.Create(config.SystemId);
                    state = NewState(config, handle.Key, handle.Reference);
                }
                else
                {
                    try
                    {
                        state = DeserializeState(bytes);
                        var migratedLegacyState = state.Version == LegacyStateVersion;
                        state = UpgradeLegacyState(config, state);
                        ValidateLoadedState(config, state, requireSignature: !migratedLegacyState);
                        handle = keyProvider.Load(config.SystemId, state.InstallationKeyReference);
                        if (!FixedAsciiEquals(handle.Key.Thumbprint, state.InstallationThumbprint))
                        {
                            if (handle.Key is IDisposable disposable) disposable.Dispose();
                            throw new NightflyerException(NightflyerFailure.InvalidState, "Persistent state belongs to another installation key.");
                        }
                        if (!migratedLegacyState) VerifyStateSignature(state, handle.Key);
                    }
                    finally { CryptographicOperations.ZeroMemory(bytes); }
                }

                NightflyerAuthorizationSession? session = null;
                try
                {
                    session = new NightflyerAuthorizationSession(config, handle.Key, true, keyProvider, store, state, transport);
                    session.VerifyRuntimeState(state, session._client);
                    session.Persist();
                    return session;
                }
                catch
                {
                    if (session is not null) session.Dispose();
                    else if (handle.Key is IDisposable disposable) disposable.Dispose();
                    if (created)
                    {
                        // Creation is all-or-nothing: do not strand a named CNG
                        // key or a half-written state record after initialization.
                        try { keyProvider.Delete(config.SystemId, handle.Reference); }
                        finally { AccessProtectedStorage(store.Delete); }
                    }
                    throw;
                }
            }
            catch (NightflyerException) { throw; }
            catch (Exception exception)
            {
                throw new NightflyerException(NightflyerFailure.InvalidState, $"Persistent Nightflyer state could not be opened: {exception.Message}");
            }
            finally { bootstrap.ReleaseMutex(); }
        }

        public AuthorizationSnapshot Load()
        {
            ThrowIfDisposed();
            if (!TryEnter(CancellationToken.None))
                return new AuthorizationSnapshot(AuthorizationState.InstallationInUse, null, "Another process is updating this installation.");
            try { return EvaluateLocalState(); }
            finally { Exit(); }
        }

        /// <summary>
        /// Runs the recommended startup and recovery flow. Supply a newly entered
        /// license key on first use or when replacing a denied key; omit it to use
        /// the protected retained credential.
        /// </summary>
        public async Task<EasyAuthorizationResult> EasyAuthorizeAsync(
            NightflyerBinding binding,
            int requestedOfflineSeconds,
            string? licenseKey = null,
            CancellationToken cancellationToken = default)
        {
            AuthorizationSnapshot snapshot;
            try
            {
                if (licenseKey is not null)
                {
                    snapshot = await AuthorizeWithKeyAsync(
                        licenseKey, binding, requestedOfflineSeconds, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    snapshot = Load();
                    snapshot = snapshot.State switch
                    {
                        AuthorizationState.RenewalDue => await RenewIfDueAsync(binding, cancellationToken).ConfigureAwait(false),
                        AuthorizationState.AuthorizedOffline or AuthorizationState.ClockUntrusted =>
                            await SynchronizeStatusAsync(cancellationToken).ConfigureAwait(false),
                        // A prior ambiguous end must finish with its exact persisted
                        // request before this installation can start a new lease epoch.
                        AuthorizationState.Ending => await EndAsync("resume_pending_end", cancellationToken).ConfigureAwait(false),
                        _ => snapshot,
                    };

                    if (snapshot.State is AuthorizationState.Inactive
                        or AuthorizationState.Ended
                        or AuthorizationState.Expired
                        or AuthorizationState.AuthDenied)
                    {
                        snapshot = await AuthorizeWithStoredKeyAsync(
                            binding, requestedOfflineSeconds, cancellationToken).ConfigureAwait(false);
                    }
                }
            }
            catch (NightflyerException exception) when (exception.Failure is NightflyerFailure.InvalidState or NightflyerFailure.LocalFailure)
            {
                snapshot = new AuthorizationSnapshot(AuthorizationState.StorageUnavailable, null, exception.Message);
            }
            catch (NightflyerException exception) when (exception.Failure is NightflyerFailure.InvalidResponse or NightflyerFailure.InvalidSignature or NightflyerFailure.InvalidToken)
            {
                snapshot = new AuthorizationSnapshot(AuthorizationState.ProtocolFailure, null, exception.Message);
            }

            return DescribeEasyAuthorization(snapshot);
        }

        public Task<AuthorizationSnapshot> AuthorizeWithKeyAsync(
            string licenseKey,
            NightflyerBinding binding,
            int requestedOfflineSeconds,
            CancellationToken cancellationToken = default) =>
            RunLockedAsync(async () =>
            {
                if (string.IsNullOrEmpty(licenseKey) || licenseKey.Length > 160)
                    throw new NightflyerException(NightflyerFailure.Configuration, "License key must contain between 1 and 160 characters.");
                _state.StoredLicenseKey = licenseKey;
                Persist();
                return await ExecuteAsync(() => _client.AuthorizeWithKeyAsync(
                    licenseKey,
                    binding.Version,
                    binding.Digest,
                    binding.SlHwid,
                    requestedOfflineSeconds,
                    _persistent,
                    _state.KeysetSequence,
                    _state.StatusSequence,
                    cancellationToken), cancellationToken, freshAuthorization: true, forgetMissingKey: true).ConfigureAwait(false);
            }, cancellationToken);

        /// <summary>Requests a fresh lease with the license key retained by the protected state store.</summary>
        public Task<AuthorizationSnapshot> AuthorizeWithStoredKeyAsync(
            NightflyerBinding binding,
            int requestedOfflineSeconds,
            CancellationToken cancellationToken = default) =>
            RunLockedAsync(async () =>
            {
                if (string.IsNullOrEmpty(_state.StoredLicenseKey))
                    return new AuthorizationSnapshot(AuthorizationState.AuthDenied, null, "NO_STORED_LICENSE_KEY");
                return await ExecuteAsync(() => _client.AuthorizeWithKeyAsync(
                    _state.StoredLicenseKey,
                    binding.Version,
                    binding.Digest,
                    binding.SlHwid,
                    requestedOfflineSeconds,
                    _persistent,
                    _state.KeysetSequence,
                    _state.StatusSequence,
                    cancellationToken), cancellationToken, freshAuthorization: true, forgetMissingKey: true).ConfigureAwait(false);
            }, cancellationToken);

        public Task<AuthorizationSnapshot> AuthorizeWithAccountAsync(
            string username,
            string password,
            NightflyerBinding binding,
            int requestedOfflineSeconds,
            CancellationToken cancellationToken = default) =>
            RunLockedAsync(
                () => ExecuteAsync(() => _client.AuthorizeWithAccountAsync(
                    username,
                    password,
                    binding.Version,
                    binding.Digest,
                    binding.SlHwid,
                    requestedOfflineSeconds,
                    _persistent,
                    _state.KeysetSequence,
                    _state.StatusSequence,
                    cancellationToken), cancellationToken, freshAuthorization: true),
                cancellationToken);

        public Task<AuthorizationSnapshot> RenewIfDueAsync(NightflyerBinding binding, CancellationToken cancellationToken = default) =>
            RunLockedAsync(async () =>
            {
                var local = EvaluateLocalState();
                if (_state.Lease is null || local.State is not AuthorizationState.RenewalDue)
                    return local;
                if (_state.NextRetryUnix > _config.Clock.UtcNow.ToUnixTimeSeconds())
                    return new AuthorizationSnapshot(AuthorizationState.RenewalDue, _state.Lease, "Renewal is waiting for its bounded retry backoff.");
                return await ExecuteAsync(() => _client.RenewAsync(
                    _state.Lease.Compact,
                    binding.Version,
                    binding.Digest,
                    binding.SlHwid,
                    _state.KeysetSequence,
                    _state.StatusSequence,
                    cancellationToken), cancellationToken).ConfigureAwait(false);
            }, cancellationToken);

        /// <summary>Runs the lease scheduler once. Call this periodically while protected work is active.</summary>
        public async Task<AuthorizationSnapshot> TickAsync(NightflyerBinding binding, CancellationToken cancellationToken = default)
        {
            var result = await RenewIfDueAsync(binding, cancellationToken).ConfigureAwait(false);
            if (!_persistent && result.State == AuthorizationState.Expired)
                return await EndAsync("lease_expired", cancellationToken).ConfigureAwait(false);
            return result;
        }

        public Task<AuthorizationSnapshot> SynchronizeStatusAsync(CancellationToken cancellationToken = default) =>
            RunLockedAsync(async () =>
            {
                if (_state.Lease is null) return EvaluateLocalState();
                return await ExecuteAsync(() => _client.StatusAsync(
                    _state.Lease.Compact,
                    _state.KeysetSequence,
                    _state.StatusSequence,
                    cancellationToken), cancellationToken).ConfigureAwait(false);
            }, cancellationToken);

        public Task<AuthorizationSnapshot> EndAsync(string reason, CancellationToken cancellationToken = default) =>
            RunLockedAsync(async () =>
            {
                if (_state.Ended) return EvaluateLocalState();
                if (_state.Lease is null && _state.PendingEnd is null) return EvaluateLocalState();

                PreparedNightflyerRequest prepared;
                if (_state.PendingEnd is not null)
                {
                    prepared = _state.PendingEnd;
                }
                else
                {
                    prepared = _client.PrepareEnd(_state.Lease!.Compact, reason, _state.KeysetSequence, _state.StatusSequence);
                    _state.PendingEnd = prepared;
                    _state.Ending = true;
                    Persist();
                }

                try
                {
                    var response = await _client.SendPreparedAsync(prepared, cancellationToken).ConfigureAwait(false);
                    if (response.HttpStatus == 429 || response.HttpStatus >= 500)
                    {
                        ScheduleRetry(response.RetryAfter);
                        return new AuthorizationSnapshot(AuthorizationState.Ending, null, response.Problem?.Code ?? response.DecisionCode ?? "The end request is waiting for an exact retry.");
                    }

                    Accept(response);
                    if (_state.Revoked) return EvaluateLocalState(response.DecisionCode);
                    if (response.DecisionCode != "LEASE_ENDED" && response.Decision?.LeaseDisposition != "ended")
                        throw new NightflyerException(NightflyerFailure.InvalidState, "The server did not acknowledge the terminal end state.");
                    _state.Ending = false;
                    _state.Ended = true;
                    _state.LeaseCompact = null;
                    _state.Lease = null;
                    _state.PendingEnd = null;
                    Persist();
                    return new AuthorizationSnapshot(AuthorizationState.Ended, null, response.DecisionCode);
                }
                catch (NightflyerException exception) when (exception.Failure == NightflyerFailure.Transport)
                {
                    ScheduleRetry(null);
                    return new AuthorizationSnapshot(AuthorizationState.Ending, null, "The exact end request is retained for retry.");
                }
            }, cancellationToken);

        /// <summary>
        /// Ends a memory-only lease without blocking the calling thread, for hosts
        /// where a synchronous network call on the main thread is unacceptable.
        /// Dispose still performs the best-effort end if this was never awaited.
        /// </summary>
        public async Task ShutdownAsync(string reason = "process_shutdown", CancellationToken cancellationToken = default)
        {
            if (_disposed) return;
            try { await EndAsync(reason, cancellationToken).ConfigureAwait(false); }
            catch (NightflyerException) { }
        }

        /// <summary>Deletes only a terminal local record. Active or pending leases must be ended or revoked first.</summary>
        public void Forget()
        {
            ThrowIfDisposed();
            if (!TryEnter(CancellationToken.None))
                throw new NightflyerException(NightflyerFailure.InvalidState, "Another process is updating this installation.");
            try
            {
                if (_state.Lease is not null || _state.Ending)
                    throw new NightflyerException(NightflyerFailure.InvalidState, "Refusing to forget an active or pending Nightflyer lease; end it first.");
                if (_keyProvider is not null && !string.IsNullOrEmpty(_state.InstallationKeyReference))
                {
                    _keyProvider!.Delete(_config.SystemId, _state.InstallationKeyReference);
                    // Once the non-exportable key is gone, stale state must never be
                    // used again even if deleting the backing record itself fails.
                    _forgotten = true;
                    if (_store is not null) AccessProtectedStorage(_store.Delete);
                }
                else
                {
                    _forgotten = true;
                }
            }
            finally { Exit(); }
        }

        private async Task<AuthorizationSnapshot> ExecuteAsync(
            Func<Task<NightflyerResponse>> operation,
            CancellationToken cancellationToken,
            bool freshAuthorization = false,
            bool forgetMissingKey = false)
        {
            try
            {
                var response = await operation().ConfigureAwait(false);
                var responseCode = response.DecisionCode ?? response.Problem?.Code;
                var signedMissingKey = forgetMissingKey && response.Decision?.ResponseCode == "KEY_NOT_FOUND";
                if (response.Lease is not null || response.Decision is not null || response.VerifiedStatus is not null)
                    Accept(response, freshAuthorization);
                if (signedMissingKey)
                {
                    // Credential deletion is a security-sensitive state mutation;
                    // an unsigned Problem Details body is never sufficient.
                    _state.StoredLicenseKey = null;
                    Persist();
                }

                if (response.HttpStatus == 429 || response.HttpStatus >= 500)
                {
                    ScheduleRetry(response.RetryAfter);
                    return RetryableFailureSnapshot(response.Problem?.Code ?? response.DecisionCode ?? "SERVICE_UNAVAILABLE");
                }

                if (signedMissingKey)
                    return new AuthorizationSnapshot(AuthorizationState.AuthDenied, null, responseCode);
                if (!response.IsSuccess && response.Decision is null)
                    return new AuthorizationSnapshot(AuthorizationState.ProtocolFailure, null, response.Problem?.Code ?? "Unsigned Nightflyer request failure.");
                return SnapshotForResponse(response, freshAuthorization);
            }
            catch (NightflyerException exception) when (exception.Failure == NightflyerFailure.Transport)
            {
                ScheduleRetry(null);
                return RetryableFailureSnapshot("Network request failed; the signed lease is unchanged.");
            }
        }

        private void Accept(NightflyerResponse response, bool freshAuthorization = false)
        {
            if (response.KeysetSequence < _state.KeysetSequence)
                throw new NightflyerException(NightflyerFailure.InvalidState, "Server keyset sequence moved backwards; local state may have been rolled back.");
            if (response.VerifiedStatus is { } status && status.Sequence < _state.StatusSequence)
                throw new NightflyerException(NightflyerFailure.InvalidState, "Server status sequence moved backwards; local state may have been rolled back.");
            if (!freshAuthorization && response.Lease is { } lease && lease.Generation < _state.HighestGeneration)
                throw new NightflyerException(NightflyerFailure.InvalidState, "Lease generation moved backwards.");

            if (response.DecisionCode == "STALE_GENERATION")
            {
                ReloadSharedState();
                return;
            }

            var acceptedTransitions = _state.KeyTransitions.Concat(response.KeyTransitions).ToList();
            try
            {
                // ProcessResponse already authenticated the new transitions. Replay
                // the complete persisted history as a second invariant so a status
                // cannot advance the saved keyset high-water mark without carrying
                // the derivation material needed after restart.
                _client.RestoreTrustedSigningKeyTransitions(acceptedTransitions, response.KeysetSequence);
            }
            catch
            {
                _client.RestoreTrustedSigningKeyTransitions(_state.KeyTransitions, _state.KeysetSequence);
                throw;
            }
            _state.KeyTransitions = acceptedTransitions;
            _state.KeysetSequence = response.KeysetSequence;

            if (response.Lease is not null)
            {
                if (freshAuthorization)
                {
                    // A signed /authorize lease starts a new lease epoch. Terminal
                    // state and generation high-water marks from the old epoch must
                    // not poison a legitimate reactivation of this installation.
                    _state.Ending = false;
                    _state.Ended = false;
                    _state.Revoked = false;
                    _state.ServerDeclaredExpired = false;
                    _state.PendingEnd = null;
                    _state.Status = null;
                    _state.StatusCompact = null;
                    _state.HighestGeneration = response.Lease.Generation;
                    _state.MinimumGeneration = 0;
                    _state.AuthorizationId = response.Lease.AuthorizationId;
                }
                _state.Lease = response.Lease;
                _state.LeaseCompact = response.Lease.Compact;
                _state.HighestGeneration = Math.Max(_state.HighestGeneration, response.Lease.Generation);
                _state.ServerDeclaredExpired = false;
            }

            if (response.VerifiedStatus is not null)
            {
                _state.Status = response.VerifiedStatus;
                _state.StatusCompact = response.VerifiedStatus.Compact;
                _state.StatusSequence = response.VerifiedStatus.Sequence;
                _state.MinimumGeneration = response.VerifiedStatus.MinimumGeneration;
                ApplyStatus(response.VerifiedStatus);
            }

            if (response.Decision is not null) ApplyDecision(response.Decision);

            if (response.SignedServerTime is { } serverTime)
            {
                var wall = _config.Clock.UtcNow;
                // A verified, request-bound response repairs local clock mistakes.
                // Never retain a wall-clock-derived future checkpoint over it.
                _state.ClockUntrusted = false;
                _state.ServerAnchorUnix = serverTime.ToUnixTimeSeconds();
                _state.AnchorMonotonicMilliseconds = _config.Clock.MonotonicMilliseconds;
                _state.BootIdentifier = _config.Clock.BootIdentifier;
                _state.WallAtAnchorUnix = wall.ToUnixTimeSeconds();
                _state.LastKnownGoodUnix = serverTime.ToUnixTimeSeconds();
            }

            _state.RetryFailures = 0;
            _state.NextRetryUnix = 0;
            Persist();
        }

        private void ApplyStatus(NightflyerStatus status)
        {
            if (_state.Lease is null) return;
            if (status.DeviceStatus == "revoked"
                || status.GrantStatus == "revoked"
                || status.MinimumGeneration > _state.Lease.Generation
                || status.RevokedSigningKeyIds.Contains(_state.Lease.SigningKeyId, StringComparer.Ordinal))
            {
                _state.Revoked = true;
                _state.Ended = false;
                _state.Lease = null;
                _state.LeaseCompact = null;
                _state.PendingEnd = null;
                _state.Ending = false;
            }
            else if (status.GrantStatus == "ended")
            {
                _state.Ended = true;
                _state.Revoked = false;
                _state.Lease = null;
                _state.LeaseCompact = null;
                _state.PendingEnd = null;
                _state.Ending = false;
            }
            else if (status.GrantStatus == "reclaim_pending")
            {
                // Keep the verified compact lease only as /status and /end retry material.
                _state.ServerDeclaredExpired = true;
            }
        }

        private void ApplyDecision(NightflyerDecision decision)
        {
            switch (decision.LeaseDisposition)
            {
                case "revoked":
                    _state.Revoked = true;
                    _state.Ended = false;
                    _state.Lease = null;
                    _state.LeaseCompact = null;
                    _state.PendingEnd = null;
                    _state.Ending = false;
                    break;
                case "ended":
                    _state.Ended = true;
                    _state.Revoked = false;
                    _state.Lease = null;
                    _state.LeaseCompact = null;
                    _state.PendingEnd = null;
                    _state.Ending = false;
                    break;
                case "expired":
                    _state.ServerDeclaredExpired = true;
                    break;
            }
        }

        private AuthorizationSnapshot SnapshotForResponse(NightflyerResponse response, bool freshAuthorization = false)
        {
            var code = response.DecisionCode;
            if (code is null) return EvaluateLocalState(online: true);
            if (code == "LEASE_REVOKED") return new AuthorizationSnapshot(AuthorizationState.Inactive, null, code);
            if (code == "LEASE_ENDED") return new AuthorizationSnapshot(AuthorizationState.Ended, null, code);
            if (code == "PROTOCOL_UPGRADE_REQUIRED") return new AuthorizationSnapshot(AuthorizationState.ProtocolUpgradeRequired, UsableLease(), code);
            if (code is "AUTH_MODE_IN_USE" or "LEASE_ALREADY_ACTIVE") return new AuthorizationSnapshot(AuthorizationState.AuthModeInUse, UsableLease(), code);
            if (code == "DEVICE_BINDING_MISMATCH") return new AuthorizationSnapshot(AuthorizationState.DeviceChanged, null, code);
            if (code == "STALE_GENERATION") return EvaluateLocalState(code);
            if (code == "LEASE_RECLAIM_PENDING" || response.Decision?.LeaseDisposition == "expired") return new AuthorizationSnapshot(AuthorizationState.Expired, null, code);
            if (response.IsSuccess) return EvaluateLocalState(code, online: true);
            if (freshAuthorization) return new AuthorizationSnapshot(AuthorizationState.AuthDenied, UsableLease(), code);
            if (_state.Revoked) return new AuthorizationSnapshot(AuthorizationState.Inactive, null, code);
            if (_state.Ended) return new AuthorizationSnapshot(AuthorizationState.Ended, null, code);
            return new AuthorizationSnapshot(AuthorizationState.AuthDenied, UsableLease(), code);
        }

        private AuthorizationSnapshot RetryableFailureSnapshot(string diagnostic)
        {
            var lease = UsableLease();
            return lease is not null
                ? new AuthorizationSnapshot(AuthorizationState.NetworkUnavailable, lease, diagnostic)
                : new AuthorizationSnapshot(AuthorizationState.NetworkUnavailable, null, diagnostic);
        }

        private AuthorizationSnapshot EvaluateLocalState(string? diagnostic = null, bool online = false)
        {
            if (_state.Ending) return new AuthorizationSnapshot(AuthorizationState.Ending, null, diagnostic);
            if (_state.Revoked) return new AuthorizationSnapshot(AuthorizationState.Inactive, null, diagnostic);
            if (_state.Ended) return new AuthorizationSnapshot(AuthorizationState.Ended, null, diagnostic);
            if (_state.Lease is null) return new AuthorizationSnapshot(AuthorizationState.AuthDenied, null, diagnostic);
            if (ClockIsUntrusted()) return new AuthorizationSnapshot(AuthorizationState.ClockUntrusted, null, diagnostic ?? "The protected time checkpoint cannot be trusted until an online check succeeds.");
            if (_state.ServerDeclaredExpired || EffectiveNow() >= _state.Lease.ExpiresAt)
                return new AuthorizationSnapshot(AuthorizationState.Expired, null, diagnostic);
            if (EffectiveNow() >= _state.Lease.RenewAfter)
                return new AuthorizationSnapshot(AuthorizationState.RenewalDue, _state.Lease, diagnostic);
            return new AuthorizationSnapshot(online ? AuthorizationState.AuthorizedOnline : AuthorizationState.AuthorizedOffline, _state.Lease, diagnostic);
        }

        private Lease? UsableLease()
        {
            if (_state.Ending || _state.Ended || _state.Revoked || _state.Lease is null || ClockIsUntrusted() || _state.ServerDeclaredExpired)
                return null;
            return EffectiveNow() < _state.Lease.ExpiresAt ? _state.Lease : null;
        }

        private bool ClockIsUntrusted()
        {
            if (_state.ClockUntrusted) return true;
            if (TryAnchoredTime(out var anchored))
                return anchored + 5 < _state.LastKnownGoodUnix;
            // A counter reset within the same boot is not a wall-clock correction.
            if (_state.ServerAnchorUnix > 0 && _state.BootIdentifier == _config.Clock.BootIdentifier) return true;
            if (!_persistent) return false;
            if (_config.Clock.UtcNow.ToUnixTimeSeconds() + 5 < _state.LastKnownGoodUnix) return true;
            if (_config.RequireOnlineAfterReboot && _state.ServerAnchorUnix > 0 && _state.BootIdentifier != _config.Clock.BootIdentifier) return true;
            return false;
        }

        private DateTimeOffset EffectiveNow()
        {
            // Within a boot, only suspend-inclusive elapsed time advances the signed
            // anchor. UTC corrections cannot shorten or extend the offline lease.
            var effectiveUnix = Math.Max(_state.LastKnownGoodUnix,
                TryAnchoredTime(out var anchored) ? anchored : _config.Clock.UtcNow.ToUnixTimeSeconds());
            return DateTimeOffset.FromUnixTimeSeconds(effectiveUnix);
        }

        private bool TryAnchoredTime(out long unixSeconds)
        {
            unixSeconds = 0;
            if (_state.ServerAnchorUnix <= 0 || _state.BootIdentifier != _config.Clock.BootIdentifier) return false;
            var monotonic = _config.Clock.MonotonicMilliseconds;
            if (monotonic < _state.AnchorMonotonicMilliseconds) return false;
            var elapsed = (monotonic - _state.AnchorMonotonicMilliseconds) / 1000;
            // Saturating at the supported time limit expires every lease without
            // throwing if a custom clock supplies an extremely large counter.
            unixSeconds = _state.ServerAnchorUnix + Math.Min(elapsed, 253_402_300_799 - _state.ServerAnchorUnix);
            return true;
        }

        private void ScheduleRetry(TimeSpan? retryAfter)
        {
            _state.RetryFailures = Math.Min(_state.RetryFailures + 1, 30);
            var now = _config.Clock.UtcNow.ToUnixTimeSeconds();
            var generalCeiling = 600;
            var leaseCeiling = _state.Lease is null
                ? generalCeiling
                : Math.Max(0, (int)Math.Min(generalCeiling, (_state.Lease.ExpiresAt.ToUnixTimeSeconds() - now) / 3));
            var exponential = Math.Min(leaseCeiling, 30 * (1 << Math.Min(_state.RetryFailures - 1, 4)));
            var delay = retryAfter is null
                ? CryptoHelpers.RandomInt32(Math.Max(1, exponential + 1))
                : Math.Max(0, (int)Math.Ceiling(retryAfter.Value.TotalSeconds));
            if (_state.Lease is not null)
                delay = Math.Min(delay, Math.Max(0, (int)(_state.Lease.ExpiresAt.ToUnixTimeSeconds() - now)));
            _state.NextRetryUnix = checked(now + delay);
            Persist();
        }

        private EasyAuthorizationResult DescribeEasyAuthorization(AuthorizationSnapshot snapshot)
        {
            var credentialPresent = false;
            TimeSpan? retryAfter = null;

            // Re-read shared state after the network workflow so guidance reflects
            // a credential deletion or retry schedule committed by another process.
            try
            {
                if (TryEnter(CancellationToken.None))
                {
                    try
                    {
                        credentialPresent = !string.IsNullOrEmpty(_state.StoredLicenseKey);
                        var remaining = _state.NextRetryUnix - _config.Clock.UtcNow.ToUnixTimeSeconds();
                        if (remaining > 0) retryAfter = TimeSpan.FromSeconds(remaining);
                    }
                    finally { Exit(); }
                }
            }
            catch (NightflyerException exception)
            {
                snapshot = new AuthorizationSnapshot(AuthorizationState.StorageUnavailable, null, exception.Message);
            }

            var canProceed = snapshot.Lease is not null;
            var recommendedAction = snapshot.State switch
            {
                AuthorizationState.AuthorizedOnline => EasyAuthorizationAction.None,
                AuthorizationState.AuthorizedOffline => EasyAuthorizationAction.ContinueOffline,
                AuthorizationState.RenewalDue or AuthorizationState.NetworkUnavailable or AuthorizationState.Ending =>
                    EasyAuthorizationAction.RetryOnline,
                AuthorizationState.Inactive or AuthorizationState.Ended or AuthorizationState.Expired or AuthorizationState.AuthDenied =>
                    EasyAuthorizationAction.RequestLicenseKey,
                AuthorizationState.ProtocolUpgradeRequired => EasyAuthorizationAction.UpdateClient,
                AuthorizationState.ClockUntrusted => EasyAuthorizationAction.CheckClock,
                AuthorizationState.StorageUnavailable => EasyAuthorizationAction.RepairProtectedStorage,
                AuthorizationState.DeviceChanged => EasyAuthorizationAction.ResolveDeviceBinding,
                AuthorizationState.AuthModeInUse => EasyAuthorizationAction.ResolveAuthenticationMode,
                AuthorizationState.InstallationInUse => EasyAuthorizationAction.WaitForInstallation,
                _ => EasyAuthorizationAction.ContactDeveloper,
            };

            return new EasyAuthorizationResult(
                snapshot,
                canProceed,
                canProceed && snapshot.State != AuthorizationState.AuthorizedOnline,
                credentialPresent,
                recommendedAction == EasyAuthorizationAction.RequestLicenseKey,
                recommendedAction,
                retryAfter);
        }

        private Task<AuthorizationSnapshot> RunLockedAsync(
            Func<Task<AuthorizationSnapshot>> operation,
            CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            return Task.Run(() =>
            {
                if (!TryEnter(cancellationToken))
                    return new AuthorizationSnapshot(AuthorizationState.InstallationInUse, null, "Another process is updating this installation.");
                try { return operation().GetAwaiter().GetResult(); }
                finally { Exit(); }
            }, cancellationToken);
        }

        private bool TryEnter(CancellationToken cancellationToken)
        {
            _gate.Wait(cancellationToken);
            var acquired = false;
            try
            {
                if (_persistent)
                {
                    acquired = WaitForMutex(_installationMutex, _config.InstallationLockTimeout, cancellationToken);
                    if (!acquired) { _gate.Release(); return false; }
                    ReloadSharedState();
                }
                return true;
            }
            catch
            {
                if (acquired) _installationMutex.ReleaseMutex();
                _gate.Release();
                throw;
            }
        }

        private void Exit()
        {
            if (_persistent) _installationMutex.ReleaseMutex();
            _gate.Release();
        }

        private void ReloadSharedState()
        {
            if (!_persistent) return;
            var bytes = AccessProtectedStorage(_store!.Load) ?? throw new NightflyerException(NightflyerFailure.InvalidState, "Shared Nightflyer state disappeared.");
            try
            {
                var reloaded = DeserializeState(bytes);
                var migratedLegacyState = reloaded.Version == LegacyStateVersion;
                reloaded = UpgradeLegacyState(_config, reloaded);
                ValidateLoadedState(_config, reloaded, requireSignature: !migratedLegacyState);
                if (!FixedAsciiEquals(reloaded.InstallationThumbprint, _key.Thumbprint)
                    || !FixedAsciiEquals(reloaded.InstallationKeyReference, _state.InstallationKeyReference))
                    throw new NightflyerException(NightflyerFailure.InvalidState, "Shared state belongs to another installation key.");
                if (!migratedLegacyState) VerifyStateSignature(reloaded, _key);

                try
                {
                    _client.RestoreTrustedSigningKeyTransitions(reloaded.KeyTransitions, reloaded.KeysetSequence);
                    VerifyRuntimeState(reloaded, _client);
                    _state = reloaded;
                }
                catch
                {
                    _client.RestoreTrustedSigningKeyTransitions(_state.KeyTransitions, _state.KeysetSequence);
                    throw;
                }
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }

        private void VerifyRuntimeState(PersistedState state, NightflyerClient verifier)
        {
            state.Lease = state.LeaseCompact is null ? null : verifier.VerifyCachedLease(state.LeaseCompact);
            state.Status = state.StatusCompact is null ? null : verifier.VerifyCachedStatus(state.StatusCompact, state.Lease);
            if (state.Lease is not null)
            {
                if (state.Lease.Generation != state.HighestGeneration || state.Lease.Generation < state.MinimumGeneration)
                    throw new NightflyerException(NightflyerFailure.InvalidState, "Persistent lease generation conflicts with its saved high-water marks.");
                if (!FixedAsciiEquals(state.Lease.AuthorizationId, state.AuthorizationId))
                    throw new NightflyerException(NightflyerFailure.InvalidState, "Persistent lease belongs to another authorization epoch.");
                if (state.Status is not null
                    && (state.Status.AuthorizationId != state.Lease.AuthorizationId || state.Status.DeviceId != state.Lease.DeviceId))
                    throw new NightflyerException(NightflyerFailure.InvalidState, "Persistent status belongs to another lease.");
            }
            if (state.Status is not null
                && (state.Status.Sequence != state.StatusSequence
                    || state.Status.KeysetSequence > state.KeysetSequence
                    || state.Status.MinimumGeneration != state.MinimumGeneration))
                throw new NightflyerException(NightflyerFailure.InvalidState, "Persistent status conflicts with its saved high-water marks.");
            if (state.Ending && (state.PendingEnd is null || state.Lease is null))
                throw new NightflyerException(NightflyerFailure.InvalidState, "Persistent end tombstone lacks exact retry material.");
        }

        private void Persist()
        {
            if (!_persistent) return;
            _state.LastKnownGoodUnix = Math.Max(_state.LastKnownGoodUnix, EffectiveNow().ToUnixTimeSeconds());
            var unsigned = SerializeUnsignedState(_state);
            try
            {
                var signature = _key.Sign(unsigned);
                try
                {
                    if (signature.Length != 64)
                        throw new NightflyerException(NightflyerFailure.LocalFailure, "The installation key returned an invalid P-256 state signature.");
                    _state.StateSignature = Base64Url.Encode(signature);
                }
                finally { CryptographicOperations.ZeroMemory(signature); }
            }
            finally { CryptographicOperations.ZeroMemory(unsigned); }
            var bytes = SerializeState(_state);
            try { AccessProtectedStorage(() => _store!.Save(bytes)); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }

        private static byte[] SerializeUnsignedState(PersistedState state)
        {
            var signature = state.StateSignature;
            state.StateSignature = null;
            try { return SerializeState(state); }
            finally { state.StateSignature = signature; }
        }

        // The persisted record is a flat, versioned JSON object written in this
        // exact member order. The state signature covers exactly these bytes with
        // StateSignature omitted, so the order must stay stable across releases.
        private static byte[] SerializeState(PersistedState state)
        {
            var members = new List<KeyValuePair<string, object?>>
            {
                new("Version", state.Version),
                new("SystemId", state.SystemId),
                new("InstallationThumbprint", state.InstallationThumbprint),
                new("InstallationKeyReference", state.InstallationKeyReference),
                new("AuthorizationId", state.AuthorizationId),
                new("StoredLicenseKey", state.StoredLicenseKey),
                new("KeyTransitions", state.KeyTransitions),
            };
            if (state.StateSignature is not null) members.Add(new("StateSignature", state.StateSignature));
            if (state.LegacyTrustedSigningKeys is not null) members.Add(new("TrustedSigningKeys", state.LegacyTrustedSigningKeys));
            members.Add(new KeyValuePair<string, object?>("LeaseCompact", state.LeaseCompact));
            members.Add(new KeyValuePair<string, object?>("StatusCompact", state.StatusCompact));
            members.Add(new KeyValuePair<string, object?>("StatusSequence", state.StatusSequence));
            members.Add(new KeyValuePair<string, object?>("KeysetSequence", state.KeysetSequence));
            members.Add(new KeyValuePair<string, object?>("HighestGeneration", state.HighestGeneration));
            members.Add(new KeyValuePair<string, object?>("MinimumGeneration", state.MinimumGeneration));
            members.Add(new KeyValuePair<string, object?>("LastKnownGoodUnix", state.LastKnownGoodUnix));
            members.Add(new KeyValuePair<string, object?>("ServerAnchorUnix", state.ServerAnchorUnix));
            members.Add(new KeyValuePair<string, object?>("WallAtAnchorUnix", state.WallAtAnchorUnix));
            members.Add(new KeyValuePair<string, object?>("AnchorMonotonicMilliseconds", state.AnchorMonotonicMilliseconds));
            members.Add(new KeyValuePair<string, object?>("BootIdentifier", state.BootIdentifier));
            members.Add(new KeyValuePair<string, object?>("NextRetryUnix", state.NextRetryUnix));
            members.Add(new KeyValuePair<string, object?>("RetryFailures", state.RetryFailures));
            members.Add(new KeyValuePair<string, object?>("Ending", state.Ending));
            members.Add(new KeyValuePair<string, object?>("Ended", state.Ended));
            members.Add(new KeyValuePair<string, object?>("Revoked", state.Revoked));
            members.Add(new KeyValuePair<string, object?>("ClockUntrusted", state.ClockUntrusted));
            members.Add(new KeyValuePair<string, object?>("ServerDeclaredExpired", state.ServerDeclaredExpired));
            members.Add(new KeyValuePair<string, object?>("PendingEnd", SerializePendingEnd(state.PendingEnd)));
            return NightflyerJsonWriter.SerializeToUtf8(members);
        }

        private static IReadOnlyList<KeyValuePair<string, object?>>? SerializePendingEnd(PreparedNightflyerRequest? pendingEnd)
        {
            if (pendingEnd is null) return null;
            return new List<KeyValuePair<string, object?>>
            {
                new("Endpoint", pendingEnd.Endpoint),
                new("RequestUrl", pendingEnd.RequestUrl),
                new("Body", pendingEnd.Body),
                new("Proof", pendingEnd.Proof),
                new("RequestJti", pendingEnd.RequestJti),
                new("PresentedLease", pendingEnd.PresentedLease),
                new("ExpectedHwid", pendingEnd.ExpectedHwid),
                new("KeysetSequence", pendingEnd.KeysetSequence),
                new("StatusSequence", pendingEnd.StatusSequence),
            };
        }

        private static PreparedNightflyerRequest? DeserializePendingEnd(NightflyerJsonNode value)
        {
            if (value.Kind == NightflyerJsonValueKind.Null) return null;
            if (value.Kind != NightflyerJsonValueKind.Object) throw new NightflyerJsonException("PendingEnd is invalid.");
            RequireStateMemberSet(value, new[]
            {
                "Endpoint", "RequestUrl", "Body", "Proof", "RequestJti",
                "PresentedLease", "ExpectedHwid", "KeysetSequence", "StatusSequence",
            }, "PendingEnd");
            return new PreparedNightflyerRequest(
                StateText(value, "Endpoint"),
                StateText(value, "RequestUrl"),
                StateText(value, "Body"),
                StateText(value, "Proof"),
                StateText(value, "RequestJti"),
                StateOptionalText(value, "PresentedLease"),
                StateOptionalText(value, "ExpectedHwid"),
                StateInteger(value, "KeysetSequence"),
                StateInteger(value, "StatusSequence"));
        }

        private static void VerifyStateSignature(PersistedState state, IInstallationKey key)
        {
            try
            {
                var signature = Base64Url.Decode(state.StateSignature!, 64);
                var unsigned = SerializeUnsignedState(state);
                try
                {
                    var jwk = NightflyerJsonNode.Parse(Encoding.UTF8.GetBytes(key.PublicJwk));
                    if (jwk.Kind != NightflyerJsonValueKind.Object
                        || jwk.TryGetProperty("kty", out var kty) is false || kty.StringValue != "EC"
                        || jwk.TryGetProperty("crv", out var crv) is false || crv.StringValue != "P-256")
                        throw new CryptographicException("Installation key is not P-256.");
                    var parameters = new ECParameters
                    {
                        Curve = ECCurve.NamedCurves.nistP256,
                        Q = new ECPoint
                        {
                            X = Base64Url.Decode(jwk.GetProperty("x").StringValue!, 32),
                            Y = Base64Url.Decode(jwk.GetProperty("y").StringValue!, 32),
                        },
                    };
                    using var verifier = ECDsa.Create(parameters);
                    if (!EcdsaInstallationKey.VerifyP1363(verifier, unsigned, signature))
                        throw new NightflyerException(NightflyerFailure.InvalidState, "Persistent Nightflyer state signature is invalid.");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(unsigned);
                    CryptographicOperations.ZeroMemory(signature);
                }
            }
            catch (NightflyerException exception) when (exception.Failure != NightflyerFailure.InvalidState)
            {
                throw new NightflyerException(NightflyerFailure.InvalidState, "Persistent Nightflyer state signature is invalid.");
            }
            catch (Exception exception) when (exception is CryptographicException or NightflyerJsonException or KeyNotFoundException or InvalidOperationException or FormatException)
            {
                throw new NightflyerException(NightflyerFailure.InvalidState, "Persistent Nightflyer state signature is invalid.");
            }
        }

        private static T AccessProtectedStorage<T>(Func<T> operation)
        {
            try { return operation(); }
            // Normalize only failures from the storage boundary. Cancellation,
            // programming errors, and existing SDK failures keep their meaning;
            // a disk or key-store failure must never be treated as missing state.
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException
                or System.Security.SecurityException or CryptographicException)
            {
                throw new NightflyerException(NightflyerFailure.LocalFailure,
                    "Protected Nightflyer storage is unavailable. Check file permissions, available disk space, and access to your operating-system key store, then retry.");
            }
        }

        private static void AccessProtectedStorage(Action operation) =>
            AccessProtectedStorage(() => { operation(); return 0; });

        private static PersistedState DeserializeState(byte[] bytes)
        {
            if (bytes.Length is 0 or > 1_048_576)
                throw new NightflyerException(NightflyerFailure.InvalidState, "Persistent Nightflyer state has an invalid size.");
            NightflyerJsonNode root;
            try
            {
                root = NightflyerJsonNode.Parse(bytes);
            }
            catch (NightflyerJsonException)
            {
                throw new NightflyerException(NightflyerFailure.InvalidState, "Persistent Nightflyer state is corrupt.");
            }
            if (root.Kind != NightflyerJsonValueKind.Object)
                throw new NightflyerException(NightflyerFailure.InvalidState, "Persistent Nightflyer state is corrupt.");
            try
            {
                return ReadState(root);
            }
            catch (NightflyerJsonException)
            {
                throw new NightflyerException(NightflyerFailure.InvalidState, "Persistent Nightflyer state is corrupt.");
            }
        }

        private static void RequireStateMemberSet(NightflyerJsonNode value, IReadOnlyList<string> members, string name)
        {
            if (value.Kind != NightflyerJsonValueKind.Object) throw new NightflyerJsonException($"{name} is invalid.");
            var actual = new HashSet<string>(value.Properties.Select(property => property.Name), StringComparer.Ordinal);
            foreach (var member in members)
            {
                if (!actual.Remove(member)) throw new NightflyerJsonException($"{name} is missing a member.");
            }
            if (actual.Count != 0) throw new NightflyerJsonException($"{name} has an unexpected member.");
        }

        private static string StateText(NightflyerJsonNode value, string name)
        {
            if (!value.TryGetProperty(name, out var property) || property.Kind != NightflyerJsonValueKind.String)
                throw new NightflyerJsonException($"{name} must be a string.");
            return property.StringValue!;
        }

        private static string? StateOptionalText(NightflyerJsonNode value, string name)
        {
            if (!value.TryGetProperty(name, out var property)) return null;
            if (property.Kind == NightflyerJsonValueKind.Null) return null;
            if (property.Kind != NightflyerJsonValueKind.String) throw new NightflyerJsonException($"{name} must be a string or null.");
            return property.StringValue;
        }

        private static long StateInteger(NightflyerJsonNode value, string name)
        {
            if (!value.TryGetProperty(name, out var property) || property.Kind != NightflyerJsonValueKind.Number || !property.TryGetInt64(out var result))
                throw new NightflyerJsonException($"{name} must be an integer.");
            return result;
        }

        private static bool StateBoolean(NightflyerJsonNode value, string name)
        {
            if (!value.TryGetProperty(name, out var property) || property.Kind is not (NightflyerJsonValueKind.True or NightflyerJsonValueKind.False))
                throw new NightflyerJsonException($"{name} must be a boolean.");
            return property.BoolValue!.Value;
        }

        private static List<string> StateStringArray(NightflyerJsonNode value, string name)
        {
            if (!value.TryGetProperty(name, out var property) || property.Kind != NightflyerJsonValueKind.Array)
                throw new NightflyerJsonException($"{name} must be an array.");
            var result = new List<string>(property.Items.Count);
            foreach (var item in property.Items)
            {
                if (item.Kind != NightflyerJsonValueKind.String) throw new NightflyerJsonException($"{name} must contain strings.");
                result.Add(item.StringValue!);
            }
            return result;
        }

        private static PersistedState ReadState(NightflyerJsonNode root)
        {
            var state = new PersistedState();
            foreach (var property in root.Properties)
            {
                switch (property.Name)
                {
                    case "Version": state.Version = checked((int)StateInteger(root, "Version")); break;
                    case "SystemId": state.SystemId = StateText(root, "SystemId"); break;
                    case "InstallationThumbprint": state.InstallationThumbprint = StateText(root, "InstallationThumbprint"); break;
                    case "InstallationKeyReference": state.InstallationKeyReference = StateText(root, "InstallationKeyReference"); break;
                    case "AuthorizationId": state.AuthorizationId = StateText(root, "AuthorizationId"); break;
                    case "StoredLicenseKey": state.StoredLicenseKey = StateOptionalText(root, "StoredLicenseKey"); break;
                    case "KeyTransitions": state.KeyTransitions = StateStringArray(root, "KeyTransitions"); break;
                    case "StateSignature": state.StateSignature = StateOptionalText(root, "StateSignature"); break;
                    case "TrustedSigningKeys":
                        if (property.Value.Kind != NightflyerJsonValueKind.Object) throw new NightflyerJsonException("TrustedSigningKeys must be an object.");
                        var legacy = new Dictionary<string, string>(StringComparer.Ordinal);
                        foreach (var pair in property.Value.Properties)
                        {
                            if (pair.Value.Kind != NightflyerJsonValueKind.String) throw new NightflyerJsonException("TrustedSigningKeys must map to strings.");
                            legacy[pair.Name] = pair.Value.StringValue!;
                        }
                        state.LegacyTrustedSigningKeys = legacy;
                        break;
                    case "LeaseCompact": state.LeaseCompact = StateOptionalText(root, "LeaseCompact"); break;
                    case "StatusCompact": state.StatusCompact = StateOptionalText(root, "StatusCompact"); break;
                    case "StatusSequence": state.StatusSequence = StateInteger(root, "StatusSequence"); break;
                    case "KeysetSequence": state.KeysetSequence = StateInteger(root, "KeysetSequence"); break;
                    case "HighestGeneration": state.HighestGeneration = StateInteger(root, "HighestGeneration"); break;
                    case "MinimumGeneration": state.MinimumGeneration = StateInteger(root, "MinimumGeneration"); break;
                    case "LastKnownGoodUnix": state.LastKnownGoodUnix = StateInteger(root, "LastKnownGoodUnix"); break;
                    case "ServerAnchorUnix": state.ServerAnchorUnix = StateInteger(root, "ServerAnchorUnix"); break;
                    case "WallAtAnchorUnix": state.WallAtAnchorUnix = StateInteger(root, "WallAtAnchorUnix"); break;
                    case "AnchorMonotonicMilliseconds": state.AnchorMonotonicMilliseconds = StateInteger(root, "AnchorMonotonicMilliseconds"); break;
                    case "BootIdentifier": state.BootIdentifier = StateText(root, "BootIdentifier"); break;
                    case "NextRetryUnix": state.NextRetryUnix = StateInteger(root, "NextRetryUnix"); break;
                    case "RetryFailures": state.RetryFailures = checked((int)StateInteger(root, "RetryFailures")); break;
                    case "Ending": state.Ending = StateBoolean(root, "Ending"); break;
                    case "Ended": state.Ended = StateBoolean(root, "Ended"); break;
                    case "Revoked": state.Revoked = StateBoolean(root, "Revoked"); break;
                    case "ClockUntrusted": state.ClockUntrusted = StateBoolean(root, "ClockUntrusted"); break;
                    case "ServerDeclaredExpired": state.ServerDeclaredExpired = StateBoolean(root, "ServerDeclaredExpired"); break;
                    case "PendingEnd": state.PendingEnd = DeserializePendingEnd(property.Value); break;
                    default: throw new NightflyerJsonException($"Unknown state member '{property.Name}'.");
                }
            }
            return state;
        }

        private static PersistedState NewState(NightflyerConfig config, IInstallationKey key, string reference)
        {
            var now = config.Clock.UtcNow.ToUnixTimeSeconds();
            return new PersistedState
            {
                Version = StateVersion,
                SystemId = config.SystemId,
                InstallationThumbprint = key.Thumbprint,
                InstallationKeyReference = reference,
                LastKnownGoodUnix = now,
                WallAtAnchorUnix = now,
                AnchorMonotonicMilliseconds = config.Clock.MonotonicMilliseconds,
                BootIdentifier = config.Clock.BootIdentifier,
            };
        }

        private static NightflyerConfig CreateClientConfig(NightflyerConfig config, IReadOnlyDictionary<string, string> keys) => new(config.SystemId, keys)
        {
            BaseUrl = config.BaseUrl,
            ExpectedIssuer = config.ExpectedIssuer,
            SdkVersion = config.SdkVersion,
            RequestTimeout = config.RequestTimeout,
            IdempotentTransportRetries = config.IdempotentTransportRetries,
            InstallationLockTimeout = config.InstallationLockTimeout,
            RequireOnlineAfterReboot = config.RequireOnlineAfterReboot,
            Clock = config.Clock,
        };

        private static PersistedState UpgradeLegacyState(NightflyerConfig config, PersistedState state)
        {
            if (state.Version != LegacyStateVersion) return state;
            if (state.LegacyTrustedSigningKeys is null || state.LegacyTrustedSigningKeys.Count == 0)
                throw new NightflyerException(NightflyerFailure.InvalidState, "Legacy persistent state does not contain its original trust roots.");
            foreach (var pair in config.TrustedSigningKeys)
            {
                if (!state.LegacyTrustedSigningKeys.TryGetValue(pair.Key, out var saved) || !FixedAsciiEquals(pair.Value, saved))
                    throw new NightflyerException(NightflyerFailure.InvalidState, "Legacy persistent state no longer contains the application's pinned trust root.");
            }

            // Version 3 saved only the expanded key ring, so transitioned keys have
            // no authenticated provenance to replay. Preserve the installation and
            // retained credential, but deliberately require fresh online authority.
            var now = config.Clock.UtcNow.ToUnixTimeSeconds();
            state.Version = StateVersion;
            state.LegacyTrustedSigningKeys = null;
            state.KeyTransitions = new List<string>();
            state.AuthorizationId = "";
            state.LeaseCompact = null;
            state.StatusCompact = null;
            state.Lease = null;
            state.Status = null;
            state.StatusSequence = 0;
            state.KeysetSequence = 0;
            state.HighestGeneration = 0;
            state.MinimumGeneration = 0;
            state.LastKnownGoodUnix = now;
            state.ServerAnchorUnix = 0;
            state.WallAtAnchorUnix = now;
            state.AnchorMonotonicMilliseconds = Math.Max(0, config.Clock.MonotonicMilliseconds);
            state.BootIdentifier = config.Clock.BootIdentifier;
            state.NextRetryUnix = 0;
            state.RetryFailures = 0;
            state.Ending = false;
            state.Ended = false;
            state.Revoked = false;
            state.ClockUntrusted = false;
            state.ServerDeclaredExpired = false;
            state.PendingEnd = null;
            return state;
        }

        private static void ValidateLoadedState(NightflyerConfig config, PersistedState state, bool requireSignature = true)
        {
            if (state.Version != StateVersion
                || state.SystemId != config.SystemId
                || string.IsNullOrWhiteSpace(state.InstallationKeyReference)
                || string.IsNullOrWhiteSpace(state.InstallationThumbprint)
                || state.LegacyTrustedSigningKeys is not null
                || state.KeyTransitions is null
                || state.KeyTransitions.Count > 1024
                || state.KeyTransitions.Any(value => string.IsNullOrWhiteSpace(value) || Encoding.UTF8.GetByteCount(value) > 65_536)
                || (requireSignature && string.IsNullOrWhiteSpace(state.StateSignature))
                || state.StatusSequence < 0
                || state.KeysetSequence < 0
                || state.HighestGeneration < 0
                || state.MinimumGeneration < 0
                || state.StatusSequence > 9_007_199_254_740_991
                || state.KeysetSequence > 9_007_199_254_740_991
                || state.HighestGeneration > 9_007_199_254_740_991
                || state.MinimumGeneration > 9_007_199_254_740_991
                || state.LastKnownGoodUnix is < 0 or > 253_402_300_799
                || state.ServerAnchorUnix is < 0 or > 253_402_300_799
                || state.WallAtAnchorUnix is < 0 or > 253_402_300_799
                || state.AnchorMonotonicMilliseconds < 0
                || state.RetryFailures < 0
                || state.RetryFailures > 30
                || state.NextRetryUnix is < 0 or > 253_402_300_799
                || (state.AuthorizationId.Length > 0 && state.AuthorizationId.Length > 256)
                || (state.StoredLicenseKey?.Length > 4096)
                || (state.Ended && state.Revoked))
                throw new NightflyerException(NightflyerFailure.InvalidState, "Persistent Nightflyer state is corrupt or belongs to another system.");
            Base64Url.Decode(state.InstallationThumbprint, 32);
            if (state.StateSignature is not null)
            {
                try { Base64Url.Decode(state.StateSignature, 64); }
                catch (NightflyerException) { throw new NightflyerException(NightflyerFailure.InvalidState, "Persistent Nightflyer state signature is invalid."); }
            }
        }

        private static bool WaitForMutex(Mutex mutex, TimeSpan timeout, CancellationToken cancellationToken)
        {
            var deadline = timeout == Timeout.InfiniteTimeSpan ? DateTimeOffset.MaxValue : DateTimeOffset.UtcNow + timeout;
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    if (mutex.WaitOne(0)) return true;
                }
                catch (AbandonedMutexException) { return true; }
                if (DateTimeOffset.UtcNow >= deadline) return false;
                Thread.Sleep(LockPollMilliseconds);
            }
        }

        private static string LockName(string purpose, string systemId, string identity)
        {
            var bytes = CryptoHelpers.Sha256Hash(Encoding.UTF8.GetBytes($"{purpose}:{systemId}:{identity}"));
            return $"SystemLocker.Nightflyer.{CryptoHelpers.ToHexUpper(bytes)}";
        }

        private static bool FixedAsciiEquals(string left, string right)
        {
            var leftBytes = Encoding.ASCII.GetBytes(left);
            var rightBytes = Encoding.ASCII.GetBytes(right);
            return leftBytes.Length == rightBytes.Length && CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
        }

        private void ThrowIfDisposed()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(NightflyerAuthorizationSession));
            if (_forgotten) throw new NightflyerException(NightflyerFailure.InvalidState, "This Nightflyer installation was forgotten and must be opened again.");
        }

        public void Dispose()
        {
            if (_disposed) return;
            if (!_persistent && !_forgotten && _state.Lease is not null && !_state.Ended && !_state.Revoked)
            {
                // Memory leases cannot be resumed after this process exits, so an
                // orderly disposal makes the protocol's best-effort /end attempt.
                // Prefer ShutdownAsync on threads that must not block.
                try { EndAsync("process_shutdown").GetAwaiter().GetResult(); }
                catch { }
            }
            _disposed = true;
            _memoryMutexLease?.Dispose();
            if (!_persistent) MemoryOwners.TryRemove(_installationLockName, out _);
            _client.Dispose();
            if (_ownsKey && _key is IDisposable disposable) disposable.Dispose();
            _installationMutex.Dispose();
            _gate.Dispose();
        }

        private sealed class LifetimeMutexLease : IDisposable
        {
            private readonly ManualResetEventSlim _release = new(false);
            private readonly Thread _thread;
            private readonly ManualResetEventSlim _ready = new(false);
            private Exception? _error;
            private bool _disposed;

            public LifetimeMutexLease(Mutex mutex, TimeSpan timeout)
            {
                _thread = new Thread(() =>
                {
                    try
                    {
                        if (!WaitForMutex(mutex, timeout, CancellationToken.None))
                            throw new NightflyerException(NightflyerFailure.InvalidState, "Another memory-only Nightflyer session owns this installation.");
                        _ready.Set();
                        _release.Wait();
                        mutex.ReleaseMutex();
                    }
                    catch (Exception exception)
                    {
                        _error = exception;
                        _ready.Set();
                    }
                })
                {
                    IsBackground = true,
                    Name = "System Locker Nightflyer memory lease",
                };
                _thread.Start();
                _ready.Wait();
                if (_error is not null) throw _error;
            }

            public void Dispose()
            {
                if (_disposed) return;
                _disposed = true;
                _release.Set();
                _thread.Join();
                _release.Dispose();
                _ready.Dispose();
            }
        }

        private sealed class PersistedState
        {
            public int Version { get; set; }
            public string SystemId { get; set; } = "";
            public string InstallationThumbprint { get; set; } = "";
            public string InstallationKeyReference { get; set; } = "";
            public string AuthorizationId { get; set; } = "";
            public string? StoredLicenseKey { get; set; }
            public List<string> KeyTransitions { get; set; } = new();
            public string? StateSignature { get; set; }
            public Dictionary<string, string>? LegacyTrustedSigningKeys { get; set; }
            public string? LeaseCompact { get; set; }
            public string? StatusCompact { get; set; }
            public long StatusSequence { get; set; }
            public long KeysetSequence { get; set; }
            public long HighestGeneration { get; set; }
            public long MinimumGeneration { get; set; }
            public long LastKnownGoodUnix { get; set; }
            public long ServerAnchorUnix { get; set; }
            public long WallAtAnchorUnix { get; set; }
            public long AnchorMonotonicMilliseconds { get; set; }
            public string BootIdentifier { get; set; } = "";
            public long NextRetryUnix { get; set; }
            public int RetryFailures { get; set; }
            public bool Ending { get; set; }
            public bool Ended { get; set; }
            public bool Revoked { get; set; }
            public bool ClockUntrusted { get; set; }
            public bool ServerDeclaredExpired { get; set; }
            public PreparedNightflyerRequest? PendingEnd { get; set; }

            public Lease? Lease { get; set; }
            public NightflyerStatus? Status { get; set; }
        }
    }
}
