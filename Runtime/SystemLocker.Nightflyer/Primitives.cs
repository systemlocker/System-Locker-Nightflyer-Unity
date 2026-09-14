using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace SystemLocker.Nightflyer
{
    public enum NightflyerFailure
    {
        Configuration,
        Transport,
        InvalidResponse,
        InvalidSignature,
        InvalidToken,
        InvalidState,
        LocalFailure,
    }

    public sealed class NightflyerException : Exception
    {
        public NightflyerException(NightflyerFailure failure, string message, int? httpStatus = null, TimeSpan? retryAfter = null)
            : base(message)
        {
            Failure = failure;
            HttpStatus = httpStatus;
            RetryAfter = retryAfter;
        }

        public NightflyerFailure Failure { get; }
        public int? HttpStatus { get; }
        public TimeSpan? RetryAfter { get; }
    }

    /// <summary>Injectable wall, suspend-inclusive monotonic, and boot-identity clock used by the authorization state machine.</summary>
    public interface INightflyerClock
    {
        DateTimeOffset UtcNow { get; }
        long MonotonicMilliseconds { get; }
        string BootIdentifier { get; }
    }

    public sealed class SystemNightflyerClock : INightflyerClock
    {
        public static SystemNightflyerClock Instance { get; } = new SystemNightflyerClock();

        private readonly Lazy<string> _bootIdentifier;

        private SystemNightflyerClock()
        {
            _bootIdentifier = new Lazy<string>(ReadBootIdentifier, LazyThreadSafetyMode.ExecutionAndPublication);
        }

        public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;

        public long MonotonicMilliseconds
        {
            get
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    if (clock_gettime(ClockBoottime, out var value) != 0)
                        throw new NightflyerException(NightflyerFailure.LocalFailure, "The suspend-inclusive system clock is unavailable.");
                    return checked(value.Seconds * 1000 + value.Nanoseconds / 1_000_000);
                }

                if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    var ticks = mach_continuous_time();
                    if (mach_timebase_info(out var timebase) == 0 && timebase.Denom != 0)
                    {
                        return checked((long)((ticks * (decimal)timebase.Numer / timebase.Denom) / 1_000_000m));
                    }
                    throw new NightflyerException(NightflyerFailure.LocalFailure, "The suspend-inclusive system clock is unavailable.");
                }

                // A clock that stops during sleep would extend an offline lease.
                // Never silently substitute a non-suspend-inclusive counter.
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return (long)GetTickCount64();
                throw new NightflyerException(NightflyerFailure.LocalFailure, "A suspend-inclusive clock adapter is required on this platform.");
            }
        }

        public string BootIdentifier => _bootIdentifier.Value;

        private string ReadBootIdentifier()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                try
                {
                    // SystemBootEnvironmentInformation provides a boot GUID that
                    // is independent of UTC corrections. The interface has existed
                    // since Windows 10; treat any failure as unavailable.
                    if (NtQuerySystemInformation(90, out var boot, (uint)Marshal.SizeOf<BootEnvironment>(), out var length) >= 0
                        && length >= 16 && boot.Identifier != Guid.Empty)
                        return "windows-" + boot.Identifier.ToString("D");
                }
                catch (Exception exception) when (exception is DllNotFoundException or EntryPointNotFoundException or TypeLoadException)
                {
                }
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                try
                {
                    var value = File.ReadAllText("/proc/sys/kernel/random/boot_id").Trim();
                    if (Guid.TryParse(value, out _)) return value.ToLowerInvariant();
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                var bytes = new byte[37];
                var size = (UIntPtr)bytes.Length;
                if (sysctlbyname("kern.bootsessionuuid", bytes, ref size, IntPtr.Zero, UIntPtr.Zero) == 0
                    && size.ToUInt64() is > 0 and <= 37
                    && Guid.TryParse(Encoding.ASCII.GetString(bytes, 0, (int)size).TrimEnd('\0'), out var identifier))
                    return "macos-" + identifier.ToString("D");
            }

            // Never guess a boot identity from the mutable wall clock. If the OS
            // cannot supply one, only this process can reuse its elapsed counter;
            // reopening falls back to UTC and the protected rollback checkpoint.
            return "process-" + Guid.NewGuid().ToString("D");
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BootEnvironment
        {
            public Guid Identifier;
            public uint FirmwareType;
            public ulong Flags;
        }

        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(int informationClass, out BootEnvironment information, uint size, out uint returnLength);

        [DllImport("libSystem.dylib", CharSet = CharSet.Ansi)]
        private static extern int sysctlbyname(string name, [Out] byte[] value, ref UIntPtr size, IntPtr newValue, UIntPtr newSize);

        private const int ClockBoottime = 7;

        [StructLayout(LayoutKind.Sequential)]
        private struct Timespec
        {
            public long Seconds;
            public long Nanoseconds;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MachTimebaseInfo
        {
            public uint Numer;
            public uint Denom;
        }

        [DllImport("libc", EntryPoint = "clock_gettime", SetLastError = true)]
        private static extern int clock_gettime(int clockId, out Timespec value);

        [DllImport("libSystem.dylib")]
        private static extern ulong mach_continuous_time();

        [DllImport("libSystem.dylib")]
        private static extern int mach_timebase_info(out MachTimebaseInfo info);

        [DllImport("kernel32.dll")]
        private static extern ulong GetTickCount64();
    }

    public sealed class NightflyerConfig
    {
        /// <param name="systemId">The 20-character system identifier from the dashboard.</param>
        /// <param name="trustedSigningKeys">Pinned Ed25519 signing keys by key ID; the local trust root, never populated from a response.</param>
        public NightflyerConfig(string systemId, IReadOnlyDictionary<string, string> trustedSigningKeys)
        {
            if (systemId is null) throw new ArgumentNullException(nameof(systemId));
            if (trustedSigningKeys is null) throw new ArgumentNullException(nameof(trustedSigningKeys));
            SystemId = systemId;
            TrustedSigningKeys = trustedSigningKeys;
        }

        public string SystemId { get; }
        public string BaseUrl { get; init; } = "https://systemlocker.net";
        public string ExpectedIssuer { get; init; } = "https://systemlocker.net";
        public string SdkVersion { get; init; } = "0.2.0";
        public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(15);
        public int IdempotentTransportRetries { get; init; } = 1;
        public TimeSpan InstallationLockTimeout { get; init; } = TimeSpan.FromSeconds(5);
        /// <summary>
        /// Requires a signed online response before a persisted lease can be used
        /// after the OS boot changes. Enable this stricter policy when its added
        /// snapshot-replay resistance is worth requiring connectivity after reboot.
        /// </summary>
        public bool RequireOnlineAfterReboot { get; init; } = false;
        public INightflyerClock Clock { get; init; } = SystemNightflyerClock.Instance;

        // The key ring is a local trust root. Never populate it from an unsigned response.
        public IReadOnlyDictionary<string, string> TrustedSigningKeys { get; }
    }

    public sealed record HttpExchange(
        int StatusCode,
        byte[] Body,
        string? TransportError = null,
        IReadOnlyDictionary<string, string>? Headers = null)
    {
        public TimeSpan? RetryAfter
        {
            get
            {
                if (Headers is null || !Headers.TryGetValue("Retry-After", out var value)) return null;
                if (int.TryParse(value, out var seconds) && seconds >= 0) return TimeSpan.FromSeconds(seconds);
                if (!DateTimeOffset.TryParse(value, out var date)) return null;
                var remaining = date - DateTimeOffset.UtcNow;
                return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
            }
        }
    }

    public interface INightflyerTransport
    {
        Task<HttpExchange> PostJsonAsync(
            string url,
            string body,
            IReadOnlyDictionary<string, string> headers,
            CancellationToken cancellationToken = default);
    }

    /// <summary>
    /// Installs the transport used when a client or session is created without
    /// one. The Unity adapter (UnityWebRequestTransport) installs itself during
    /// engine startup; hosts without the engine must always provide a transport.
    /// </summary>
    internal static class NightflyerTransports
    {
        internal static Func<TimeSpan, string, INightflyerTransport>? DefaultTransportFactory { get; set; }
    }

    public interface IInstallationKey
    {
        string PublicJwk { get; }
        string Thumbprint { get; }
        byte[] Sign(ReadOnlySpan<byte> input);
    }

    public sealed record InstallationKeyHandle(string Reference, IInstallationKey Key);

    /// <summary>Loads or creates a persistent, preferably non-exportable P-256 installation key.</summary>
    public interface INightflyerInstallationKeyProvider
    {
        InstallationKeyHandle Create(string systemId);
        InstallationKeyHandle Load(string systemId, string reference);
        void Delete(string systemId, string reference);
    }

    /// <summary>
    /// Windows installation keys held in the CNG key stores. Keys are created
    /// non-exportable, preferring the TPM-backed Platform Crypto Provider with
    /// the software key storage provider as the fallback. This is a direct
    /// port of the native Nightflyer CNG adapter and uses NCrypt directly so
    /// it does not depend on Windows-specific BCL classes.
    /// </summary>
    public sealed class WindowsNcryptInstallationKeyProvider : INightflyerInstallationKeyProvider
    {
        private const string ReferencePrefix = "cng-v1:";
        private const string PlatformCryptoProvider = "Microsoft Platform Crypto Provider";
        private const string SoftwareKeyStorageProvider = "Microsoft Software Key Storage Provider";
        private const int Success = 0;

        public InstallationKeyHandle Create(string systemId)
        {
            RequireWindows();
            var name = $"SystemLocker.Nightflyer.{systemId}.{Guid.NewGuid():N}";
            return CreateNamed(name);
        }

        /// <summary>Opens or creates the stable installation key used by memory-only sessions on this Windows user profile.</summary>
        public InstallationKeyHandle OpenOrCreateStable(string systemId)
        {
            RequireWindows();
            var name = $"SystemLocker.Nightflyer.{systemId}.memory";
            foreach (var providerName in new[] { PlatformCryptoProvider, SoftwareKeyStorageProvider })
            {
                try { return OpenNamed(providerName, name); }
                catch (NightflyerException exception) when (exception.Failure == NightflyerFailure.InvalidState) { }
            }
            return CreateNamed(name);
        }

        public InstallationKeyHandle Load(string systemId, string reference)
        {
            RequireWindows();
            var parsed = ParseReference(systemId, reference);
            var handle = OpenKeyHandle(parsed.ProviderName, parsed.KeyName);
            return new InstallationKeyHandle(reference, new NcryptInstallationKey(handle));
        }

        public void Delete(string systemId, string reference)
        {
            RequireWindows();
            var parsed = ParseReference(systemId, reference);
            IntPtr provider = IntPtr.Zero;
            IntPtr key = IntPtr.Zero;
            try
            {
                if (NCryptOpenStorageProvider(out provider, parsed.ProviderName, 0) != Success
                    || NCryptOpenKey(provider, out key, parsed.KeyName, 0, 0) != Success
                    || NCryptDeleteKey(key, 0) != Success)
                    throw new NightflyerException(NightflyerFailure.LocalFailure, "The persistent CNG installation key could not be deleted.");
                key = IntPtr.Zero; // NCryptDeleteKey invalidates the handle.
            }
            finally
            {
                if (key != IntPtr.Zero) NCryptFreeObject(key);
                if (provider != IntPtr.Zero) NCryptFreeObject(provider);
            }
        }

        private static void RequireWindows()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                throw new PlatformNotSupportedException("Windows CNG installation keys are available only on Windows.");
        }

        private static (string ProviderName, string KeyName) ParseReference(string systemId, string reference)
        {
            if (!reference.StartsWith(ReferencePrefix, StringComparison.Ordinal))
                throw new NightflyerException(NightflyerFailure.InvalidState, "The persistent installation-key reference is invalid.");
            byte[] bytes;
            try
            {
                bytes = Base64Url.Decode(reference.Substring(ReferencePrefix.Length));
            }
            catch (NightflyerException)
            {
                throw new NightflyerException(NightflyerFailure.InvalidState, "The persistent installation-key reference is invalid.");
            }
            string providerName;
            string keyName;
            try
            {
                var value = NightflyerJsonNode.Parse(bytes);
                if (value.Kind != NightflyerJsonValueKind.Object
                    || !value.TryGetProperty("provider", out var providerNode) || providerNode.Kind != NightflyerJsonValueKind.String
                    || !value.TryGetProperty("name", out var nameNode) || nameNode.Kind != NightflyerJsonValueKind.String)
                    throw new NightflyerJsonException("CNG key reference profile is invalid.");
                providerName = providerNode.StringValue!;
                keyName = nameNode.StringValue!;
                if (value.Properties.Count != 2)
                    throw new NightflyerJsonException("CNG key reference profile is invalid.");
            }
            catch (NightflyerJsonException)
            {
                throw new NightflyerException(NightflyerFailure.InvalidState, "The persistent installation-key reference is invalid.");
            }
            if (!keyName.StartsWith($"SystemLocker.Nightflyer.{systemId}.", StringComparison.Ordinal))
                throw new NightflyerException(NightflyerFailure.InvalidState, "The persistent installation key belongs to another system.");
            return (providerName, keyName);
        }

        private static string BuildReference(string providerName, string keyName) =>
            ReferencePrefix + Base64Url.Encode(NightflyerJsonWriter.SerializeToUtf8(new List<KeyValuePair<string, object?>>
            {
                new("provider", providerName),
                new("name", keyName),
            }));

        private static IntPtr OpenKeyHandle(string providerName, string keyName)
        {
            IntPtr provider = IntPtr.Zero;
            IntPtr key = IntPtr.Zero;
            try
            {
                if (NCryptOpenStorageProvider(out provider, providerName, 0) != Success
                    || NCryptOpenKey(provider, out key, keyName, 0, 0) != Success)
                    throw new NightflyerException(NightflyerFailure.InvalidState, "The persistent CNG installation key is unavailable.");
                return key;
            }
            finally
            {
                // The key handle stays owned by the returned installation key.
                if (provider != IntPtr.Zero) NCryptFreeObject(provider);
            }
        }

        private static InstallationKeyHandle OpenNamed(string providerName, string keyName)
        {
            var handle = OpenKeyHandle(providerName, keyName);
            return new InstallationKeyHandle(BuildReference(providerName, keyName), new NcryptInstallationKey(handle));
        }

        private static InstallationKeyHandle CreateNamed(string keyName)
        {
            foreach (var providerName in new[] { PlatformCryptoProvider, SoftwareKeyStorageProvider })
            {
                IntPtr provider = IntPtr.Zero;
                IntPtr key = IntPtr.Zero;
                try
                {
                    if (NCryptOpenStorageProvider(out provider, providerName, 0) == Success
                        && NCryptCreatePersistedKey(provider, out key, "ECDSA_P256", keyName, 0, 0) == Success)
                    {
                        // Signing-only key usage; the key is never marked exportable.
                        var usage = BitConverter.GetBytes(2 /* NCRYPT_ALLOW_SIGNING_FLAG */);
                        _ = NCryptSetProperty(key, "Key Usage", usage, usage.Length, 0);
                        if (NCryptFinalizeKey(key, 0) == Success)
                        {
                            var reference = BuildReference(providerName, keyName);
                            var installation = new NcryptInstallationKey(key);
                            key = IntPtr.Zero; // ownership moved
                            return new InstallationKeyHandle(reference, installation);
                        }
                    }
                }
                finally
                {
                    if (key != IntPtr.Zero) NCryptFreeObject(key);
                    if (provider != IntPtr.Zero) NCryptFreeObject(provider);
                }
                // Another process may have won the named-key creation race.
                try { return OpenNamed(providerName, keyName); }
                catch (NightflyerException exception) when (exception.Failure == NightflyerFailure.InvalidState) { }
            }
            throw new NightflyerException(NightflyerFailure.LocalFailure, "Windows could not create the non-exportable CNG installation key.");
        }

        /// <summary>A P-256 installation key held by CNG. NCryptSignHash returns the 64-byte IEEE P-1363 form directly.</summary>
        private sealed class NcryptInstallationKey : IInstallationKey, IDisposable
        {
            private IntPtr _key;
            private readonly byte[] _publicCoordinates; // x[32] || y[32]
            private readonly string _jwk;

            public NcryptInstallationKey(IntPtr key)
            {
                _key = key;
                var blob = ExportPublicKey(key);
                _publicCoordinates = new byte[64];
                Buffer.BlockCopy(blob, 8, _publicCoordinates, 0, 64);
                _jwk = $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{Base64Url.Encode(_publicCoordinates, 0, 32)}\",\"y\":\"{Base64Url.Encode(_publicCoordinates, 32, 32)}\"}}";
                Thumbprint = Base64Url.Encode(CryptoHelpers.Sha256Hash(Encoding.UTF8.GetBytes(_jwk)));
            }

            public string PublicJwk => _jwk;
            public string Thumbprint { get; }

            public byte[] Sign(ReadOnlySpan<byte> input)
            {
                if (_key == IntPtr.Zero) throw new ObjectDisposedException(nameof(NcryptInstallationKey));
                var hash = CryptoHelpers.Sha256Hash(input.ToArray());
                var signature = new byte[64];
                if (NCryptSignHash(_key, IntPtr.Zero, hash, hash.Length, signature, signature.Length, out var length, 0) != Success || length != 64)
                    throw new NightflyerException(NightflyerFailure.LocalFailure, "CNG installation proof signing failed.");
                return signature;
            }

            public void Dispose()
            {
                if (_key != IntPtr.Zero)
                {
                    NCryptFreeObject(_key);
                    _key = IntPtr.Zero;
                }
            }

            private static byte[] ExportPublicKey(IntPtr key)
            {
                if (NCryptExportKey(key, IntPtr.Zero, "ECCPUBLICBLOB", IntPtr.Zero, null, 0, out var length, 0) != Success)
                    throw new NightflyerException(NightflyerFailure.LocalFailure, "Could not read the CNG installation public key.");
                var blob = new byte[length];
                if (NCryptExportKey(key, IntPtr.Zero, "ECCPUBLICBLOB", IntPtr.Zero, blob, blob.Length, out var written, 0) != Success
                    || written != blob.Length)
                    throw new NightflyerException(NightflyerFailure.LocalFailure, "Could not read the CNG installation public key.");
                // BCRYPT_ECCKEY_BLOB header: magic (0x31534345 = 'ECS1', ECDSA public P-256), then cbKey == 32, then x and y.
                if (blob.Length != 8 + 64 || BitConverter.ToUInt32(blob, 0) != 0x31534345u || BitConverter.ToUInt32(blob, 4) != 32u)
                    throw new NightflyerException(NightflyerFailure.LocalFailure, "The CNG installation key is not P-256.");
                return blob;
            }
        }

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, int dwFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptCreatePersistedKey(IntPtr hProvider, out IntPtr phKey, string pszAlgId, string pszKeyName, int dwLegacyKeySpec, int dwFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptOpenKey(IntPtr hProvider, out IntPtr phKey, string pszKeyName, int dwLegacyKeySpec, int dwFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptSetProperty(IntPtr hKey, string pszProperty, byte[] pbInput, int cbInput, int dwFlags);

        [DllImport("ncrypt.dll")]
        private static extern int NCryptFinalizeKey(IntPtr hKey, int dwFlags);

        [DllImport("ncrypt.dll")]
        private static extern int NCryptDeleteKey(IntPtr hKey, int dwFlags);

        [DllImport("ncrypt.dll")]
        private static extern int NCryptFreeObject(IntPtr hObject);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptExportKey(IntPtr hKey, IntPtr hImportKey, string pszBlobType, IntPtr pParameterList, byte[]? pbOutput, int cbOutput, out int pcbResult, int dwFlags);

        [DllImport("ncrypt.dll")]
        private static extern int NCryptSignHash(IntPtr hKey, IntPtr pPaddingInfo, byte[] pbHash, int cbHash, byte[] pbSignature, int cbSignature, out int pcbResult, int dwFlags);
    }

    /// <summary>In-memory P-256 installation proof key. Use a CNG or platform key provider for persistent sessions whenever available.</summary>
    public sealed class EcdsaInstallationKey : IInstallationKey, IDisposable
    {
        private readonly ECDsa _key;
        private readonly string _jwk;

        public EcdsaInstallationKey(ECDsa? key = null)
        {
            _key = key ?? ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var parameters = _key.ExportParameters(false);
            if (parameters.Q.X is not { Length: 32 } x || parameters.Q.Y is not { Length: 32 } y)
            {
                _key.Dispose();
                throw new NightflyerException(NightflyerFailure.Configuration, "Installation key must use the P-256 curve.");
            }

            _jwk = $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{Base64Url.Encode(x)}\",\"y\":\"{Base64Url.Encode(y)}\"}}";
            Thumbprint = Base64Url.Encode(CryptoHelpers.Sha256Hash(Encoding.UTF8.GetBytes(_jwk)));
        }

        public string PublicJwk => _jwk;
        public string Thumbprint { get; }

        public byte[] Sign(ReadOnlySpan<byte> input)
        {
            // Some runtimes emit ASN.1 DER from the plain overload; normalize to
            // the fixed 64-byte r||s form the protocol signs and stores.
            var signature = _key.SignData(input.ToArray(), HashAlgorithmName.SHA256);
            if (signature.Length == 64) return signature;
            return DsaSignatures.DerToP1363(signature);
        }

        public bool Verify(ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature)
        {
            if (signature.Length != 64) throw new NightflyerException(NightflyerFailure.LocalFailure, "A P-256 signature must be 64 bytes.");
            return VerifyP1363(_key, input.ToArray(), signature.ToArray());
        }

        /// <summary>
        /// Verifies a P-1363 signature. The plain VerifyData overload is
        /// format-dependent across runtimes (CNG accepts r||s; OpenSSL-backed
        /// providers accept DER), so both encodings are attempted.
        /// </summary>
        internal static bool VerifyP1363(ECDsa key, byte[] data, byte[] signatureP1363)
        {
            try
            {
                if (key.VerifyData(data, signatureP1363, HashAlgorithmName.SHA256)) return true;
            }
            catch (CryptographicException) { }
            try
            {
                if (key.VerifyData(data, DsaSignatures.P1363ToDer(signatureP1363), HashAlgorithmName.SHA256)) return true;
            }
            catch (CryptographicException) { }
            return false;
        }

        /// <summary>Exports the private scalar and public point as three 32-byte values for adapter-managed storage.</summary>
        public byte[] ExportPrivateBytes()
        {
            var parameters = _key.ExportParameters(true);
            if (parameters.D is not { Length: <= 32 } || parameters.Q.X is not { Length: 32 } || parameters.Q.Y is not { Length: 32 })
                throw new NightflyerException(NightflyerFailure.LocalFailure, "Installation key is not P-256.");
            var result = new byte[96];
            CopyLeftPadded(parameters.D!, result, 0);
            Buffer.BlockCopy(parameters.Q.X!, 0, result, 32, 32);
            Buffer.BlockCopy(parameters.Q.Y!, 0, result, 64, 32);
            return result;
        }

        public static EcdsaInstallationKey ImportPrivateBytes(ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length != 96) throw new NightflyerException(NightflyerFailure.Configuration, "Installation key material must be 96 bytes.");
            var material = bytes.ToArray();
            var key = ECDsa.Create();
            try
            {
                key.ImportParameters(new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    D = material[..32],
                    Q = new ECPoint { X = material[32..64], Y = material[64..96] },
                });
                return new EcdsaInstallationKey(key);
            }
            catch
            {
                key.Dispose();
                throw;
            }
        }

        private static void CopyLeftPadded(byte[] source, byte[] destination, int offset)
        {
            for (var index = 0; index < 32; index++) destination[offset + index] = 0;
            Buffer.BlockCopy(source, 0, destination, offset + (32 - source.Length), source.Length);
        }

        public void Dispose() => _key.Dispose();
    }

    /// <summary>ASN.1 DER ⇄ IEEE P-1363 conversion for ECDSA signatures.</summary>
    internal static class DsaSignatures
    {
        public static byte[] DerToP1363(byte[] der)
        {
            try
            {
                var position = 0;
                if (der[position++] != 0x30) throw new FormatException();
                var length = ReadDerLength(der, ref position);
                if (position + length != der.Length) throw new FormatException();
                var r = ReadDerInteger(der, ref position);
                var s = ReadDerInteger(der, ref position);
                if (position != der.Length || r.Length > 32 || s.Length > 32) throw new FormatException();
                var result = new byte[64];
                Buffer.BlockCopy(r, 0, result, 32 - r.Length, r.Length);
                Buffer.BlockCopy(s, 0, result, 64 - s.Length, s.Length);
                return result;
            }
            catch (Exception exception) when (exception is FormatException or IndexOutOfRangeException)
            {
                throw new NightflyerException(NightflyerFailure.LocalFailure, "A DER signature could not be converted.");
            }
        }

        public static byte[] P1363ToDer(byte[] signature)
        {
            if (signature.Length != 64) throw new NightflyerException(NightflyerFailure.LocalFailure, "A P-256 signature must be 64 bytes.");
            var r = TrimLeadingZeros(signature, 0, 32);
            var s = TrimLeadingZeros(signature, 32, 32);
            // DER INTEGERs are signed: a magnitude with its high bit set needs a leading zero byte.
            var rLength = r.Length + (r[0] >= 0x80 ? 1 : 0);
            var sLength = s.Length + (s[0] >= 0x80 ? 1 : 0);
            var bodyLength = 2 + rLength + 2 + sLength;
            var result = new byte[2 + bodyLength + 1];
            var position = 0;
            result[position++] = 0x30;
            if (bodyLength < 128)
            {
                result[position++] = (byte)bodyLength;
            }
            else
            {
                result[position++] = 0x81;
                result[position++] = (byte)bodyLength;
            }
            WriteDerInteger(result, ref position, r);
            WriteDerInteger(result, ref position, s);
            return result[..position];
        }

        private static byte[] TrimLeadingZeros(byte[] value, int offset, int length)
        {
            var end = offset + length;
            while (offset < end - 1 && value[offset] == 0) offset++;
            return value[offset..end];
        }

        private static void WriteDerInteger(byte[] destination, ref int position, byte[] magnitude)
        {
            destination[position++] = 0x02;
            if (magnitude[0] >= 0x80)
            {
                destination[position++] = (byte)(magnitude.Length + 1);
                destination[position++] = 0;
            }
            else
            {
                destination[position++] = (byte)magnitude.Length;
            }
            Buffer.BlockCopy(magnitude, 0, destination, position, magnitude.Length);
            position += magnitude.Length;
        }

        private static int ReadDerLength(byte[] der, ref int position)
        {
            var first = der[position++];
            if (first < 0x80) return first;
            var lengthBytes = first & 0x7f;
            if (lengthBytes == 0 || lengthBytes > 4) throw new FormatException();
            var length = 0;
            for (var index = 0; index < lengthBytes; index++) length = (length << 8) | der[position++];
            return length;
        }

        private static byte[] ReadDerInteger(byte[] der, ref int position)
        {
            if (der[position++] != 0x02) throw new FormatException();
            var length = ReadDerLength(der, ref position);
            if (length == 0 || length > 33) throw new FormatException();
            var value = der[position..(position + length)];
            position += length;
            if (length == 33 && value[0] == 0) return value[1..]; // canonical non-negative padding
            return value;
        }
    }

    internal static class CryptoHelpers
    {
        public static byte[] Sha256Hash(byte[] input)
        {
            using var sha256 = SHA256.Create();
            return sha256.ComputeHash(input);
        }

        public static byte[] RandomBytes(int count)
        {
            var bytes = new byte[count];
            RandomNumberGenerator.Fill(bytes);
            return bytes;
        }

        public static int RandomInt32(int exclusiveUpperBound)
        {
            if (exclusiveUpperBound <= 0) throw new ArgumentOutOfRangeException(nameof(exclusiveUpperBound));
            // Rejection sampling over a CSPRNG keeps the distribution uniform.
            var limit = 0x1_0000_0000u / (uint)exclusiveUpperBound * (uint)exclusiveUpperBound;
            while (true)
            {
                var value = RandomUInt32();
                if (value < limit) return (int)(value % (uint)exclusiveUpperBound);
            }
        }

        private static uint RandomUInt32() => BitConverter.ToUInt32(RandomBytes(4), 0);

        public static string ToHexUpper(byte[] bytes)
        {
            var result = new StringBuilder(bytes.Length * 2);
            foreach (var value in bytes) result.Append(value.ToString("X2", CultureInfo.InvariantCulture));
            return result.ToString();
        }
    }

    internal static class ProtocolValidation
    {
        private static readonly Regex KidPatternValue = new(@"\A[0-9A-HJKMNP-TV-Z]{26}\z", RegexOptions.CultureInvariant | RegexOptions.Compiled);
        private static readonly Regex SystemPatternValue = new(@"\A[A-Za-z0-9]{20}\z", RegexOptions.CultureInvariant | RegexOptions.Compiled);
        private static readonly Regex UuidV4PatternValue = new(@"\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z", RegexOptions.CultureInvariant | RegexOptions.Compiled);

        public static bool IsKid(string value) => KidPatternValue.IsMatch(value);
        public static bool IsSystemId(string value) => SystemPatternValue.IsMatch(value);
        public static bool IsUuidV4(string value) => UuidV4PatternValue.IsMatch(value);

        public static Uri RequireHttpsOrigin(string value, string name)
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)
                || uri.Scheme != Uri.UriSchemeHttps
                || string.IsNullOrEmpty(uri.Host)
                || !string.IsNullOrEmpty(uri.UserInfo)
                || !string.IsNullOrEmpty(uri.Query)
                || !string.IsNullOrEmpty(uri.Fragment)
                || uri.AbsolutePath is not "/")
            {
                throw new NightflyerException(NightflyerFailure.Configuration, $"{name} must be an HTTPS origin without a path, query, fragment, or credentials.");
            }
            return uri;
        }

        public static void RequireValidUnicode(string value)
        {
            // Unpaired surrogates are the only way UTF-16 strings can hold
            // invalid Unicode scalar values.
            for (var index = 0; index < value.Length; index++)
            {
                var character = value[index];
                if (char.IsHighSurrogate(character))
                {
                    if (index + 1 >= value.Length || !char.IsLowSurrogate(value[index + 1]))
                        throw new NightflyerException(NightflyerFailure.Configuration, "Request strings must contain valid Unicode scalar values.");
                    index++;
                }
                else if (char.IsLowSurrogate(character))
                {
                    throw new NightflyerException(NightflyerFailure.Configuration, "Request strings must contain valid Unicode scalar values.");
                }
            }
        }
    }

    internal static class Base64Url
    {
        public static string Encode(ReadOnlySpan<byte> bytes) => Convert.ToBase64String(bytes.ToArray()).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        public static string Encode(byte[] bytes, int offset, int length) => Encode(bytes.AsSpan(offset, length));

        public static byte[] Decode(string value, int? expectedBytes = null)
        {
            if (string.IsNullOrEmpty(value) || value.Contains('=') || value.Any(c => !(IsAsciiLetterOrDigit(c) || c is '-' or '_')))
                throw new NightflyerException(NightflyerFailure.InvalidToken, "Invalid base64url encoding.");
            var padded = value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4);
            byte[] bytes;
            try { bytes = Convert.FromBase64String(padded); }
            catch (FormatException) { throw new NightflyerException(NightflyerFailure.InvalidToken, "Invalid base64url encoding."); }
            if (expectedBytes is not null && bytes.Length != expectedBytes.Value)
                throw new NightflyerException(NightflyerFailure.InvalidToken, "Unexpected base64url length.");
            if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(value), Encoding.ASCII.GetBytes(Encode(bytes))))
                throw new NightflyerException(NightflyerFailure.InvalidToken, "Non-canonical base64url encoding.");
            return bytes;
        }

        private static bool IsAsciiLetterOrDigit(char c) =>
            (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
    }
}
