using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace SystemLocker.Nightflyer
{
    public sealed record Lease(
        string Compact,
        string AuthorizationId,
        long Generation,
        DateTimeOffset IssuedAt,
        DateTimeOffset ExpiresAt,
        DateTimeOffset RenewAfter,
        string DeviceThumbprint,
        string DeviceId,
        string HwidHash,
        string SigningKeyId);

    public sealed record NightflyerStatus(
        string Compact,
        string AuthorizationId,
        long Sequence,
        long KeysetSequence,
        long MinimumGeneration,
        string DeviceStatus,
        string GrantStatus,
        IReadOnlyList<string> RevokedSigningKeyIds,
        DateTimeOffset IssuedAt,
        DateTimeOffset? NextUpdate,
        string DeviceId);

    public sealed record NightflyerDecision(
        string Compact,
        string ResponseCode,
        string LeaseDisposition,
        DateTimeOffset IssuedAt,
        string? DeviceId,
        string? DeviceThumbprint,
        bool? OccupancyReleased,
        long? MinimumProtocolVersion,
        long? LatestProtocolVersion,
        string? MinimumSdkVersion,
        string? UpdateUrl);

    public sealed record NightflyerProblem(string Type, string Title, int Status, string Detail, string Code);

    public sealed record NightflyerResponse(
        int HttpStatus,
        Lease? Lease,
        NightflyerStatus? VerifiedStatus,
        NightflyerDecision? Decision,
        NightflyerProblem? Problem,
        IReadOnlyList<string> KeyTransitions,
        long KeysetSequence,
        TimeSpan? RetryAfter)
    {
        public string? Status => VerifiedStatus?.Compact;
        public string? DecisionCode => Decision?.ResponseCode;
        public bool IsSuccess => HttpStatus is >= 200 and < 300;
        public DateTimeOffset? SignedServerTime => VerifiedStatus?.IssuedAt ?? Decision?.IssuedAt ?? Lease?.IssuedAt;
    }

    internal sealed record PreparedNightflyerRequest(
        string Endpoint,
        string RequestUrl,
        string Body,
        string Proof,
        string RequestJti,
        string? PresentedLease,
        string? ExpectedHwid,
        long KeysetSequence,
        long StatusSequence);

    public sealed class NightflyerClient : IDisposable
    {
        private const long MaxSafeInteger = 9_007_199_254_740_991;
        private const long MaximumUnixTimestamp = 253_402_300_799;
        private const long MaximumOfflineSeconds = 7_776_000;

        private static readonly Regex ResponseCodePatternValue = new(@"\A[A-Z][A-Z0-9_]{0,63}\z", RegexOptions.CultureInvariant | RegexOptions.Compiled);

        private readonly NightflyerConfig _config;
        private readonly IInstallationKey _installationKey;
        private readonly INightflyerTransport? _injectedTransport;
        private INightflyerTransport? _transport;
        private readonly bool _ownsTransport;
        private readonly Uri _requestOrigin;
        private readonly Uri _issuerOrigin;
        private readonly Dictionary<string, byte[]> _rootKeys = new(StringComparer.Ordinal);
        private Dictionary<string, byte[]> _keys = new(StringComparer.Ordinal);
        private bool _disposed;

        public NightflyerClient(NightflyerConfig config, IInstallationKey installationKey, INightflyerTransport? transport = null)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _installationKey = installationKey ?? throw new ArgumentNullException(nameof(installationKey));
            ValidateConfig(config);
            _requestOrigin = ProtocolValidation.RequireHttpsOrigin(config.BaseUrl, nameof(config.BaseUrl));
            _issuerOrigin = ProtocolValidation.RequireHttpsOrigin(config.ExpectedIssuer, nameof(config.ExpectedIssuer));

            foreach (var pair in config.TrustedSigningKeys)
            {
                if (!ProtocolValidation.IsKid(pair.Key))
                    throw new NightflyerException(NightflyerFailure.Configuration, "Every trusted signing key ID must be a 26-character Crockford ULID.");
                var decoded = Base64Url.Decode(pair.Value, 32);
                _rootKeys.Add(pair.Key, decoded);
                _keys.Add(pair.Key, (byte[])decoded.Clone());
            }
            if (_keys.Count == 0)
                throw new NightflyerException(NightflyerFailure.Configuration, "At least one pinned Nightflyer signing key is required.");

            _injectedTransport = transport;
            _ownsTransport = transport is null;
        }

        private INightflyerTransport ResolveTransport()
        {
            if (_transport is not null) return _transport;
            if (_injectedTransport is not null) return _transport = _injectedTransport;
            var factory = NightflyerTransports.DefaultTransportFactory;
            if (factory is null)
                throw new NightflyerException(NightflyerFailure.LocalFailure, "No default Nightflyer transport is installed; provide an INightflyerTransport.");
            return _transport = factory(_config.RequestTimeout, $"systemlocker-nightflyer-unity/{_config.SdkVersion}");
        }

        public Task<NightflyerResponse> AuthorizeWithKeyAsync(
            string licenseKey,
            string version,
            string digest,
            string slHwid,
            int requestedOfflineSeconds,
            bool persistent,
            long keysetSequence = 0,
            long statusSequence = 0,
            CancellationToken cancellationToken = default) =>
            SendPreparedAsync(Prepare(
                "authorize",
                new List<KeyValuePair<string, object?>>
                {
                    new("identity_type", "key"),
                    new("license_key", licenseKey),
                    new("version", version),
                    new("digest", digest),
                    new("sl_hwid", slHwid),
                    new("storage_mode", persistent ? "persistent" : "memory"),
                    new("requested_offline_seconds", requestedOfflineSeconds),
                },
                null,
                keysetSequence,
                statusSequence), cancellationToken);

        public Task<NightflyerResponse> AuthorizeWithAccountAsync(
            string username,
            string password,
            string version,
            string digest,
            string slHwid,
            int requestedOfflineSeconds,
            bool persistent,
            long keysetSequence = 0,
            long statusSequence = 0,
            CancellationToken cancellationToken = default) =>
            SendPreparedAsync(Prepare(
                "authorize",
                new List<KeyValuePair<string, object?>>
                {
                    new("identity_type", "account"),
                    new("username", username),
                    new("password", password),
                    new("version", version),
                    new("digest", digest),
                    new("sl_hwid", slHwid),
                    new("storage_mode", persistent ? "persistent" : "memory"),
                    new("requested_offline_seconds", requestedOfflineSeconds),
                },
                null,
                keysetSequence,
                statusSequence), cancellationToken);

        public Task<NightflyerResponse> RenewAsync(
            string lease,
            string version,
            string digest,
            string slHwid,
            long keysetSequence = 0,
            long statusSequence = 0,
            CancellationToken cancellationToken = default) =>
            SendPreparedAsync(Prepare(
                "renew",
                new List<KeyValuePair<string, object?>>
                {
                    new("lease", lease),
                    new("version", version),
                    new("digest", digest),
                    new("sl_hwid", slHwid),
                },
                lease,
                keysetSequence,
                statusSequence), cancellationToken);

        public Task<NightflyerResponse> StatusAsync(
            string lease,
            long keysetSequence = 0,
            long statusSequence = 0,
            CancellationToken cancellationToken = default) =>
            SendPreparedAsync(Prepare(
                "status",
                new List<KeyValuePair<string, object?>> { new("lease", lease) },
                lease,
                keysetSequence,
                statusSequence), cancellationToken);

        public Task<NightflyerResponse> EndAsync(
            string lease,
            string reason,
            long keysetSequence = 0,
            long statusSequence = 0,
            CancellationToken cancellationToken = default) =>
            SendPreparedAsync(PrepareEnd(lease, reason, keysetSequence, statusSequence), cancellationToken);

        internal PreparedNightflyerRequest PrepareEnd(string lease, string reason, long keysetSequence, long statusSequence) =>
            Prepare(
                "end",
                new List<KeyValuePair<string, object?>> { new("lease", lease), new("end_reason", reason) },
                lease,
                keysetSequence,
                statusSequence);

        /// <summary>Returns the pinned keys plus keys accepted through verified, sequenced transitions.</summary>
        public IReadOnlyDictionary<string, string> ExportTrustedSigningKeys() =>
            _keys.ToDictionary(pair => pair.Key, pair => Base64Url.Encode(pair.Value), StringComparer.Ordinal);

        internal Lease VerifyCachedLease(string compact) => VerifyLease(compact, null, null, _keys);

        internal NightflyerStatus VerifyCachedStatus(string compact, Lease? lease) =>
            VerifyStatus(compact, null, lease, _keys);

        // Persistent state carries the server-signed derivation path, never a
        // mutable snapshot of the resulting trust ring. Replaying from the
        // application roots makes every additional key prove its provenance.
        internal void RestoreTrustedSigningKeyTransitions(IReadOnlyList<string> transitions, long expectedSequence)
        {
            var workingKeys = _rootKeys.ToDictionary(pair => pair.Key, pair => (byte[])pair.Value.Clone(), StringComparer.Ordinal);
            long sequence = 0;
            try
            {
                foreach (var transition in transitions)
                    sequence = ApplyTransition(transition, sequence, workingKeys);
            }
            catch (NightflyerException exception) when (exception.Failure is NightflyerFailure.InvalidToken or NightflyerFailure.InvalidSignature)
            {
                throw new NightflyerException(NightflyerFailure.InvalidState, "Persistent signing-key transition history is not authentic.");
            }

            if (sequence != expectedSequence)
                throw new NightflyerException(NightflyerFailure.InvalidState, "Persistent signing-key transition history does not match its high-water mark.");
            _keys = workingKeys;
        }

        internal async Task<NightflyerResponse> SendPreparedAsync(
            PreparedNightflyerRequest prepared,
            CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            var transport = ResolveTransport();
            var headers = new Dictionary<string, string>(StringComparer.Ordinal) { ["Nightflyer-Proof"] = prepared.Proof };
            var exchange = await transport.PostJsonAsync(prepared.RequestUrl, prepared.Body, headers, cancellationToken).ConfigureAwait(false);

            // An in-flight transport retry deliberately reuses the exact bytes and
            // proof JTI, matching the server's idempotent replay window.
            for (var attempt = 0; exchange.TransportError is not null && attempt < _config.IdempotentTransportRetries; attempt++)
                exchange = await transport.PostJsonAsync(prepared.RequestUrl, prepared.Body, headers, cancellationToken).ConfigureAwait(false);

            if (exchange.TransportError is not null)
                throw new NightflyerException(NightflyerFailure.Transport, exchange.TransportError);
            return ProcessResponse(exchange, prepared);
        }

        private PreparedNightflyerRequest Prepare(
            string endpoint,
            List<KeyValuePair<string, object?>> request,
            string? lease,
            long keysetSequence,
            long statusSequence)
        {
            ThrowIfDisposed();
            ValidateRequest(endpoint, request, keysetSequence, statusSequence);

            SetMember(request, "protocol_version", 1L);
            SetMember(request, "sdk_version", _config.SdkVersion);
            SetMember(request, "system", _config.SystemId);
            SetMember(request, "trusted_kids", _keys.Keys.OrderBy(key => key, StringComparer.Ordinal).ToArray());
            SetMember(request, "keyset_sequence", keysetSequence);
            SetMember(request, "status_sequence", statusSequence);

            var relative = $"api/nightflyer/v1/{endpoint}";
            var requestUrl = new Uri(_requestOrigin, relative).AbsoluteUri;
            var proofHtu = new Uri(_issuerOrigin, relative).AbsoluteUri;
            var requestJson = NightflyerJsonWriter.Serialize(request);
            var projection = RequestProjection(endpoint, request);
            var requestJti = Base64Url.Encode(CryptoHelpers.RandomBytes(16));
            var proof = CreateProof(proofHtu, projection, lease, requestJti);
            var expectedHwid = TryGetMember(request, "sl_hwid", out var hwid) && hwid is string hwidText ? hwidText : null;
            return new PreparedNightflyerRequest(endpoint, requestUrl, requestJson, proof, requestJti, lease, expectedHwid, keysetSequence, statusSequence);
        }

        private static void SetMember(List<KeyValuePair<string, object?>> request, string name, object? value)
        {
            for (var index = 0; index < request.Count; index++)
            {
                if (string.Equals(request[index].Key, name, StringComparison.Ordinal))
                {
                    request[index] = new KeyValuePair<string, object?>(name, value);
                    return;
                }
            }
            request.Add(new KeyValuePair<string, object?>(name, value));
        }

        private static bool TryGetMember(IReadOnlyList<KeyValuePair<string, object?>> request, string name, out object? value)
        {
            foreach (var pair in request)
            {
                if (string.Equals(pair.Key, name, StringComparison.Ordinal))
                {
                    value = pair.Value;
                    return true;
                }
            }
            value = null;
            return false;
        }

        private static object? GetMember(IReadOnlyList<KeyValuePair<string, object?>> request, string name) =>
            TryGetMember(request, name, out var value) ? value : throw new KeyNotFoundException(name);

        private string CreateProof(
            string htu,
            IReadOnlyList<KeyValuePair<string, object?>> projection,
            string? lease,
            string requestJti)
        {
            var jwk = NightflyerJsonNode.Parse(Encoding.UTF8.GetBytes(_installationKey.PublicJwk));
            RequireExact(jwk, new[] { "crv", "kty", "x", "y" }, "installation JWK");
            var headerBytes = NightflyerJsonWriter.SerializeToUtf8(new List<KeyValuePair<string, object?>>
            {
                new("alg", "ES256"),
                new("typ", "nightflyer-proof+jwt"),
                new("jwk", jwk),
            });

            var claims = new List<KeyValuePair<string, object?>>
            {
                new("nightflyer_version", 1L),
                new("htm", "POST"),
                new("htu", htu),
                new("system", _config.SystemId),
                new("iat", _config.Clock.UtcNow.ToUnixTimeSeconds()),
                new("jti", requestJti),
                new("rqh", Base64Url.Encode(CryptoHelpers.Sha256Hash(Encoding.UTF8.GetBytes(CanonicalJson(projection))))),
            };
            if (lease is not null) claims.Add(new("ath", Base64Url.Encode(CryptoHelpers.Sha256Hash(Encoding.ASCII.GetBytes(lease)))));

            var header = Base64Url.Encode(headerBytes);
            var payload = Base64Url.Encode(NightflyerJsonWriter.SerializeToUtf8(claims));
            var input = Encoding.ASCII.GetBytes(header + "." + payload);
            return header + "." + payload + "." + Base64Url.Encode(_installationKey.Sign(input));
        }

        private NightflyerResponse ProcessResponse(HttpExchange exchange, PreparedNightflyerRequest prepared)
        {
            if (exchange.Body.Length == 0 || exchange.Body.Length > 1_048_576)
                throw InvalidResponse("Nightflyer response body is missing or too large.");

            var root = ParseJson(exchange.Body, NightflyerFailure.InvalidResponse, "Nightflyer response is not strict JSON.");
            RequireObject(root, "response", NightflyerFailure.InvalidResponse);

            if (!root.TryGetProperty("protocol_version", out _))
            {
                if (exchange.StatusCode is >= 200 and < 300)
                    throw InvalidResponse("A successful response lacks Nightflyer framing.");
                var unsignedProblem = ParseProblem(root, exchange.StatusCode);
                return new NightflyerResponse(exchange.StatusCode, null, null, null, unsignedProblem, Array.Empty<string>(), prepared.KeysetSequence, exchange.RetryAfter);
            }

            if (RequireInteger(root, "protocol_version") != 1
                || RequireString(root, "request_jti") is not { } responseJti
                || !FixedAsciiEquals(responseJti, prepared.RequestJti))
                throw InvalidResponse("Response does not bind to this request.");
            Base64Url.Decode(responseJti, 16);

            var outerMembers = new List<string> { "protocol_version", "request_jti", "key_transitions" };
            foreach (var optional in new[] { "lease", "status", "decision", "problem" })
                if (root.TryGetProperty(optional, out _)) outerMembers.Add(optional);
            RequireExact(root, outerMembers, "response", NightflyerFailure.InvalidResponse);

            if (!root.TryGetProperty("key_transitions", out var transitionArray) || transitionArray.Kind != NightflyerJsonValueKind.Array)
                throw InvalidResponse("Nightflyer framing lacks key_transitions.");

            var workingKeys = _keys.ToDictionary(pair => pair.Key, pair => (byte[])pair.Value.Clone(), StringComparer.Ordinal);
            var transitions = new List<string>();
            var acceptedKeysetSequence = prepared.KeysetSequence;
            foreach (var transitionValue in transitionArray.Items)
            {
                if (transitionValue.Kind != NightflyerJsonValueKind.String)
                    throw InvalidResponse("A key transition is not a compact JWS.");
                var transition = transitionValue.StringValue!;
                acceptedKeysetSequence = ApplyTransition(transition, acceptedKeysetSequence, workingKeys);
                transitions.Add(transition);
            }

            Lease? presentedLease = prepared.PresentedLease is null
                ? null
                : VerifyLease(prepared.PresentedLease, null, prepared.ExpectedHwid, workingKeys);
            Lease? responseLease = null;
            if (root.TryGetProperty("lease", out var leaseValue))
            {
                if (leaseValue.Kind != NightflyerJsonValueKind.String) throw InvalidResponse("The response lease is not a compact JWS.");
                responseLease = VerifyLease(leaseValue.StringValue!, prepared.RequestJti, prepared.ExpectedHwid, workingKeys);
            }

            NightflyerStatus? status = null;
            if (root.TryGetProperty("status", out var statusValue))
            {
                if (statusValue.Kind != NightflyerJsonValueKind.String) throw InvalidResponse("The response status is not a compact JWS.");
                status = VerifyStatus(statusValue.StringValue!, prepared.RequestJti, responseLease ?? presentedLease, workingKeys);
                acceptedKeysetSequence = Math.Max(acceptedKeysetSequence, status.KeysetSequence);
            }

            NightflyerDecision? decision = null;
            if (root.TryGetProperty("decision", out var decisionValue))
            {
                if (decisionValue.Kind != NightflyerJsonValueKind.String) throw InvalidResponse("The response decision is not a compact JWS.");
                decision = VerifyDecision(decisionValue.StringValue!, prepared.RequestJti, responseLease ?? presentedLease, status, workingKeys);
            }

            NightflyerProblem? problem = root.TryGetProperty("problem", out var problemValue)
                ? ParseProblem(problemValue, exchange.StatusCode)
                : null;

            if (exchange.StatusCode is >= 200 and < 300)
            {
                if (status is null) throw InvalidResponse("A successful Nightflyer response requires a signed status.");
            }
            else if (decision is null)
            {
                throw InvalidResponse("A framed denial requires a signed decision.");
            }
            if (exchange.StatusCode is < 200 or >= 300 && problem is null)
                throw InvalidResponse("A framed denial requires Problem Details.");

            _keys = workingKeys;
            return new NightflyerResponse(
                exchange.StatusCode,
                responseLease,
                status,
                decision,
                problem,
                transitions,
                acceptedKeysetSequence,
                exchange.RetryAfter);
        }

        private Lease VerifyLease(
            string token,
            string? expectedRequestJti,
            string? expectedHwid,
            IReadOnlyDictionary<string, byte[]> keys)
        {
            var verified = VerifyJws(token, "nightflyer-auth+jwt", keys);
            var claims = verified.Claims;
            RequireExact(claims,
                new[]
                {
                    "iss", "sub", "aud", "jti", "nightflyer_version", "device_id", "cnf", "sl_hwid_sha256",
                    "generation", "iat", "nbf", "exp", "renew_after", "policy_revision", "request_jti", "entitlements",
                }, "lease");

            RequireAudienceAndVersion(claims);
            var subject = RequireString(claims, "sub"); Base64Url.Decode(subject, 32);
            var authorizationId = RequireString(claims, "jti");
            var deviceId = RequireString(claims, "device_id");
            if (!ProtocolValidation.IsUuidV4(authorizationId) || !ProtocolValidation.IsUuidV4(deviceId))
                throw InvalidToken("Lease identifiers are invalid.");

            var requestJti = RequireString(claims, "request_jti"); Base64Url.Decode(requestJti, 16);
            if (expectedRequestJti is not null && !FixedAsciiEquals(requestJti, expectedRequestJti))
                throw InvalidToken("Lease does not bind to this request.");

            var confirmation = claims.GetProperty("cnf");
            RequireExact(confirmation, new[] { "jkt" }, "lease confirmation");
            var thumbprint = RequireString(confirmation, "jkt"); Base64Url.Decode(thumbprint, 32);
            if (!FixedAsciiEquals(thumbprint, _installationKey.Thumbprint))
                throw InvalidToken("Lease belongs to another installation.");

            var hwidHash = RequireString(claims, "sl_hwid_sha256"); Base64Url.Decode(hwidHash, 32);
            if (expectedHwid is not null)
            {
                var expectedHash = Base64Url.Encode(CryptoHelpers.Sha256Hash(Encoding.UTF8.GetBytes(expectedHwid)));
                if (!FixedAsciiEquals(hwidHash, expectedHash))
                    throw InvalidToken("Lease belongs to a different hardware identity.");
            }

            var generation = RequireSafePositiveInteger(claims, "generation");
            _ = RequireSafePositiveInteger(claims, "policy_revision");
            var issued = RequireTimestamp(claims, "iat");
            var notBefore = RequireTimestamp(claims, "nbf");
            var expires = RequireTimestamp(claims, "exp");
            var renewAfter = RequireTimestamp(claims, "renew_after");
            if (notBefore != issued || renewAfter < issued || renewAfter >= expires || expires <= issued || expires - issued > MaximumOfflineSeconds)
                throw InvalidToken("Lease timestamps are invalid.");

            var entitlements = claims.GetProperty("entitlements");
            if (entitlements.Kind != NightflyerJsonValueKind.Object || entitlements.Properties.Count != 0)
                throw InvalidToken("Lease entitlements use an unsupported profile.");

            return new Lease(
                token,
                authorizationId,
                generation,
                DateTimeOffset.FromUnixTimeSeconds(issued),
                DateTimeOffset.FromUnixTimeSeconds(expires),
                DateTimeOffset.FromUnixTimeSeconds(renewAfter),
                thumbprint,
                deviceId,
                hwidHash,
                verified.Kid);
        }

        private NightflyerStatus VerifyStatus(
            string token,
            string? requestJti,
            Lease? lease,
            IReadOnlyDictionary<string, byte[]> keys)
        {
            var verified = VerifyJws(token, "nightflyer-status+jwt", keys);
            var claims = verified.Claims;
            RequireExact(claims,
                new[]
                {
                    "iss", "aud", "nightflyer_version", "device_id", "authorization_id", "status_sequence",
                    "keyset_sequence", "minimum_generation", "device_status", "grant_status", "revoked_kids",
                    "iat", "next_update", "request_jti",
                }, "status");
            RequireAudienceAndVersion(claims);

            var tokenRequestJti = RequireString(claims, "request_jti"); Base64Url.Decode(tokenRequestJti, 16);
            if (requestJti is not null && !FixedAsciiEquals(tokenRequestJti, requestJti))
                throw InvalidToken("Status does not bind to this request.");
            var authorizationId = RequireString(claims, "authorization_id");
            var deviceId = RequireString(claims, "device_id");
            if (!ProtocolValidation.IsUuidV4(authorizationId) || !ProtocolValidation.IsUuidV4(deviceId))
                throw InvalidToken("Status identifiers are invalid.");
            if (lease is not null && (!FixedAsciiEquals(authorizationId, lease.AuthorizationId) || !FixedAsciiEquals(deviceId, lease.DeviceId)))
                throw InvalidToken("Status belongs to another lease or device.");

            var sequence = RequireSafeNonNegativeInteger(claims, "status_sequence");
            var keysetSequence = RequireSafeNonNegativeInteger(claims, "keyset_sequence");
            var minimumGeneration = RequireSafePositiveInteger(claims, "minimum_generation");
            var deviceStatus = RequireString(claims, "device_status");
            var grantStatus = RequireString(claims, "grant_status");
            if (deviceStatus is not "active" and not "revoked"
                || grantStatus is not "active" and not "reclaim_pending" and not "ended" and not "revoked")
                throw InvalidToken("Status state is invalid.");

            var revokedValue = claims.GetProperty("revoked_kids");
            if (revokedValue.Kind != NightflyerJsonValueKind.Array) throw InvalidToken("Status revocation list is invalid.");
            var revoked = new List<string>();
            string? previous = null;
            foreach (var item in revokedValue.Items)
            {
                if (item.Kind != NightflyerJsonValueKind.String || !ProtocolValidation.IsKid(item.StringValue!))
                    throw InvalidToken("Status revocation list is invalid.");
                var kid = item.StringValue!;
                if (previous is not null && string.CompareOrdinal(previous, kid) >= 0)
                    throw InvalidToken("Status revocation list is not strictly sorted.");
                previous = kid;
                revoked.Add(kid);
            }

            var issuedAt = RequireTimestamp(claims, "iat");
            var nextValue = claims.GetProperty("next_update");
            DateTimeOffset? nextUpdate = nextValue.Kind switch
            {
                NightflyerJsonValueKind.Null => null,
                NightflyerJsonValueKind.Number => DateTimeOffset.FromUnixTimeSeconds(RequireTimestamp(claims, "next_update")),
                _ => throw InvalidToken("Status update time is invalid."),
            };

            return new NightflyerStatus(
                token,
                authorizationId,
                sequence,
                keysetSequence,
                minimumGeneration,
                deviceStatus,
                grantStatus,
                revoked,
                DateTimeOffset.FromUnixTimeSeconds(issuedAt),
                nextUpdate,
                deviceId);
        }

        private NightflyerDecision VerifyDecision(
            string token,
            string requestJti,
            Lease? lease,
            NightflyerStatus? status,
            IReadOnlyDictionary<string, byte[]> keys)
        {
            var verified = VerifyJws(token, "nightflyer-decision+jwt", keys);
            var claims = verified.Claims;
            RequireAudienceAndVersion(claims);

            var code = RequireString(claims, "response_code");
            if (!ResponseCodePatternValue.IsMatch(code)) throw InvalidToken("Decision response code is invalid.");
            var tokenRequestJti = RequireString(claims, "request_jti"); Base64Url.Decode(tokenRequestJti, 16);
            if (!FixedAsciiEquals(tokenRequestJti, requestJti)) throw InvalidToken("Decision does not bind to this request.");
            var issuedAt = RequireTimestamp(claims, "iat");
            var disposition = RequireString(claims, "lease_disposition");
            if (disposition is not "unchanged" and not "revoked" and not "ended" and not "expired")
                throw InvalidToken("Decision lease disposition is invalid.");

            var hasDeviceId = claims.TryGetProperty("device_id", out var deviceIdValue);
            var hasDeviceJkt = claims.TryGetProperty("device_jkt", out var deviceJktValue);
            if (hasDeviceId == hasDeviceJkt) throw InvalidToken("Decision must contain exactly one device binding.");

            string? deviceId = null;
            string? deviceJkt = null;
            if (hasDeviceId)
            {
                deviceId = deviceIdValue.Kind == NightflyerJsonValueKind.String ? deviceIdValue.StringValue : null;
                if (deviceId is null || !ProtocolValidation.IsUuidV4(deviceId)) throw InvalidToken("Decision device ID is invalid.");
                var expectedDeviceId = status?.DeviceId ?? lease?.DeviceId;
                if (expectedDeviceId is null || !FixedAsciiEquals(deviceId, expectedDeviceId))
                    throw InvalidToken("Decision belongs to another device.");
            }
            else
            {
                deviceJkt = deviceJktValue.Kind == NightflyerJsonValueKind.String ? deviceJktValue.StringValue : null;
                if (deviceJkt is null) throw InvalidToken("Decision installation thumbprint is invalid.");
                Base64Url.Decode(deviceJkt, 32);
                if (!FixedAsciiEquals(deviceJkt, _installationKey.Thumbprint))
                    throw InvalidToken("Decision belongs to another installation.");
            }

            bool? occupancyReleased = null;
            if (claims.TryGetProperty("occupancy_released", out var occupancy))
            {
                if (occupancy.Kind is not NightflyerJsonValueKind.True and not NightflyerJsonValueKind.False)
                    throw InvalidToken("Decision occupancy result is invalid.");
                occupancyReleased = occupancy.BoolValue;
            }

            long? minimumProtocol = null;
            long? latestProtocol = null;
            string? minimumSdk = null;
            string? updateUrl = null;
            if (code == "PROTOCOL_UPGRADE_REQUIRED")
            {
                minimumProtocol = RequireSafePositiveInteger(claims, "minimum_protocol_version");
                latestProtocol = RequireSafePositiveInteger(claims, "latest_protocol_version");
                minimumSdk = RequireString(claims, "minimum_sdk_version");
                updateUrl = RequireString(claims, "update_url");
                if (!Uri.TryCreate(updateUrl, UriKind.Absolute, out var updateUri) || updateUri.Scheme != Uri.UriSchemeHttps)
                    throw InvalidToken("Decision update URL is invalid.");
            }

            var expectedMembers = new List<string>
            {
                "iss", "aud", "nightflyer_version", "response_code", hasDeviceId ? "device_id" : "device_jkt",
                "request_jti", "iat", "lease_disposition",
            };
            if (occupancyReleased is not null) expectedMembers.Add("occupancy_released");
            if (code == "PROTOCOL_UPGRADE_REQUIRED")
                expectedMembers.AddRange(new[] { "minimum_protocol_version", "latest_protocol_version", "minimum_sdk_version", "update_url" });
            RequireExact(claims, expectedMembers, "decision");

            return new NightflyerDecision(
                token,
                code,
                disposition,
                DateTimeOffset.FromUnixTimeSeconds(issuedAt),
                deviceId,
                deviceJkt,
                occupancyReleased,
                minimumProtocol,
                latestProtocol,
                minimumSdk,
                updateUrl);
        }

        private long ApplyTransition(string token, long previousSequence, Dictionary<string, byte[]> keys)
        {
            var verified = VerifyJws(token, "nightflyer-keyset+jwt", keys);
            var claims = verified.Claims;
            RequireExact(claims, new[] { "iss", "aud", "nightflyer_version", "old_kid", "new_kid", "new_key", "iat", "keyset_sequence" }, "key transition");
            RequireAudienceAndVersion(claims);
            var oldKid = RequireString(claims, "old_kid");
            var newKid = RequireString(claims, "new_kid");
            if (!ProtocolValidation.IsKid(oldKid) || !ProtocolValidation.IsKid(newKid) || !FixedAsciiEquals(oldKid, verified.Kid))
                throw InvalidToken("Key transition identifiers are invalid.");
            _ = RequireTimestamp(claims, "iat");
            var sequence = RequireSafePositiveInteger(claims, "keyset_sequence");
            if (sequence <= previousSequence) throw InvalidToken("Key transition sequence did not advance beyond the saved high-water mark.");

            var key = claims.GetProperty("new_key");
            RequireExact(key, new[] { "kty", "crv", "x" }, "transition key");
            if (RequireString(key, "kty") != "OKP" || RequireString(key, "crv") != "Ed25519")
                throw InvalidToken("Transition key profile is invalid.");
            var decoded = Base64Url.Decode(RequireString(key, "x"), 32);
            if (keys.TryGetValue(newKid, out var existing) && !CryptographicOperations.FixedTimeEquals(existing, decoded))
                throw InvalidToken("Key transition changes an existing key identifier.");
            keys[newKid] = decoded;
            return sequence;
        }

        private (NightflyerJsonNode Claims, string Kid) VerifyJws(
            string token,
            string type,
            IReadOnlyDictionary<string, byte[]> keys)
        {
            var parts = CompactParts(token);
            var header = ParseJson(Base64Url.Decode(parts[0]), NightflyerFailure.InvalidToken, "JWS header is not strict JSON.");
            RequireExact(header, new[] { "alg", "kid", "typ" }, "JWS header");
            var kid = RequireString(header, "kid");
            if (RequireString(header, "alg") != "EdDSA" || RequireString(header, "typ") != type || !ProtocolValidation.IsKid(kid))
                throw InvalidToken("Unexpected signed token profile.");
            if (!keys.TryGetValue(kid, out var key)) throw InvalidToken("Token signing key is not trusted.");

            var signature = Base64Url.Decode(parts[2], 64);
            if (!Ed25519Verifier.Verify(key, signature, Encoding.ASCII.GetBytes(parts[0] + "." + parts[1])))
                throw new NightflyerException(NightflyerFailure.InvalidSignature, "Nightflyer signature verification failed.");

            var claims = ParseJson(Base64Url.Decode(parts[1]), NightflyerFailure.InvalidToken, "JWS claims are not strict JSON.");
            RequireObject(claims, "JWS claims", NightflyerFailure.InvalidToken);
            if (!claims.TryGetProperty("iss", out var issuer) || issuer.Kind != NightflyerJsonValueKind.String || issuer.StringValue != _issuerOrigin.GetLeftPart(UriPartial.Authority))
                throw InvalidToken("Token issuer is not trusted.");
            return (claims, kid);
        }

        private void RequireAudienceAndVersion(NightflyerJsonNode claims)
        {
            if (RequireString(claims, "aud") != _config.SystemId || RequireInteger(claims, "nightflyer_version") != 1)
                throw InvalidToken("Signed object audience or protocol version is invalid.");
        }

        private static NightflyerProblem ParseProblem(NightflyerJsonNode value, int httpStatus)
        {
            RequireExact(value, new[] { "type", "title", "status", "detail", "code" }, "problem", NightflyerFailure.InvalidResponse);
            var type = RequireString(value, "type", NightflyerFailure.InvalidResponse);
            var title = RequireString(value, "title", NightflyerFailure.InvalidResponse);
            var status = RequireInteger(value, "status", NightflyerFailure.InvalidResponse);
            var detail = RequireString(value, "detail", NightflyerFailure.InvalidResponse);
            var code = RequireString(value, "code", NightflyerFailure.InvalidResponse);
            if (status != httpStatus || type != "about:blank" || !ResponseCodePatternValue.IsMatch(code))
                throw InvalidResponse("Problem Details framing is invalid.");
            return new NightflyerProblem(type, title, checked((int)status), detail, code);
        }

        private static NightflyerJsonNode ParseJson(byte[] value, NightflyerFailure failure, string message)
        {
            try
            {
                return NightflyerJsonNode.Parse(value);
            }
            catch (NightflyerJsonException exception)
            {
                if (exception.Duplicate) throw new NightflyerException(failure, "Duplicate JSON property.");
                throw new NightflyerException(failure, message);
            }
        }

        private static string[] CompactParts(string token)
        {
            if (string.IsNullOrEmpty(token) || token.Any(c => c > 0x7f)) throw InvalidToken("Invalid compact JWS.");
            var parts = token.Split('.');
            if (parts.Length != 3 || parts.Any(string.IsNullOrEmpty)) throw InvalidToken("Invalid compact JWS.");
            return parts;
        }

        private static void RequireObject(NightflyerJsonNode value, string name, NightflyerFailure failure = NightflyerFailure.InvalidToken)
        {
            if (value.Kind != NightflyerJsonValueKind.Object) throw new NightflyerException(failure, $"{name} is not an object.");
        }

        private static void RequireExact(
            NightflyerJsonNode value,
            IEnumerable<string> members,
            string name,
            NightflyerFailure failure = NightflyerFailure.InvalidToken)
        {
            RequireObject(value, name, failure);
            var actual = value.Properties.Select(property => property.Name).OrderBy(key => key, StringComparer.Ordinal);
            var expected = members.OrderBy(key => key, StringComparer.Ordinal);
            if (!actual.SequenceEqual(expected, StringComparer.Ordinal))
                throw new NightflyerException(failure, $"{name} has an unexpected member profile.");
        }

        private static string RequireString(NightflyerJsonNode value, string name, NightflyerFailure failure = NightflyerFailure.InvalidToken)
        {
            if (!value.TryGetProperty(name, out var property) || property.Kind != NightflyerJsonValueKind.String)
                throw new NightflyerException(failure, $"{name} must be a string.");
            return property.StringValue!;
        }

        private static long RequireInteger(NightflyerJsonNode value, string name, NightflyerFailure failure = NightflyerFailure.InvalidToken)
        {
            if (!value.TryGetProperty(name, out var property) || property.Kind != NightflyerJsonValueKind.Number || !property.TryGetInt64(out var result))
                throw new NightflyerException(failure, $"{name} must be an integer.");
            return result;
        }

        private static long RequireSafeNonNegativeInteger(NightflyerJsonNode value, string name)
        {
            var result = RequireInteger(value, name);
            if (result < 0 || result > MaxSafeInteger) throw InvalidToken($"{name} is outside the supported integer range.");
            return result;
        }

        private static long RequireSafePositiveInteger(NightflyerJsonNode value, string name)
        {
            var result = RequireSafeNonNegativeInteger(value, name);
            if (result == 0) throw InvalidToken($"{name} must be positive.");
            return result;
        }

        private static long RequireTimestamp(NightflyerJsonNode value, string name)
        {
            var result = RequireInteger(value, name);
            if (result < 0 || result > MaximumUnixTimestamp) throw InvalidToken($"{name} is outside the supported timestamp range.");
            return result;
        }

        private static IReadOnlyList<KeyValuePair<string, object?>> RequestProjection(
            string endpoint,
            IReadOnlyList<KeyValuePair<string, object?>> request)
        {
            string[] names = endpoint switch
            {
                "authorize" => new[] { "protocol_version", "sdk_version", "system", "identity_type", "version", "digest", "sl_hwid", "storage_mode", "requested_offline_seconds", "trusted_kids", "keyset_sequence", "status_sequence" },
                "renew" => new[] { "protocol_version", "sdk_version", "system", "version", "digest", "sl_hwid", "trusted_kids", "keyset_sequence", "status_sequence" },
                "status" => new[] { "protocol_version", "sdk_version", "system", "trusted_kids", "keyset_sequence", "status_sequence" },
                "end" => new[] { "protocol_version", "sdk_version", "system", "end_reason", "trusted_kids", "keyset_sequence", "status_sequence" },
                _ => throw new NightflyerException(NightflyerFailure.LocalFailure, "Unknown Nightflyer endpoint."),
            };
            var projection = new List<KeyValuePair<string, object?>>(names.Length);
            foreach (var name in names) projection.Add(new KeyValuePair<string, object?>(name, GetMember(request, name)));
            return projection;
        }

        private static string CanonicalJson(object? value) => value switch
        {
            null => "null",
            string text => CanonicalString(text),
            bool boolean => boolean ? "true" : "false",
            long number => number.ToString(CultureInfo.InvariantCulture),
            int number => number.ToString(CultureInfo.InvariantCulture),
            IEnumerable<string> array => "[" + string.Join(",", array.Select(CanonicalString)) + "]",
            IReadOnlyList<KeyValuePair<string, object?>> map => "{" + string.Join(",", map.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => CanonicalString(pair.Key) + ":" + CanonicalJson(pair.Value))) + "}",
            _ => throw new NightflyerException(NightflyerFailure.LocalFailure, "Unsupported request value in canonical projection."),
        };

        private static string CanonicalString(string value)
        {
            ProtocolValidation.RequireValidUnicode(value);
            var result = new StringBuilder(value.Length + 2);
            result.Append('"');
            foreach (var character in value)
            {
                switch (character)
                {
                    case '"': result.Append("\\\""); break;
                    case '\\': result.Append("\\\\"); break;
                    case '\b': result.Append("\\b"); break;
                    case '\t': result.Append("\\t"); break;
                    case '\n': result.Append("\\n"); break;
                    case '\f': result.Append("\\f"); break;
                    case '\r': result.Append("\\r"); break;
                    default:
                        if (character < 0x20) result.Append("\\u").Append(((int)character).ToString("x4", CultureInfo.InvariantCulture));
                        else result.Append(character);
                        break;
                }
            }
            return result.Append('"').ToString();
        }

        private static void ValidateConfig(NightflyerConfig config)
        {
            if (!ProtocolValidation.IsSystemId(config.SystemId))
                throw new NightflyerException(NightflyerFailure.Configuration, "SystemId must be 20 ASCII alphanumeric characters.");
            if (config.SdkVersion.Length is < 1 or > 64)
                throw new NightflyerException(NightflyerFailure.Configuration, "SdkVersion must contain 1 through 64 UTF-8 characters.");
            ProtocolValidation.RequireValidUnicode(config.SdkVersion);
            if (config.RequestTimeout <= TimeSpan.Zero || config.IdempotentTransportRetries is < 0 or > 5 || config.InstallationLockTimeout < TimeSpan.Zero)
                throw new NightflyerException(NightflyerFailure.Configuration, "Nightflyer timeout or retry configuration is invalid.");
            if (config.Clock is null) throw new NightflyerException(NightflyerFailure.Configuration, "A Nightflyer clock is required.");
        }

        private static void ValidateRequest(string endpoint, IReadOnlyList<KeyValuePair<string, object?>> request, long keysetSequence, long statusSequence)
        {
            if (keysetSequence < 0 || keysetSequence > MaxSafeInteger || statusSequence < 0 || statusSequence > MaxSafeInteger)
                throw new NightflyerException(NightflyerFailure.Configuration, "Sequence high-water marks are outside the supported range.");

            static string Text(IReadOnlyList<KeyValuePair<string, object?>> values, string name, int minimum, int maximum)
            {
                var found = false;
                object? raw = null;
                foreach (var pair in values)
                {
                    if (string.Equals(pair.Key, name, StringComparison.Ordinal)) { raw = pair.Value; found = true; break; }
                }
                if (!found || raw is not string text || Encoding.UTF8.GetByteCount(text) < minimum || Encoding.UTF8.GetByteCount(text) > maximum)
                    throw new NightflyerException(NightflyerFailure.Configuration, $"{name} is invalid.");
                ProtocolValidation.RequireValidUnicode(text);
                return text;
            }

            static object? Value(IReadOnlyList<KeyValuePair<string, object?>> values, string name)
            {
                foreach (var pair in values)
                {
                    if (string.Equals(pair.Key, name, StringComparison.Ordinal)) return pair.Value;
                }
                throw new NightflyerException(NightflyerFailure.Configuration, $"{name} is invalid.");
            }

            if (endpoint == "authorize")
            {
                _ = Text(request, "identity_type", 3, 7);
                _ = Text(request, "version", 0, 128);
                _ = Text(request, "digest", 0, 512);
                _ = Text(request, "sl_hwid", 1, 1024);
                _ = Text(request, "storage_mode", 6, 10);
                if (Value(request, "requested_offline_seconds") is not int seconds || seconds is < 1200 || seconds > MaximumOfflineSeconds)
                    throw new NightflyerException(NightflyerFailure.Configuration, "requestedOfflineSeconds must be between 1200 and 7776000.");
                if ((string)Value(request, "identity_type")! == "key") _ = Text(request, "license_key", 1, 160);
                else { _ = Text(request, "username", 1, 191); _ = Text(request, "password", 1, 4096); }
            }
            else
            {
                _ = Text(request, "lease", 1, 32768);
                if (endpoint == "renew")
                {
                    _ = Text(request, "version", 0, 128);
                    _ = Text(request, "digest", 0, 512);
                    _ = Text(request, "sl_hwid", 1, 1024);
                }
                if (endpoint == "end") _ = Text(request, "end_reason", 1, 128);
            }
        }

        private static bool FixedAsciiEquals(string left, string right)
        {
            var leftBytes = Encoding.ASCII.GetBytes(left);
            var rightBytes = Encoding.ASCII.GetBytes(right);
            return leftBytes.Length == rightBytes.Length && CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
        }

        private static NightflyerException InvalidToken(string message) => new(NightflyerFailure.InvalidToken, message);
        private static NightflyerException InvalidResponse(string message) => new(NightflyerFailure.InvalidResponse, message);
        private void ThrowIfDisposed() { if (_disposed) throw new ObjectDisposedException(nameof(NightflyerClient)); }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            if (_ownsTransport && _transport is IDisposable disposable) disposable.Dispose();
        }
    }
}
