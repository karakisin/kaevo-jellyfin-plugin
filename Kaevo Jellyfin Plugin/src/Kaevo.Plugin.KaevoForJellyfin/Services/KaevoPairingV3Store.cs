using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal sealed record KaevoPairingV3Identity(
    string PluginInstanceId,
    string PrivateKeyBase64Url,
    string PublicKeyBase64Url,
    string Fingerprint,
    DateTimeOffset CreatedAtUtc,
    int KeyVersion = 1,
    string RotationState = "active");

internal sealed record KaevoPairingV3Ticket(
    string TicketId,
    string ChallengeVerificationPublicKey,
    DateTimeOffset ExpiresAtUtc,
    string PluginInstanceId,
    string PluginPublicKey,
    string PluginFingerprint,
    string JellyfinServerId,
    string JellyfinServerName,
    string LocalEndpoint,
    string JellyfinSetupUserId,
    string State = "available",
    string PairingAttemptId = "",
    DateTimeOffset? ReservedAtUtc = null,
    DateTimeOffset? ReservationExpiresAtUtc = null,
    string RedemptionState = "",
    string ConnectorId = "",
    string AuthorizationJti = "",
    string AccountBinding = "",
    string FamilyBinding = "");

internal sealed record KaevoPairingV3Challenge(
    string ChallengeId,
    string TicketId,
    string PairingAttemptId,
    string PairingAuthorizationHash,
    string NonceHash,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    bool Used = false);

internal sealed record KaevoPairingV3Connector(
    string ConnectorId,
    string PluginInstanceId,
    string PluginPublicKey,
    string PluginFingerprint,
    int KeyVersion,
    string AccountBinding,
    string FamilyBinding,
    string JellyfinServerId,
    string JellyfinSetupUserProvenance,
    DateTimeOffset EnrolledAtUtc,
    string Status,
    string LastPairingAttemptId,
    string ProtocolVersion,
    string LastContactState = "");

internal sealed class KaevoPairingV3State
{
    public int SchemaVersion { get; set; } = 1;
    public KaevoPairingV3Identity? Identity { get; set; }
    public Dictionary<string, KaevoPairingV3Ticket> Tickets { get; set; } = new(StringComparer.Ordinal);
    public Dictionary<string, KaevoPairingV3Challenge> Challenges { get; set; } = new(StringComparer.Ordinal);
    public KaevoPairingV3Connector? Connector { get; set; }
}

/// <summary>V3-only durable state. It never stores ticket secrets, Cloud authorizations, or owner credentials.</summary>
internal sealed class KaevoPairingV3Store
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    // Jellyfin normally hosts one plugin process, but service recreation must
    // still share the same in-process transaction gate for this state file.
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> Gates = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _gate;
    private readonly string _directory;
    private readonly string _path;

    internal KaevoPairingV3Store(string directory)
    {
        _directory = directory;
        _path = Path.Combine(directory, "pairing-v3-state.json");
        KaevoFilePermissions.OwnerOnlyDirectory(directory);
        _gate = Gates.GetOrAdd(Path.GetFullPath(_path), _ => new SemaphoreSlim(1, 1));
    }

    internal string StatePath => _path;
    internal string DirectoryPath => _directory;

    internal static KaevoPairingV3Store ForPlugin() => new(Path.Combine(KaevoPlugin.Instance?.DataFolderPath
        ?? throw new InvalidOperationException("Kaevo plugin data folder is unavailable."), "pairing-v3"));

    internal async Task<T> MutateAsync<T>(Func<KaevoPairingV3State, T> mutation, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var state = Load();
            var result = mutation(state);
            Write(state);
            return result;
        }
        finally { _gate.Release(); }
    }

    internal async Task<T> ReadAsync<T>(Func<KaevoPairingV3State, T> read, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { return read(Load()); }
        finally { _gate.Release(); }
    }

    private KaevoPairingV3State Load()
    {
        if (!File.Exists(_path)) return new KaevoPairingV3State();
        try
        {
            var state = JsonSerializer.Deserialize<KaevoPairingV3State>(File.ReadAllBytes(_path), JsonOptions)
                ?? throw new InvalidOperationException("pairingV3StateMalformed");
            if (state.SchemaVersion != 1 || state.Tickets is null || state.Challenges is null) throw new InvalidOperationException("pairingV3StateMalformed");
            if (state.Identity is not null) ValidateIdentity(state.Identity);
            KaevoFilePermissions.OwnerOnlyFile(_path);
            return state;
        }
        catch (JsonException exception) { throw new InvalidOperationException("pairingV3StateMalformed", exception); }
    }

    private void Write(KaevoPairingV3State state)
    {
        var temporary = _path + ".tmp." + Guid.NewGuid().ToString("N");
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            { JsonSerializer.Serialize(stream, state, JsonOptions); stream.Flush(true); }
            KaevoFilePermissions.OwnerOnlyFile(temporary);
            File.Move(temporary, _path, true);
            KaevoFilePermissions.OwnerOnlyFile(_path);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    internal static KaevoPairingV3Identity NewIdentity()
    {
        var seed = RandomNumberGenerator.GetBytes(32);
        try
        {
            var publicKey = KaevoPairingV3Crypto.PublicKeyFromSeed(seed);
            return new(Guid.NewGuid().ToString("D"), KaevoPairingV3Crypto.Base64Url(seed), KaevoPairingV3Crypto.Base64Url(publicKey),
                KaevoPairingV3Crypto.Fingerprint(publicKey), DateTimeOffset.UtcNow);
        }
        finally { CryptographicOperations.ZeroMemory(seed); }
    }

    internal static void ValidateIdentity(KaevoPairingV3Identity identity)
    {
        if (!Guid.TryParseExact(identity.PluginInstanceId, "D", out _) || identity.KeyVersion < 1 || identity.RotationState is not "active" and not "rotation_pending")
            throw new InvalidOperationException("pairingV3IdentityMalformed");
        var privateKey = KaevoPairingV3Crypto.Base64UrlDecode(identity.PrivateKeyBase64Url);
        var publicKey = KaevoPairingV3Crypto.Base64UrlDecode(identity.PublicKeyBase64Url);
        if (privateKey.Length != 32 || publicKey.Length != 32 || !CryptographicOperations.FixedTimeEquals(KaevoPairingV3Crypto.PublicKeyFromSeed(privateKey), publicKey)
            || !CryptographicOperations.FixedTimeEquals(System.Text.Encoding.UTF8.GetBytes(KaevoPairingV3Crypto.Fingerprint(publicKey)), System.Text.Encoding.UTF8.GetBytes(identity.Fingerprint)))
            throw new InvalidOperationException("pairingV3IdentityMalformed");
    }
}
