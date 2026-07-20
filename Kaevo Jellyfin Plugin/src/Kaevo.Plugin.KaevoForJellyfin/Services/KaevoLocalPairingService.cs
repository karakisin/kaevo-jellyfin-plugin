using System.Security.Cryptography;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

public sealed record KaevoLocalPairingTicket(string Code, DateTimeOffset ExpiresAtUtc);

/// <summary>Maintains one short-lived, single-use setup ticket in memory only.</summary>
public sealed class KaevoLocalPairingService
{
    private readonly object _gate = new();
    private byte[]? _codeHash;
    private DateTimeOffset _expiresAtUtc;

    public KaevoLocalPairingTicket Start()
    {
        var raw = Convert.ToHexString(RandomNumberGenerator.GetBytes(5));
        var code = string.Concat(raw.AsSpan(0, 5), "-", raw.AsSpan(5, 5));
        lock (_gate)
        {
            _codeHash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(Normalize(code)));
            _expiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(10);
        }
        return new(code, _expiresAtUtc);
    }

    public bool Consume(string code)
    {
        var candidate = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(Normalize(code)));
        lock (_gate)
        {
            if (_codeHash is null || DateTimeOffset.UtcNow >= _expiresAtUtc
                || !CryptographicOperations.FixedTimeEquals(_codeHash, candidate)) return false;
            CryptographicOperations.ZeroMemory(_codeHash);
            _codeHash = null;
            _expiresAtUtc = default;
            return true;
        }
    }

    private static string Normalize(string value) => value.Trim().Replace("-", string.Empty, StringComparison.Ordinal).ToUpperInvariant();
}
