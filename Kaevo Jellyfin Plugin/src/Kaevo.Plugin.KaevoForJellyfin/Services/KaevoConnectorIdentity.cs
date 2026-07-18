using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

public sealed class KaevoConnectorIdentity : IDisposable
{
    private readonly ECDsa _key;

    private KaevoConnectorIdentity(ECDsa key) => _key = key;

    public static KaevoConnectorIdentity LoadOrCreate(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        if (File.Exists(path))
        {
            key.ImportFromPem(File.ReadAllText(path));
            if (key.KeySize != 256)
            {
                key.Dispose();
                throw new InvalidOperationException("connectorIdentityKeyTypeInvalid");
            }
        }
        else
        {
            var bytes = Encoding.ASCII.GetBytes(key.ExportPkcs8PrivateKeyPem());
            using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
            stream.Write(bytes);
            stream.Flush(true);
        }

        KaevoFilePermissions.OwnerOnlyFile(path);
        return new KaevoConnectorIdentity(key);
    }

    public IReadOnlyDictionary<string, string> PublicJwk
    {
        get
        {
            var parameters = _key.ExportParameters(false);
            return new SortedDictionary<string, string>(StringComparer.Ordinal)
            {
                ["crv"] = "P-256",
                ["kty"] = "EC",
                ["x"] = Base64Url(parameters.Q.X!),
                ["y"] = Base64Url(parameters.Q.Y!)
            };
        }
    }

    public string Thumbprint
    {
        get
        {
            var canonical = JsonSerializer.Serialize(PublicJwk);
            return Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
        }
    }

    public string CreateProof(HttpMethod method, Uri absoluteUri, long? now = null, string? jti = null)
    {
        if (!absoluteUri.IsAbsoluteUri)
        {
            throw new ArgumentException("dpopAbsoluteUriRequired", nameof(absoluteUri));
        }

        var header = Base64Url(JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object>
        {
            ["alg"] = "ES256", ["jwk"] = PublicJwk, ["typ"] = "dpop+jwt"
        }));
        var payload = Base64Url(JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object>
        {
            ["htm"] = method.Method.ToUpperInvariant(),
            ["htu"] = absoluteUri.AbsoluteUri,
            ["iat"] = now ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["jti"] = jti ?? Guid.NewGuid().ToString()
        }));
        var signingInput = Encoding.ASCII.GetBytes(header + "." + payload);
        var signature = _key.SignData(signingInput, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return header + "." + payload + "." + Base64Url(signature);
    }

    internal static string Base64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public void Dispose() => _key.Dispose();
}

internal static class KaevoFilePermissions
{
    internal static void OwnerOnlyDirectory(string path)
    {
        Directory.CreateDirectory(path);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    internal static void OwnerOnlyFile(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }
}
