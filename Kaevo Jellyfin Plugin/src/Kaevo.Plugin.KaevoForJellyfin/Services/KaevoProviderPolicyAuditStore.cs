using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

public sealed class KaevoProviderPolicyAuditStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public KaevoProviderPolicyAuditStore()
    {
        var directory = Path.Combine(KaevoPlugin.Instance?.DataFolderPath
            ?? throw new InvalidOperationException("Kaevo plugin data folder is unavailable."), "audit");
        KaevoFilePermissions.OwnerOnlyDirectory(directory);
        _path = Path.Combine(directory, "provider-policy.jsonl");
    }

    internal KaevoProviderPolicyAuditStore(string directory)
    {
        KaevoFilePermissions.OwnerOnlyDirectory(directory);
        _path = Path.Combine(directory, "provider-policy.jsonl");
    }

    public async Task RecordAsync(string provider, string outcome, string securityClass, Uri? destination, string reason, CancellationToken cancellationToken)
    {
        var safeProvider = provider is "sonarr" or "radarr" or "seerr" or "sabnzbd" or "qbittorrent"
            or "lidarr" or "readarr" or "prowlarr" or "bazarr" or "tdarr" ? provider : "unknown";
        var destinationReference = destination is null ? "" : Reference(destination.Scheme + "://" + destination.IdnHost + ":" + destination.Port);
        var record = JsonSerializer.Serialize(new
        {
            timestamp = DateTimeOffset.UtcNow,
            event_type = "provider_destination_policy",
            provider = safeProvider,
            outcome = outcome is "approved" or "denied" ? outcome : "denied",
            destination_class = securityClass is "private" or "prohibited" ? securityClass : "unknown",
            destination_ref = destinationReference,
            reason = SafeReason(reason)
        }) + Environment.NewLine;
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var options = new FileStreamOptions
            {
                Mode = FileMode.Append,
                Access = FileAccess.Write,
                Share = FileShare.Read,
                Options = FileOptions.WriteThrough
            };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            await using var stream = new FileStream(_path, options);
            var bytes = Encoding.UTF8.GetBytes(record);
            await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            stream.Flush(true);
            KaevoFilePermissions.OwnerOnlyFile(_path);
        }
        finally
        {
            _gate.Release();
        }
    }

    private static string Reference(string value) => "pdr1_" + KaevoConnectorIdentity.Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes(value)))[..16];
    private static string SafeReason(string value) => value is "approved" or "invalid" or "prohibited" or "reapproval_required" ? value : "denied";
}
