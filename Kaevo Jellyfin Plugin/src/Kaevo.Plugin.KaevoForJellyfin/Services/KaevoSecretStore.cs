using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

public sealed record KaevoLocalProviderSecret(
    string BaseUrl,
    string ApiKey,
    bool Enabled = true);

public sealed record KaevoConnectorSecrets(
    string ConnectorToken,
    string PlaybackGrantKey,
    string JellyfinApiKey,
    string SonarrBaseUrl = "",
    string SonarrApiKey = "",
    Dictionary<string, KaevoLocalProviderSecret>? Providers = null)
{
    public KaevoLocalProviderSecret? GetProvider(string provider)
    {
        if (Providers is not null
            && Providers.TryGetValue(provider, out var configured))
        {
            return configured;
        }

        // Keep installations provisioned before 0.2.16 working without asking
        // the administrator to enter Sonarr again.
        if (string.Equals(provider, "sonarr", StringComparison.OrdinalIgnoreCase)
            && !string.IsNullOrWhiteSpace(SonarrBaseUrl)
            && !string.IsNullOrWhiteSpace(SonarrApiKey))
        {
            return new KaevoLocalProviderSecret(SonarrBaseUrl, SonarrApiKey, true);
        }

        return null;
    }
}

public sealed class KaevoSecretStore
{
    private readonly string _path;
    private readonly ILogger<KaevoSecretStore> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public KaevoSecretStore(ILogger<KaevoSecretStore> logger)
    {
        _logger = logger;
        var dataFolder = KaevoPlugin.Instance?.DataFolderPath
            ?? throw new InvalidOperationException("Kaevo plugin data folder is unavailable.");
        Directory.CreateDirectory(dataFolder);
        _path = Path.Combine(dataFolder, "connector-secrets.json");
    }

    public async Task<KaevoConnectorSecrets?> ReadAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!File.Exists(_path))
            {
                return null;
            }

            await using var stream = File.OpenRead(_path);
            return await JsonSerializer.DeserializeAsync<KaevoConnectorSecrets>(stream, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Kaevo connector secrets could not be read.");
            return null;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task WriteAsync(KaevoConnectorSecrets secrets, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var temporaryPath = _path + ".tmp";
            await using (var stream = File.Create(temporaryPath))
            {
                await JsonSerializer.SerializeAsync(stream, secrets, cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
            }

            File.Move(temporaryPath, _path, true);
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(_path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Delete()
    {
        if (File.Exists(_path))
        {
            File.Delete(_path);
        }
    }
}
