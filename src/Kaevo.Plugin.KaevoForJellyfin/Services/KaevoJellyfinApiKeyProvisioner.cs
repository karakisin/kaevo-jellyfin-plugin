using MediaBrowser.Controller.Security;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

public sealed class KaevoJellyfinApiKeyProvisioner
{
    internal const string ApiKeyName = "Kaevo Jellyfin Plugin";

    private readonly IAuthenticationManager _authenticationManager;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public KaevoJellyfinApiKeyProvisioner(IAuthenticationManager authenticationManager)
    {
        _authenticationManager = authenticationManager;
    }

    internal async Task<string> EnsureAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var accessToken = SelectExisting(await _authenticationManager.GetApiKeys().ConfigureAwait(false));
            if (!string.IsNullOrWhiteSpace(accessToken))
            {
                return accessToken;
            }

            await _authenticationManager.CreateApiKey(ApiKeyName).ConfigureAwait(false);
            accessToken = SelectExisting(await _authenticationManager.GetApiKeys().ConfigureAwait(false));
            return !string.IsNullOrWhiteSpace(accessToken)
                ? accessToken
                : throw new InvalidOperationException("jellyfinApiKeyProvisioningFailed");
        }
        finally
        {
            _gate.Release();
        }
    }

    internal static string SelectExisting(IReadOnlyList<AuthenticationInfo> apiKeys)
        => apiKeys
            .Where(key => string.Equals(key.AppName, ApiKeyName, StringComparison.Ordinal)
                && !string.IsNullOrWhiteSpace(key.AccessToken))
            .OrderByDescending(key => key.DateCreated)
            .Select(key => key.AccessToken)
            .FirstOrDefault() ?? string.Empty;
}
