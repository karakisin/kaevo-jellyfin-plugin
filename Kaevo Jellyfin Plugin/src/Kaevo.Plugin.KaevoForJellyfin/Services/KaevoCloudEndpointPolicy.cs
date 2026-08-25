namespace Kaevo.Plugin.KaevoForJellyfin.Services;

public static class KaevoCloudEndpointPolicy
{
    private const string ProductionApi = "https://o25nzxe9bk.execute-api.us-west-2.amazonaws.com/production";
    private const string DevelopmentApi = "https://aneohx5ff6.execute-api.us-west-2.amazonaws.com/dev";
    private const string DevelopmentCustomApi = "https://api.kaevo.watch";
    private const string SecurityStageApi = "https://vsuh8a8v8i.execute-api.us-west-2.amazonaws.com/security-stage";

    public static bool TryNormalize(string? value, out Uri uri)
    {
        var environment = NormalizeEnvironment(
            Environment.GetEnvironmentVariable("KAEVO_CLOUD_ENVIRONMENT"));
        return TryNormalize(value, environment, out uri);
    }

    /// <summary>
    /// Resolves the Cloud endpoint used by an explicit Pairing V3 repair.
    /// Existing approved configuration is preserved. Missing, stale, or
    /// otherwise unapproved configuration is migrated only to the immutable
    /// endpoint compiled for the current environment.
    /// </summary>
    public static bool TryResolvePairingEndpoint(string? configuredValue, out Uri uri, out bool migrated)
    {
        var environment = NormalizeEnvironment(
            Environment.GetEnvironmentVariable("KAEVO_CLOUD_ENVIRONMENT"));
        return TryResolvePairingEndpoint(configuredValue, environment, out uri, out migrated);
    }

    public static bool IsApprovedHost(string host, string? environment)
    {
        var normalizedEnvironment = NormalizeEnvironment(environment);
        return normalizedEnvironment switch
        {
            "production" => HostMatches(ProductionApi, host),
            "development" => HostMatches(DevelopmentApi, host)
                || HostMatches(DevelopmentCustomApi, host),
            "security-stage" => HostMatches(SecurityStageApi, host),
            _ => false
        };
    }

    internal static bool IsApprovedEndpoint(Uri uri, string environment)
    {
        var expected = environment switch
        {
            "production" => new[] { ProductionApi },
            "development" => new[] { DevelopmentApi, DevelopmentCustomApi },
            "security-stage" => new[] { SecurityStageApi },
            _ => Array.Empty<string>()
        };
        var candidate = uri.GetComponents(
            UriComponents.SchemeAndServer | UriComponents.Path,
            UriFormat.Unescaped).TrimEnd('/');
        return expected.Any(value => string.Equals(candidate, value, StringComparison.OrdinalIgnoreCase));
    }

    internal static bool TryResolvePairingEndpoint(
        string? configuredValue,
        string? environment,
        out Uri uri,
        out bool migrated)
    {
        var normalizedEnvironment = NormalizeEnvironment(environment);
        if (TryNormalize(configuredValue, normalizedEnvironment, out uri))
        {
            migrated = false;
            return true;
        }

        var primaryEndpoint = normalizedEnvironment switch
        {
            "production" => ProductionApi,
            "development" => DevelopmentApi,
            "security-stage" => SecurityStageApi,
            _ => null
        };
        if (primaryEndpoint is not null
            && Uri.TryCreate(primaryEndpoint, UriKind.Absolute, out var primaryUri)
            && primaryUri is not null)
        {
            uri = primaryUri;
            migrated = true;
            return true;
        }

        uri = null!;
        migrated = false;
        return false;
    }

    internal static string NormalizeEnvironment(string? environment)
    {
        return environment?.Trim().ToLowerInvariant() switch
        {
            null or "" or "production" => "production",
            "dev" or "development" or "internal-qa" => "development",
            "security-stage" => "security-stage",
            _ => "invalid"
        };
    }

    private static bool HostMatches(string endpoint, string host)
        => Uri.TryCreate(endpoint, UriKind.Absolute, out var expected)
            && string.Equals(expected.Host, host, StringComparison.OrdinalIgnoreCase);

    private static bool TryNormalize(string? value, string environment, out Uri uri)
    {
        if (Uri.TryCreate(value?.Trim().TrimEnd('/'), UriKind.Absolute, out var parsed)
            && string.Equals(parsed.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            && string.IsNullOrEmpty(parsed.UserInfo)
            && string.IsNullOrEmpty(parsed.Query)
            && string.IsNullOrEmpty(parsed.Fragment)
            && (parsed.IsDefaultPort || parsed.Port == 443)
            && IsApprovedEndpoint(parsed, environment))
        {
            uri = parsed;
            return true;
        }

        uri = null!;
        return false;
    }
}
