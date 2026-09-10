namespace Kaevo.Plugin.KaevoForJellyfin.Services;

public static class KaevoCloudEndpointPolicy
{
    private const string ProductionApi = "https://o25nzxe9bk.execute-api.us-west-2.amazonaws.com/production";
    private const string DevelopmentApi = "https://aneohx5ff6.execute-api.us-west-2.amazonaws.com/dev";
    private const string DevelopmentCustomApi = "https://api.kaevo.watch";
    private const string SecurityStageApi = "https://vsuh8a8v8i.execute-api.us-west-2.amazonaws.com/security-stage";

    public static bool TryNormalize(string? value, out Uri uri)
    {
        var configuration = KaevoPlugin.Instance?.Configuration;
        var environment = ResolveSavedEnvironment(
            configuration?.CloudEnvironment,
            Environment.GetEnvironmentVariable("KAEVO_CLOUD_ENVIRONMENT"),
            configuration?.CloudBaseUrl);
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

    public static bool IsApprovedHost(string host, string? environment)
    {
        var normalizedEnvironment = NormalizeEnvironment(environment);
        return normalizedEnvironment switch
        {
            "production" => HostMatches(ProductionApi, host),
            "development" => HostMatches(DevelopmentApi, host)
                || HostMatches(DevelopmentCustomApi, host)
                || HostMatches(KaevoFirebaseRuntime.Endpoint, host),
            "security-stage" => HostMatches(SecurityStageApi, host),
            _ => false
        };
    }

    internal static bool IsApprovedEndpoint(Uri uri, string environment)
    {
        var expected = environment switch
        {
            "production" => new[] { ProductionApi },
            "development" => new[] { DevelopmentApi, DevelopmentCustomApi, KaevoFirebaseRuntime.Endpoint },
            "security-stage" => new[] { SecurityStageApi },
            _ => Array.Empty<string>()
        };
        var candidate = uri.GetComponents(
            UriComponents.SchemeAndServer | UriComponents.Path,
            UriFormat.Unescaped).TrimEnd('/');
        return expected.Any(value => string.Equals(candidate, value, StringComparison.OrdinalIgnoreCase));
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

    // Older paired configurations saved the exact approved AWS URL without an
    // environment field. Recover that saved selection only when neither source
    // explicitly specifies an environment. A request URL cannot choose it.
    internal static string ResolveSavedEnvironment(string? configured, string? process, string? savedEndpoint)
    {
        if (string.IsNullOrWhiteSpace(configured) && string.IsNullOrWhiteSpace(process))
        {
            var saved = savedEndpoint?.Trim().TrimEnd('/');
            if (string.Equals(saved, DevelopmentApi, StringComparison.OrdinalIgnoreCase)
                || string.Equals(saved, DevelopmentCustomApi, StringComparison.OrdinalIgnoreCase))
                return "development";
        }
        return ResolveEnvironment(configured, process);
    }

    internal static string ResolveEnvironment(string? configuredEnvironment, string? processEnvironment)
    {
        var configured = configuredEnvironment?.Trim();
        var process = processEnvironment?.Trim();
        if (!string.IsNullOrEmpty(configured) && !string.IsNullOrEmpty(process))
        {
            var normalizedConfigured = NormalizeEnvironment(configured);
            var normalizedProcess = NormalizeEnvironment(process);
            return normalizedConfigured == normalizedProcess ? normalizedConfigured : "invalid";
        }

        return NormalizeEnvironment(!string.IsNullOrEmpty(configured) ? configured : process);
    }

    private static bool HostMatches(string endpoint, string host)
        => Uri.TryCreate(endpoint, UriKind.Absolute, out var expected)
            && string.Equals(expected.Host, host, StringComparison.OrdinalIgnoreCase);
}
