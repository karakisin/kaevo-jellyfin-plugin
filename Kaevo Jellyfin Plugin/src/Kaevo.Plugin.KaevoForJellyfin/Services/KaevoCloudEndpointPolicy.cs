namespace Kaevo.Plugin.KaevoForJellyfin.Services;

public static class KaevoCloudEndpointPolicy
{
    private const string ProductionApiHost = "aneohx5ff6.execute-api.us-west-2.amazonaws.com";
    private const string SecurityStageApiHost = "vsuh8a8v8i.execute-api.us-west-2.amazonaws.com";

    public static bool TryNormalize(string? value, out Uri uri)
    {
        var environment = Environment.GetEnvironmentVariable("KAEVO_CLOUD_ENVIRONMENT")?.Trim();
        if (Uri.TryCreate(value?.Trim().TrimEnd('/'), UriKind.Absolute, out var parsed)
            && string.Equals(parsed.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            && string.IsNullOrEmpty(parsed.UserInfo)
            && string.IsNullOrEmpty(parsed.Query)
            && string.IsNullOrEmpty(parsed.Fragment)
            && (parsed.IsDefaultPort || parsed.Port == 443)
            && IsApprovedHost(parsed.Host, environment))
        {
            uri = parsed;
            return true;
        }

        uri = null!;
        return false;
    }

    public static bool IsApprovedHost(string host, string? environment)
        => string.Equals(host, ProductionApiHost, StringComparison.OrdinalIgnoreCase)
            || string.Equals(host, "kaevo.app", StringComparison.OrdinalIgnoreCase)
            || host.EndsWith(".kaevo.app", StringComparison.OrdinalIgnoreCase)
            || (string.Equals(environment, "security-stage", StringComparison.Ordinal)
                && string.Equals(host, SecurityStageApiHost, StringComparison.OrdinalIgnoreCase));
}
