using Kaevo.Plugin.KaevoForJellyfin.Configuration;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal static class KaevoFirebaseRuntime
{
    internal const string Endpoint = "https://kaevo-development-mobile-9z2mf5rz.wl.gateway.dev";
    internal const string ProjectId = "project-d2d72828-62c4-48d1-8ca";

    internal static bool IsConnectorTarget(Uri uri) => uri.IsAbsoluteUri
        && string.Equals(uri.AbsoluteUri, Endpoint + "/", StringComparison.Ordinal);
    // Public Firebase project identifier, restricted to Identity Toolkit.
    // This key grants no connector, user, profile or database authority.
    internal const string AuthenticationApiKey = "AIzaSyAUo7cCsNHpmG9oWku8tMwVV4Kr5BQfLX4";

    internal static bool IsSelected(PluginConfiguration configuration)
    {
        var environment = KaevoCloudEndpointPolicy.ResolveEnvironment(configuration.CloudEnvironment,
            Environment.GetEnvironmentVariable("KAEVO_CLOUD_ENVIRONMENT"));
        return environment == "development"
            && Uri.TryCreate(configuration.CloudBaseUrl, UriKind.Absolute, out var uri)
            && KaevoCloudEndpointPolicy.IsApprovedEndpoint(uri, environment)
            && string.Equals(uri.AbsoluteUri.TrimEnd('/'), Endpoint, StringComparison.Ordinal);
    }

    internal static void RequireAdmission(FirebaseControlAdmission admission)
    {
        admission.Check();
        if (!admission.ActivationAllowed) throw new InvalidOperationException("firebaseControlNotActivated");
    }
}
