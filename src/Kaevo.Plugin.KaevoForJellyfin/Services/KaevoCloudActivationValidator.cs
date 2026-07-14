using System.Text.RegularExpressions;
using Kaevo.Plugin.KaevoForJellyfin.Models;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

public sealed record KaevoValidatedCloudActivation(
    string CloudBaseUrl,
    string ProfileId,
    string ConnectorId,
    string PairingCode,
    string JellyfinUserId,
    string JellyfinAccessToken);

public static partial class KaevoCloudActivationValidator
{
    public static KaevoValidatedCloudActivation Validate(KaevoCloudActivationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var cloudBaseUrl = request.CloudBaseUrl?.Trim().TrimEnd('/') ?? string.Empty;
        if (!Uri.TryCreate(cloudBaseUrl, UriKind.Absolute, out var cloudUri)
            || !string.Equals(cloudUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(cloudUri.UserInfo)
            || !string.IsNullOrEmpty(cloudUri.Query)
            || !string.IsNullOrEmpty(cloudUri.Fragment)
            || (!cloudUri.IsDefaultPort && cloudUri.Port != 443)
            || !IsApprovedCloudHost(cloudUri.Host))
        {
            throw new ArgumentException("cloudServiceUnavailable");
        }

        var profileId = RequireMatch(request.ProfileId, ProfileIdRegex(), "profileInvalid");
        var connectorId = RequireMatch(request.ConnectorId, ConnectorIdRegex(), "pairingInvalid");
        var pairingCode = RequireMatch(request.PairingCode?.ToUpperInvariant(), PairingCodeRegex(), "pairingInvalid");
        var jellyfinUserId = RequireMatch(request.JellyfinUserId, JellyfinUserIdRegex(), "accountInvalid");
        var jellyfinAccessToken = request.JellyfinAccessToken?.Trim() ?? string.Empty;
        if (jellyfinAccessToken.Length is < 16 or > 512 || jellyfinAccessToken.Any(char.IsWhiteSpace))
        {
            throw new ArgumentException("accountInvalid");
        }

        return new KaevoValidatedCloudActivation(
            cloudBaseUrl,
            profileId,
            connectorId,
            pairingCode,
            jellyfinUserId,
            jellyfinAccessToken);
    }

    private static bool IsApprovedCloudHost(string host)
        => string.Equals(host, "aneohx5ff6.execute-api.us-west-2.amazonaws.com", StringComparison.OrdinalIgnoreCase)
            || string.Equals(host, "kaevo.app", StringComparison.OrdinalIgnoreCase)
            || host.EndsWith(".kaevo.app", StringComparison.OrdinalIgnoreCase);

    private static string RequireMatch(string? value, Regex regex, string error)
    {
        var normalized = value?.Trim() ?? string.Empty;
        if (!regex.IsMatch(normalized))
        {
            throw new ArgumentException(error);
        }

        return normalized;
    }

    [GeneratedRegex("^[A-Za-z0-9_-]{1,128}$", RegexOptions.CultureInvariant)]
    private static partial Regex ProfileIdRegex();

    [GeneratedRegex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$", RegexOptions.CultureInvariant)]
    private static partial Regex ConnectorIdRegex();

    [GeneratedRegex("^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$", RegexOptions.CultureInvariant)]
    private static partial Regex PairingCodeRegex();

    [GeneratedRegex("^[0-9a-fA-F]{32}$", RegexOptions.CultureInvariant)]
    private static partial Regex JellyfinUserIdRegex();
}