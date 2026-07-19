using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

public interface IKaevoDnsResolver
{
    Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken);
}

public sealed class KaevoSystemDnsResolver : IKaevoDnsResolver
{
    public async Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        return await Dns.GetHostAddressesAsync(host, timeout.Token).ConfigureAwait(false);
    }
}

public sealed record KaevoApprovedDestination(Uri BaseUri, string[] Addresses, string SecurityClass);

public sealed class KaevoProviderDestinationPolicy
{
    private static readonly IReadOnlyDictionary<string, HashSet<int>> ProviderPorts =
        new Dictionary<string, HashSet<int>>(StringComparer.OrdinalIgnoreCase)
        {
            ["sonarr"] = new() { 80, 443, 8989 },
            ["radarr"] = new() { 80, 443, 7878 },
            ["seerr"] = new() { 80, 443, 5055 },
            ["sabnzbd"] = new() { 80, 443, 8080 },
            ["qbittorrent"] = new() { 80, 443, 8080 },
            ["lidarr"] = new() { 80, 443, 8686 },
            ["readarr"] = new() { 80, 443, 8787 },
            ["prowlarr"] = new() { 80, 443, 9696 },
            ["bazarr"] = new() { 80, 443, 6767 },
            ["tdarr"] = new() { 80, 443, 8265 }
        };

    private readonly IKaevoDnsResolver _dns;
    private readonly HashSet<string> _stagingHosts;
    private readonly bool _staging;

    public KaevoProviderDestinationPolicy()
        : this(new KaevoSystemDnsResolver(),
            string.Equals(Environment.GetEnvironmentVariable("KAEVO_CLOUD_ENVIRONMENT"), "security-stage", StringComparison.Ordinal),
            (Environment.GetEnvironmentVariable("KAEVO_PROVIDER_STAGING_ALLOWLIST") ?? string.Empty)
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
    {
    }

    internal KaevoProviderDestinationPolicy(IKaevoDnsResolver dns, bool staging = false, IEnumerable<string>? stagingHosts = null)
    {
        _dns = dns;
        _staging = staging;
        _stagingHosts = new HashSet<string>(stagingHosts ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
    }

    public async Task<KaevoApprovedDestination> ApproveAsync(string provider, string raw, CancellationToken cancellationToken)
    {
        var uri = Normalize(provider, raw);
        var addresses = await ResolveAndValidateAsync(uri.Host, cancellationToken).ConfigureAwait(false);
        if (_staging && !_stagingHosts.Contains(uri.IdnHost))
        {
            throw new ArgumentException("providerDestinationNotStagingMock");
        }
        return new KaevoApprovedDestination(uri, addresses.Select(static value => value.ToString()).Order(StringComparer.Ordinal).ToArray(), "private");
    }

    public async Task<IPAddress[]> RevalidateAsync(string provider, KaevoLocalProviderSecret secret, Uri requestUri, CancellationToken cancellationToken)
    {
        var approved = Normalize(provider, secret.BaseUrl);
        if (!SameOrigin(approved, requestUri) || !IsWithinBasePath(approved, requestUri))
        {
            throw new InvalidOperationException("providerDestinationEscaped");
        }
        var current = await ResolveAndValidateAsync(approved.Host, cancellationToken).ConfigureAwait(false);
        var currentText = current.Select(static value => value.ToString()).Order(StringComparer.Ordinal).ToArray();
        var saved = (secret.ApprovedAddresses ?? Array.Empty<string>()).Order(StringComparer.Ordinal).ToArray();
        if (saved.Length == 0 || !saved.SequenceEqual(currentText, StringComparer.Ordinal))
        {
            throw new InvalidOperationException("providerDestinationReapprovalRequired");
        }
        return current;
    }

    public Uri ValidateRedirect(string provider, KaevoLocalProviderSecret secret, Uri from, Uri location)
    {
        var target = location.IsAbsoluteUri ? location : new Uri(from, location);
        var escapedPath = target.GetComponents(UriComponents.Path, UriFormat.UriEscaped);
        if (escapedPath.Contains("%2e", StringComparison.OrdinalIgnoreCase)
            || escapedPath.Contains("%2f", StringComparison.OrdinalIgnoreCase)
            || escapedPath.Contains("%5c", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("providerRedirectRejected");
        }
        var approved = Normalize(provider, secret.BaseUrl);
        if (!SameOrigin(approved, target) || !IsWithinBasePath(approved, target)
            || (from.Scheme == Uri.UriSchemeHttps && target.Scheme != Uri.UriSchemeHttps))
        {
            throw new InvalidOperationException("providerRedirectRejected");
        }
        return target;
    }

    internal static Uri Normalize(string provider, string raw)
    {
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            || string.IsNullOrWhiteSpace(uri.Host)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Fragment)
            || uri.Host.Contains('%', StringComparison.Ordinal)
            || uri.Host is "*" or "+")
        {
            throw new ArgumentException("providerDestinationInvalid");
        }
        if (LooksLikeAlternateNumericAddress(uri.Host))
        {
            throw new ArgumentException("providerDestinationNumericEncodingRejected");
        }
        var idn = new IdnMapping().GetAscii(uri.IdnHost.TrimEnd('.')).ToLowerInvariant();
        if (string.IsNullOrEmpty(idn)) throw new ArgumentException("providerDestinationInvalid");
        var port = uri.IsDefaultPort ? (uri.Scheme == Uri.UriSchemeHttps ? 443 : 80) : uri.Port;
        if (port is < 1 or > 65535 || !ProviderPorts.TryGetValue(provider, out var ports) || !ports.Contains(port))
        {
            throw new ArgumentException("providerPortNotApproved");
        }
        var builder = new UriBuilder(uri.Scheme.ToLowerInvariant(), idn, port)
        {
            Path = string.IsNullOrEmpty(uri.AbsolutePath) ? "/" : uri.AbsolutePath.TrimEnd('/') + "/",
            Query = string.Empty,
            Fragment = string.Empty
        };
        return builder.Uri;
    }

    internal static bool IsProhibited(IPAddress input)
    {
        var address = input.IsIPv4MappedToIPv6 ? input.MapToIPv4() : input;
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)
            || address.Equals(IPAddress.Broadcast)) return true;
        var b = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return b[0] == 0 || b[0] == 127 || b[0] >= 224
                || (b[0] == 169 && b[1] == 254)
                || (b[0] == 100 && b[1] is >= 64 and <= 127)
                || (b[0] == 198 && b[1] is 18 or 19);
        }
        if (address.IsIPv6LinkLocal || address.IsIPv6Multicast || address.IsIPv6SiteLocal) return true;
        if ((b[0] & 0xfe) == 0xfc) return false;
        return true;
    }

    internal static bool IsPrivate(IPAddress input)
    {
        var address = input.IsIPv4MappedToIPv6 ? input.MapToIPv4() : input;
        if (IsProhibited(address)) return false;
        var b = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return b[0] == 10 || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168);
        }
        return (b[0] & 0xfe) == 0xfc;
    }

    private async Task<IPAddress[]> ResolveAndValidateAsync(string host, CancellationToken cancellationToken)
    {
        IPAddress[] addresses;
        if (IPAddress.TryParse(host, out var literal)) addresses = new[] { literal };
        else addresses = await _dns.ResolveAsync(host, cancellationToken).ConfigureAwait(false);
        if (addresses.Length == 0 || addresses.Any(IsProhibited) || addresses.Any(static value => !IsPrivate(value)))
        {
            throw new ArgumentException("providerDestinationProhibited");
        }
        return addresses.Distinct().OrderBy(static value => value.ToString(), StringComparer.Ordinal).ToArray();
    }

    private static bool SameOrigin(Uri left, Uri right) =>
        string.Equals(left.Scheme, right.Scheme, StringComparison.OrdinalIgnoreCase)
        && string.Equals(left.IdnHost.TrimEnd('.'), right.IdnHost.TrimEnd('.'), StringComparison.OrdinalIgnoreCase)
        && left.Port == right.Port;

    private static bool IsWithinBasePath(Uri approved, Uri target) =>
        target.AbsolutePath.StartsWith(approved.AbsolutePath, StringComparison.Ordinal);

    private static bool LooksLikeAlternateNumericAddress(string host)
    {
        if (IPAddress.TryParse(host, out _)) return false;
        var labels = host.Split('.');
        return labels.All(static label => label.Length > 0 && (label.All(char.IsDigit)
            || label.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            || (label.Length > 1 && label[0] == '0' && label.All(char.IsDigit))));
    }
}
