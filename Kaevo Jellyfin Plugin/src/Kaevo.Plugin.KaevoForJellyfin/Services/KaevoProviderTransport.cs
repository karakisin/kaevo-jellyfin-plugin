using System.Net;
using System.Net.Sockets;
using System.Collections.Concurrent;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

public sealed class KaevoProviderTransport : IDisposable
{
    private readonly KaevoProviderDestinationPolicy _policy;
    private readonly ConcurrentDictionary<string, HttpClient> _clients = new(StringComparer.Ordinal);

    public KaevoProviderTransport(KaevoProviderDestinationPolicy policy) => _policy = policy;

    public async Task<HttpResponseMessage> SendAsync(
        string provider,
        KaevoLocalProviderSecret secret,
        HttpRequestMessage request,
        HttpCompletionOption completion,
        CancellationToken cancellationToken)
    {
        if (request.RequestUri is null) throw new InvalidOperationException("providerDestinationMissing");
        var current = request;
        for (var hop = 0; hop <= 3; hop++)
        {
            var addresses = await _policy.RevalidateAsync(provider, secret, current.RequestUri!, cancellationToken).ConfigureAwait(false);
            var selected = addresses[0];
            var cacheKey = current.RequestUri!.Scheme + "://" + current.RequestUri.IdnHost + ":" + current.RequestUri.Port
                + "|" + string.Join(',', addresses.Select(static value => value.ToString()).Order(StringComparer.Ordinal));
            var client = _clients.GetOrAdd(cacheKey, _ => CreateClient(selected));
            var response = await client.SendAsync(current, completion, cancellationToken).ConfigureAwait(false);
            if ((int)response.StatusCode is < 300 or >= 400 || response.Headers.Location is null)
            {
                return response;
            }
            if (request.Method != HttpMethod.Get && request.Method != HttpMethod.Head)
            {
                return response;
            }
            if (hop == 3)
            {
                response.Dispose();
                throw new InvalidOperationException("providerRedirectLimitExceeded");
            }
            var target = _policy.ValidateRedirect(provider, secret, current.RequestUri!, response.Headers.Location);
            response.Dispose();
            var redirected = new HttpRequestMessage(request.Method, target);
            foreach (var header in request.Headers)
            {
                redirected.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
            if (!ReferenceEquals(current, request)) current.Dispose();
            current = redirected;
        }
        throw new InvalidOperationException("providerRedirectLimitExceeded");
    }

    private static HttpClient CreateClient(IPAddress selected)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            PooledConnectionLifetime = TimeSpan.FromMinutes(1),
            ConnectCallback = async (context, token) =>
            {
                var socket = new Socket(selected.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    await socket.ConnectAsync(new IPEndPoint(selected, context.DnsEndPoint.Port), token).ConfigureAwait(false);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            }
        };
        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
    }

    public void Dispose()
    {
        foreach (var client in _clients.Values) client.Dispose();
        _clients.Clear();
    }
}
