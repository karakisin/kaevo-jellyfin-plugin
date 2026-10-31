using System.Net;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Text;
using Google.Cloud.Firestore.V1;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

// Transport recovery only: every hint still goes through the existing signed claim.
internal static class FirebaseControlReadFallback
{
    private static readonly HttpClient Client = new(new HttpClientHandler { AllowAutoRedirect = false })
    { Timeout = TimeSpan.FromSeconds(6), DefaultRequestVersion = HttpVersion.Version11,
        DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact };

    internal static async IAsyncEnumerable<string> ReadAsync(
        Func<CancellationToken, IAsyncEnumerable<string>> live,
        Func<CancellationToken, Task<IReadOnlyList<string>>> read,
        Func<TimeSpan> silence, DateTimeOffset expiry,
        [EnumeratorCancellation] CancellationToken cancellationToken,
        TimeSpan? stallWindow = null, TimeSpan? pollInterval = null, Action? beganFallback = null)
    {
        var remaining = expiry - DateTimeOffset.UtcNow;
        if (remaining <= TimeSpan.Zero || remaining > TimeSpan.FromSeconds(300))
            throw FirebaseFirestoreControlListener.Failure("firebaseControlAdmissionInvalid");
        using var lease = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        lease.CancelAfter(remaining);
        using var liveStop = CancellationTokenSource.CreateLinkedTokenSource(lease.Token);
        var window = stallWindow ?? TimeSpan.FromSeconds(8);
        var reader = live(liveStop.Token).GetAsyncEnumerator(liveStop.Token);
        Task<bool>? pending = null;
        string? handoffHint = null;
        try
        {
            while (!lease.IsCancellationRequested)
            {
                bool next;
                pending ??= reader.MoveNextAsync().AsTask();
                var wait = window - silence();
                if (wait <= TimeSpan.Zero && !pending.IsCompleted) break;
                try { next = await pending.WaitAsync(wait > TimeSpan.Zero ? wait : TimeSpan.FromMilliseconds(1), lease.Token).ConfigureAwait(false); }
                catch (TimeoutException)
                {
                    if (silence() < window) continue;
                    break;
                }
                catch (InvalidOperationException error) when (error.Message is
                    "firebaseControlTransportFailed" or "firebaseControlDisconnected") { break; }
                pending = null;
                if (!next) break;
                lease.Token.ThrowIfCancellationRequested();
                yield return reader.Current;
            }
        }
        finally
        {
            liveStop.Cancel();
            // The listener has a bounded two-second target removal. Await its
            // pending move before disposing: async iterators cannot be disposed concurrently.
            try
            {
                if (pending is not null)
                    try { if (await pending.ConfigureAwait(false)) handoffHint = reader.Current; }
                    catch (InvalidOperationException error) when (error.Message is
                        "firebaseControlAccessDenied" or "firebaseControlSignalInvalid" or "firebaseControlAdmissionInvalid" or "firebaseControlTargetLost") { throw; }
                    catch (Exception) { }
            }
            finally { await reader.DisposeAsync().ConfigureAwait(false); }
        }
        lease.Token.ThrowIfCancellationRequested();
        if (handoffHint is not null) yield return handoffHint;
        beganFallback?.Invoke();
        while (true)
        {
            lease.Token.ThrowIfCancellationRequested();
            if (DateTimeOffset.UtcNow >= expiry)
                throw FirebaseFirestoreControlListener.Failure("firebaseControlLeaseExpired");
            var ids = await read(lease.Token).ConfigureAwait(false);
            foreach (var id in ids)
            {
                lease.Token.ThrowIfCancellationRequested();
                yield return id;
            }
            await Task.Delay(pollInterval ?? TimeSpan.FromSeconds(3), lease.Token).ConfigureAwait(false);
        }
    }

    internal static async Task<IReadOnlyList<string>> ReadDocumentAsync(
        string project, string channel, string epoch, string token, DateTimeOffset expiry,
        FirebaseFirestoreSignalState state, Action<Document>? acceptSnapshot, CancellationToken cancellationToken,
        HttpClient? client = null)
    {
        if (project is not (FirebaseFirestoreControlListener.DevelopmentProject or FirebaseFirestoreControlListener.DemoProject)
            || !FirebaseFirestoreControlListener.IsOpaque(channel, 43)
            || !FirebaseFirestoreControlListener.IsOpaque(epoch, 32)
            || token.Length is < 1 or > 7000 || token.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_' or '.'))
            || expiry <= DateTimeOffset.UtcNow || expiry > DateTimeOffset.UtcNow.AddSeconds(300))
            throw FirebaseFirestoreControlListener.Failure("firebaseControlAdmissionInvalid");
        var path = $"projects/{project}/databases/(default)/documents/connector_signals/{channel}";
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Min(6, (expiry - DateTimeOffset.UtcNow).TotalSeconds)));
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://firestore.googleapis.com/v1/" + path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await (client ?? Client).SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            throw FirebaseFirestoreControlListener.Failure("firebaseControlAccessDenied");
        if (!response.IsSuccessStatusCode)
            throw FirebaseFirestoreControlListener.Failure("firebaseControlTransportFailed");
        await using var body = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
        using var bytes = new MemoryStream();
        var buffer = new byte[8192];
        int count;
        while ((count = await body.ReadAsync(buffer, timeout.Token).ConfigureAwait(false)) > 0)
        {
            if (bytes.Length + count > 131072)
                throw FirebaseFirestoreControlListener.Failure("firebaseControlSignalInvalid");
            bytes.Write(buffer, 0, count);
        }
        Document document;
        try { document = Document.Parser.ParseJson(Encoding.UTF8.GetString(bytes.ToArray())); }
        catch (Exception) { throw FirebaseFirestoreControlListener.Failure("firebaseControlSignalInvalid"); }
        timeout.Token.ThrowIfCancellationRequested();
        if (DateTimeOffset.UtcNow >= expiry)
            throw FirebaseFirestoreControlListener.Failure("firebaseControlLeaseExpired");
        var ids = state.Accept(document);
        acceptSnapshot?.Invoke(document);
        return ids;
    }
}
