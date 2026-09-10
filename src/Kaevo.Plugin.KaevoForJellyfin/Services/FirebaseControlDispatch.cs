namespace Kaevo.Plugin.KaevoForJellyfin.Services;

// A notification is only a hint. Existing signed exact-ID claims remain the
// authority to execute. No unbounded task queue, payloads or provider identity
// projection here. Preview-only until live admission and renewal are wired.
internal static class FirebaseControlDispatch
{
    internal static async Task RunAsync<T>(
        IAsyncEnumerable<string> notifications,
        Func<string, CancellationToken, Task<T?>> claim,
        Func<T, CancellationToken, Task> handle,
        Func<T, string> claimedRequestId,
        int concurrency,
        CancellationToken cancellationToken) where T : class
    {
        if (concurrency is < 1 or > 4)
            throw new InvalidOperationException("firebaseControlConcurrencyInvalid");
        using var delivery = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        await using var iterator = notifications.GetAsyncEnumerator(delivery.Token);
        var inFlight = new Dictionary<string, Task>(StringComparer.Ordinal);
        Task<bool>? receive = null;
        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                foreach (var pair in inFlight.Where(pair => pair.Value.IsCompleted).ToArray())
                {
                    await pair.Value.ConfigureAwait(false);
                    inFlight.Remove(pair.Key);
                }
                if (inFlight.Count == concurrency)
                {
                    await Task.WhenAny(inFlight.Values).WaitAsync(cancellationToken).ConfigureAwait(false);
                    continue;
                }
                receive ??= iterator.MoveNextAsync().AsTask();
                // Observe a handler failure even if no new notification arrives.
                if (inFlight.Count != 0)
                {
                    var ready = await Task.WhenAny(inFlight.Values.Append(receive))
                        .WaitAsync(cancellationToken).ConfigureAwait(false);
                    if (ready != receive) continue;
                }
                if (!await receive.WaitAsync(cancellationToken).ConfigureAwait(false)) break;
                receive = null;
                cancellationToken.ThrowIfCancellationRequested();
                var id = iterator.Current;
                if (id is null || !FirebaseFirestoreControlListener.IsRequestId(id))
                    throw new InvalidOperationException("firebaseControlSignalInvalid");
                if (inFlight.ContainsKey(id)) continue;
                // Keep exact claims serial, as in the retained WebSocket loop.
                // No handler runs when the server denies or coalesces a claim.
                var request = await claim(id, cancellationToken).ConfigureAwait(false);
                if (request is not null)
                {
                    if (claimedRequestId(request) != id)
                        throw new InvalidOperationException("firebaseControlClaimMismatch");
                    inFlight.Add(id, handle(request, cancellationToken));
                }
            }
        }
        finally
        {
            delivery.Cancel();
            // Never DisposeAsync concurrently with MoveNextAsync. The concrete
            // Firestore iterator has a bounded cancellation/cleanup deadline.
            if (receive is not null)
            {
                try { await receive.ConfigureAwait(false); }
                catch (Exception) { /* Original failure/cancellation remains authoritative. */ }
            }
            // Lease/transport loss stops new claims, not already-claimed work.
            // Host/configuration cancellation still reaches the existing handler.
            await Task.WhenAll(inFlight.Values).ConfigureAwait(false);
        }
    }
}
