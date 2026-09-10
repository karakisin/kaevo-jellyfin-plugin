using System.Runtime.CompilerServices;
using Google.Api.Gax.Grpc;
using Google.Cloud.Firestore.V1;
using Grpc.Core;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

// Not selected by the installed control loop. Activation requires an approved
// backend handoff, authenticated channel receipt and existing exact-ID claims.
internal static class FirebaseFirestoreControlListener
{
    internal const string DevelopmentProject = "project-d2d72828-62c4-48d1-8ca";
    internal const string DemoProject = "demo-kaevo-migration";

    internal static FirestoreClient CreateDevelopmentClient() => new FirestoreClientBuilder
    {
        Endpoint = "firestore.googleapis.com:443",
        ChannelCredentials = new SslCredentials(), // Explicit TLS, never ADC.
        GrpcChannelOptions = GrpcChannelOptions.Empty.WithMaxReceiveMessageSize(32768),
    }.Build();

    internal static async IAsyncEnumerable<string> ReadAsync(
        FirestoreClient client, string project, string channel, string epoch,
        string idToken, DateTimeOffset leaseExpiry,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var remaining = leaseExpiry - DateTimeOffset.UtcNow;
        if (project is not (DevelopmentProject or DemoProject)
            || channel is null || epoch is null || !IsOpaque(channel, 43) || !IsOpaque(epoch, 32)
            || idToken is null || idToken.Length is < 1 or > 7000
            || idToken.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_' or '.'))
            || remaining <= TimeSpan.Zero || remaining > TimeSpan.FromSeconds(300))
            throw Failure("firebaseControlAdmissionInvalid");
        var database = $"projects/{project}/databases/(default)";
        var path = database + "/documents/connector_signals/" + channel;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(remaining); // Monotonic cancellation also bounds an idle stream.
        // Stop delivery at the lease boundary, then allow at most two seconds
        // to remove the target before hard-cancelling the underlying RPC.
        using var transportDeadline = new CancellationTokenSource(remaining + TimeSpan.FromSeconds(2));
        var settings = CallSettings.FromCancellationToken(transportDeadline.Token)
            .WithHeader("authorization", "Bearer " + idToken)
            .WithHeader("google-cloud-resource-prefix", database);
        using var stream = client.Listen(settings);
        try
        {
            await stream.WriteAsync(new ListenRequest
            {
                Database = database,
                AddTarget = new Target { TargetId = 1,
                    Documents = new Target.Types.DocumentsTarget { Documents = { path } } },
            }).WaitAsync(deadline.Token).ConfigureAwait(false);
        }
        catch (Exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw Failure("firebaseControlTransportFailed");
        }

        var state = new FirebaseFirestoreSignalState(path, epoch);
        var responses = stream.GetResponseStream();
        Task<bool>? pendingRead = null;
        try
        {
            while (true)
            {
                bool next;
                try
                {
                    pendingRead = responses.MoveNextAsync(CancellationToken.None).AsTask();
                    next = await pendingRead.WaitAsync(deadline.Token).ConfigureAwait(false);
                    pendingRead = null;
                }
                catch (Exception error)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (error is RpcException { StatusCode: StatusCode.PermissionDenied })
                        throw Failure("firebaseControlAccessDenied");
                    throw Failure(deadline.IsCancellationRequested ? "firebaseControlLeaseExpired" : "firebaseControlTransportFailed");
                }
                cancellationToken.ThrowIfCancellationRequested();
                if (deadline.IsCancellationRequested || DateTimeOffset.UtcNow >= leaseExpiry)
                    throw Failure("firebaseControlLeaseExpired");
                if (!next) throw Failure("firebaseControlDisconnected");
                var response = responses.Current;
                if (response.TargetChange is { } target)
                {
                    if (target.Cause?.Code == 7) throw Failure("firebaseControlAccessDenied");
                    if (target.Cause?.Code is > 0 || target.TargetIds.Any(id => id != 1)
                        || target.TargetChangeType is not (TargetChange.Types.TargetChangeType.NoChange
                            or TargetChange.Types.TargetChangeType.Add or TargetChange.Types.TargetChangeType.Current))
                        throw Failure("firebaseControlTargetLost");
                    continue;
                }
                if (response.Filter is { TargetId: 1, Count: 1 }) continue;
                if (response.DocumentChange is not { } change
                    || change.TargetIds.Count != 1 || change.TargetIds[0] != 1 || change.RemovedTargetIds.Count != 0)
                    throw Failure("firebaseControlSignalInvalid");
                // Validate the entire snapshot before exposing even its first ID.
                foreach (var id in state.Accept(change.Document))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (deadline.IsCancellationRequested || DateTimeOffset.UtcNow >= leaseExpiry)
                        throw Failure("firebaseControlLeaseExpired");
                    yield return id;
                }
            }
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            try
            {
                await stream.WriteAsync(new ListenRequest { Database = database, RemoveTarget = 1 })
                    .WaitAsync(cleanup.Token).ConfigureAwait(false);
                var read = pendingRead ?? responses.MoveNextAsync(CancellationToken.None).AsTask();
                while (await read.WaitAsync(cleanup.Token).ConfigureAwait(false))
                {
                    if (responses.Current.TargetChange?.TargetChangeType == TargetChange.Types.TargetChangeType.Remove)
                        break;
                    read = responses.MoveNextAsync(CancellationToken.None).AsTask();
                }
                await stream.WriteCompleteAsync().WaitAsync(cleanup.Token).ConfigureAwait(false);
            }
            catch (Exception) { /* Bounded best-effort cleanup; no provider diagnostics. */ }
        }
    }

    internal static bool IsOpaque(string value, int length) => value.Length == length
        && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    internal static bool IsRequestId(string value) => value.Length is >= 1 and <= 128
        && char.IsAsciiLetterOrDigit(value[0])
        && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or ':');

    internal static InvalidOperationException Failure(string category) => new(category);
}

internal sealed class FirebaseFirestoreSignalState(string path, string epoch)
{
    private long revision = -1;
    private string[] previous = [];

    internal IReadOnlyList<string> Accept(Document document)
    {
        if (document.Name != path || document.Fields.Count != 3
            || !document.Fields.TryGetValue("epoch", out var actualEpoch)
            || actualEpoch.ValueTypeCase != Value.ValueTypeOneofCase.StringValue || actualEpoch.StringValue != epoch
            || !document.Fields.TryGetValue("revision", out var version)
            || version.ValueTypeCase != Value.ValueTypeOneofCase.IntegerValue
            || version.IntegerValue is < 0 or > 9007199254740991 || version.IntegerValue < revision
            || !document.Fields.TryGetValue("request_ids", out var ids)
            || ids.ValueTypeCase != Value.ValueTypeOneofCase.ArrayValue || ids.ArrayValue.Values.Count > 64
            || ids.ArrayValue.Values.Any(id => id.ValueTypeCase != Value.ValueTypeOneofCase.StringValue
                || !FirebaseFirestoreControlListener.IsRequestId(id.StringValue)))
            throw FirebaseFirestoreControlListener.Failure("firebaseControlSignalInvalid");
        var current = ids.ArrayValue.Values.Select(id => id.StringValue).ToArray();
        if (current.Distinct(StringComparer.Ordinal).Count() != current.Length
            || (version.IntegerValue == revision && !previous.SequenceEqual(current, StringComparer.Ordinal)))
            throw FirebaseFirestoreControlListener.Failure("firebaseControlSignalInvalid");
        var added = current.Except(previous, StringComparer.Ordinal).ToArray();
        previous = current;
        revision = version.IntegerValue;
        return added;
    }
}
