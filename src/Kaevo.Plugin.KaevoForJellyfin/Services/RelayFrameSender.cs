using System.Net.WebSockets;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal static class RelayFrameSender
{
    internal static async Task SendAsync(WebSocket socket, SemaphoreSlim gate, byte[] bytes,
        WebSocketMessageType type, CancellationToken request, CancellationToken connection)
    {
        await gate.WaitAsync(request).ConfigureAwait(false);
        try
        {
            request.ThrowIfCancellationRequested();
            // Cancelling ClientWebSocket.SendAsync aborts the shared socket.
            // Once a frame starts, finish it even if that viewer cancels; the
            // relay discards its released request. Connection shutdown and a
            // finite send deadline still interrupt a genuinely stuck socket.
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(connection);
            deadline.CancelAfter(TimeSpan.FromSeconds(5));
            await socket.SendAsync(new ArraySegment<byte>(bytes), type, true, deadline.Token).ConfigureAwait(false);
        }
        finally { gate.Release(); }
    }
}
