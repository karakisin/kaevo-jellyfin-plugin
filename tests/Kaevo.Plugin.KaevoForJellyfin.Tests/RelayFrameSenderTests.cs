using System.Net.WebSockets;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class RelayFrameSenderTests
{
    [Fact]
    public async Task ViewerCancellationDuringFrameDoesNotAbortSharedConnection()
    {
        using var request = new CancellationTokenSource();
        using var socket = new PendingSocket();
        using var gate = new SemaphoreSlim(1);
        var sending = RelayFrameSender.SendAsync(socket, gate, new byte[256 * 1024], WebSocketMessageType.Binary, request.Token, CancellationToken.None);
        await socket.Started.Task;
        request.Cancel();
        Assert.False(socket.SendToken.IsCancellationRequested);
        socket.Release.TrySetResult();
        await sending;
        await RelayFrameSender.SendAsync(socket, gate, new byte[1], WebSocketMessageType.Text, CancellationToken.None, CancellationToken.None);
        Assert.Equal(2, socket.Count);
    }

    [Fact]
    public async Task CancelledQueuedRequestNeverSendsAndDoesNotTakeGate()
    {
        using var request = new CancellationTokenSource();
        using var socket = new PendingSocket();
        using var gate = new SemaphoreSlim(0, 1);
        var sending = RelayFrameSender.SendAsync(socket, gate, new byte[1], WebSocketMessageType.Text, request.Token, CancellationToken.None);
        request.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sending);
        Assert.Equal(0, socket.Count);
        Assert.Equal(0, gate.CurrentCount);
    }

    [Fact]
    public async Task ConnectionShutdownStillInterruptsFrameAndReleasesGate()
    {
        using var connection = new CancellationTokenSource();
        using var socket = new PendingSocket();
        using var gate = new SemaphoreSlim(1);
        var sending = RelayFrameSender.SendAsync(socket, gate, new byte[1], WebSocketMessageType.Binary, CancellationToken.None, connection.Token);
        await socket.Started.Task;
        connection.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sending);
        Assert.Equal(1, gate.CurrentCount);
    }

    [Fact]
    public async Task RealManagedSocketSurvivesCancellationInsideBlockedWrite()
    {
        using var stream = new BlockedStream();
        using var socket = WebSocket.CreateFromStream(stream, true, null, Timeout.InfiniteTimeSpan);
        using var request = new CancellationTokenSource();
        using var gate = new SemaphoreSlim(1);
        var send = RelayFrameSender.SendAsync(socket, gate, new byte[256 * 1024], WebSocketMessageType.Binary, request.Token, CancellationToken.None);
        await stream.Started.Task.WaitAsync(TimeSpan.FromSeconds(2));
        request.Cancel();
        Assert.Equal(WebSocketState.Open, socket.State);
        stream.Release.TrySetResult();
        await send.WaitAsync(TimeSpan.FromSeconds(2));
        await RelayFrameSender.SendAsync(socket, gate, new byte[1], WebSocketMessageType.Text, CancellationToken.None, CancellationToken.None);
        Assert.Equal(WebSocketState.Open, socket.State);
    }

    private sealed class BlockedStream : Stream
    {
        internal readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] b, int o, int c) => throw new NotSupportedException();
        public override long Seek(long o, SeekOrigin s) => throw new NotSupportedException();
        public override void SetLength(long n) => throw new NotSupportedException();
        public override void Write(byte[] b, int o, int c) => throw new NotSupportedException();
        public override Task WriteAsync(byte[] b, int o, int c, CancellationToken token) => WriteAsync(b.AsMemory(o, c), token).AsTask();
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> b, CancellationToken token = default)
        {
            Started.TrySetResult();
            await Release.Task.WaitAsync(token);
        }
    }

    private sealed class PendingSocket : WebSocket
    {
        internal readonly TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal CancellationToken SendToken;
        internal int Count;
        public override WebSocketCloseStatus? CloseStatus => null;
        public override string? CloseStatusDescription => null;
        public override WebSocketState State => WebSocketState.Open;
        public override string? SubProtocol => null;
        public override void Abort() { }
        public override void Dispose() { }
        public override Task CloseAsync(WebSocketCloseStatus status, string? description, CancellationToken token) => Task.CompletedTask;
        public override Task CloseOutputAsync(WebSocketCloseStatus status, string? description, CancellationToken token) => Task.CompletedTask;
        public override Task<WebSocketReceiveResult> ReceiveAsync(ArraySegment<byte> buffer, CancellationToken token) => throw new NotSupportedException();
        public override async Task SendAsync(ArraySegment<byte> buffer, WebSocketMessageType type, bool end, CancellationToken token)
        {
            Count++; SendToken = token; Started.TrySetResult();
            await Release.Task.WaitAsync(token);
        }
    }
}
