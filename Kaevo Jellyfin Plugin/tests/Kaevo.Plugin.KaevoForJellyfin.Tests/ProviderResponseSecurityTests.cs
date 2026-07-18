using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class ProviderResponseSecurityTests
{
    [Fact]
    public async Task OversizedChunkedBodyStopsAtTheConfiguredBound()
    {
        var content = new StreamContent(new ChunkStream(32, 4096));
        var result = await KaevoCloudConnectorService.ReadBoundedAsync(content, 8192, default);
        Assert.True(result.Truncated);
        Assert.Equal(8192, result.Data.Length);
    }

    [Fact]
    public async Task ExactBoundIsAcceptedButOneAdditionalByteIsRejected()
    {
        var exact = await KaevoCloudConnectorService.ReadBoundedAsync(new ByteArrayContent(new byte[1024]), 1024, default);
        var over = await KaevoCloudConnectorService.ReadBoundedAsync(new ByteArrayContent(new byte[1025]), 1024, default);
        Assert.False(exact.Truncated);
        Assert.True(over.Truncated);
        Assert.Equal(1024, over.Data.Length);
    }

    [Fact]
    public async Task StalledBodyHonorsCancellationPromptly()
    {
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            KaevoCloudConnectorService.ReadBoundedAsync(new StreamContent(new StalledStream()), 1024, cancellation.Token));
    }

    [Fact]
    public async Task StalledBodyHonorsIndependentIdleDeadline()
    {
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            KaevoCloudConnectorService.ReadBoundedAsync(
                new StreamContent(new StalledStream()),
                1024,
                default,
                TimeSpan.FromSeconds(1),
                TimeSpan.FromMilliseconds(25)));
    }

    [Fact]
    public async Task EndlessSlowBodyHonorsIndependentTotalDeadline()
    {
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            KaevoCloudConnectorService.ReadBoundedAsync(
                new StreamContent(new SlowByteStream()),
                1024,
                default,
                TimeSpan.FromMilliseconds(60),
                TimeSpan.FromMilliseconds(40)));
    }

    private sealed class ChunkStream(int chunks, int chunkSize) : Stream
    {
        private int _remaining = chunks;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_remaining-- <= 0) return ValueTask.FromResult(0);
            var count = Math.Min(chunkSize, buffer.Length);
            buffer.Span[..count].Fill(0x41);
            return ValueTask.FromResult(count);
        }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class StalledStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        { await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken); return 0; }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class SlowByteStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(20, cancellationToken);
            buffer.Span[0] = 0x41;
            return 1;
        }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
