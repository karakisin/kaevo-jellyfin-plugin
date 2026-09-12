using Kaevo.Plugin.KaevoForJellyfin.Services;
using MediaBrowser.Controller.MediaEncoding;
using MediaBrowser.Controller.Streaming;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class HardwareTranscodeManagerTests
{
    [Fact]
    public async Task OriginalManagerOwnsStartupCancellationResultAndErrors()
    {
        var original = new RecordingManager();
        var manager = new KaevoHardwareTranscodeManager(original);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var user = Guid.NewGuid();
        var state = new StreamState(null!, TranscodingJobType.Hls, null!);
        var result = manager.StartFfMpeg(state, "/out", "unmodified", user, TranscodingJobType.Hls, cancellation, "/work");
        Assert.Same(original.StartResult, result);
        Assert.Equal(new object?[] { state, "/out", "unmodified", user, TranscodingJobType.Hls, cancellation, "/work" }, original.Arguments);
        var error = new IOException("original startup failed");
        original.StartResult = Task.FromException<TranscodingJob>(error);
        Assert.Same(error, await Assert.ThrowsAsync<IOException>(() => manager.StartFfMpeg(state, "/out", "unmodified", user, TranscodingJobType.Hls, cancellation)));
    }

    [Fact]
    public void MissingStateDoesNotMakeTheOptionalPlannerTakeOverOriginalValidation()
    {
        var original = new RecordingManager();
        var manager = new KaevoHardwareTranscodeManager(original);
        using var cancellation = new CancellationTokenSource();
        Assert.Same(original.StartResult, manager.StartFfMpeg(null!, "/out", "original", Guid.Empty, TranscodingJobType.Hls, cancellation));
        Assert.Equal("original", original.Arguments[2]);
    }

    [Fact]
    public async Task AllJobLifecycleOperationsAreDelegatedWithoutNewOwnership()
    {
        var original = new RecordingManager();
        var manager = new KaevoHardwareTranscodeManager(original);
        var type = TranscodingJobType.Hls;
        manager.GetTranscodingJob("session");
        Assert.Equal(new object?[] { "session" }, original.Arguments);
        manager.GetTranscodingJob("/out", type);
        Assert.Equal(new object?[] { "/out", type }, original.Arguments);
        manager.PingTranscodingJob("session", true);
        Assert.Equal(new object?[] { "session", true }, original.Arguments);
        Func<string, bool> delete = _ => false;
        Assert.Same(original.KillResult, manager.KillTranscodingJobs("device", "session", delete));
        Assert.Equal(new object?[] { "device", "session", delete }, original.Arguments);
        var state = new StreamState(null!, type, null!);
        manager.ReportTranscodingProgress(null!, state, TimeSpan.FromSeconds(123), 24, 50, 456, 789);
        Assert.Equal(new object?[] { null, state, TimeSpan.FromSeconds(123), 24f, 50d, 456L, 789 }, original.Arguments);
        manager.OnTranscodeBeginRequest("/out", type);
        Assert.Equal(new object?[] { "/out", type }, original.Arguments);
        manager.OnTranscodeEndRequest(null!);
        Assert.Equal(new object?[] { null }, original.Arguments);
        using var cancel = new CancellationTokenSource();
        using var held = await manager.LockAsync("/lock", cancel.Token);
        Assert.Same(original.Lock, held);
        Assert.Equal(new object?[] { "/lock", cancel.Token }, original.Arguments);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("foreign")]
    [InlineData("factory")]
    [InlineData("instance")]
    [InlineData("duplicate")]
    public void UnknownServiceRegistrationsArePreservedExactly(string shape)
    {
        var services = new ServiceCollection();
        if (shape == "foreign") services.AddSingleton<ITranscodeManager, RecordingManager>();
        if (shape == "factory") services.AddSingleton<ITranscodeManager>(_ => new RecordingManager());
        if (shape == "instance") services.AddSingleton<ITranscodeManager>(new RecordingManager());
        if (shape == "duplicate") { services.AddSingleton<ITranscodeManager, RecordingManager>(); services.AddSingleton<ITranscodeManager, RecordingManager>(); }
        var before = services.ToArray();
        KaevoHardwareTranscodeManager.Register(services);
        Assert.Equal(before, services.ToArray());
    }

    private sealed class RecordingManager : ITranscodeManager
    {
        internal object?[] Arguments = [];
        internal Task<TranscodingJob> StartResult = Task.FromResult<TranscodingJob>(null!);
        internal Task KillResult = Task.CompletedTask;
        internal IDisposable Lock = new EmptyLease();
        public Task<TranscodingJob> StartFfMpeg(StreamState state, string path, string command, Guid user, TranscodingJobType type, CancellationTokenSource cancellation, string? directory = null)
        { Arguments = [state, path, command, user, type, cancellation, directory]; return StartResult; }
        public TranscodingJob? GetTranscodingJob(string session) { Arguments = [session]; return null; }
        public TranscodingJob? GetTranscodingJob(string path, TranscodingJobType type) { Arguments = [path, type]; return null; }
        public void PingTranscodingJob(string session, bool? paused) => Arguments = [session, paused];
        public Task KillTranscodingJobs(string device, string? session, Func<string, bool> delete) { Arguments = [device, session, delete]; return KillResult; }
        public void ReportTranscodingProgress(TranscodingJob job, StreamState state, TimeSpan? position, float? fps, double? percent, long? bytes, int? bitrate) => Arguments = [job, state, position, fps, percent, bytes, bitrate];
        public TranscodingJob? OnTranscodeBeginRequest(string path, TranscodingJobType type) { Arguments = [path, type]; return null; }
        public void OnTranscodeEndRequest(TranscodingJob job) => Arguments = [job];
        public ValueTask<IDisposable> LockAsync(string path, CancellationToken cancellation) { Arguments = [path, cancellation]; return ValueTask.FromResult(Lock); }
        private sealed class EmptyLease : IDisposable { public void Dispose() { } }
    }
}
