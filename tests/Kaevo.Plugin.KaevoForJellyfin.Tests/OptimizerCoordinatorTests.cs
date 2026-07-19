using Kaevo.Plugin.KaevoForJellyfin.Services;
using System.Text.Json;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class OptimizerCoordinatorTests
{
    [Theory]
    [InlineData("/media/Movies/The Avengers.ts", "/media/Movies/The Avengers.kaevo-partial.mp4")]
    [InlineData("/media/Movies/Movie.mkv", "/media/Movies/Movie.kaevo-partial.mp4")]
    public void TemporaryOutputAlwaysKeepsMp4Extension(string source, string expected)
    {
        var result = KaevoOptimizerCoordinator.TemporaryOutputPath(source);

        Assert.Equal(expected, result);
        Assert.EndsWith(".mp4", result, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("/media/Movies/The Sheep Detectives.mp4", "/media/Movies/The Sheep Detectives.mp4")]
    [InlineData("/media/Movies/The Sheep Detectives.MP4", "/media/Movies/The Sheep Detectives.MP4")]
    [InlineData("/media/Movies/The Avengers.ts", "/media/Movies/The Avengers.mp4")]
    [InlineData("/media/Movies/Movie.mkv", "/media/Movies/Movie.mp4")]
    public void DirectPlayOutputPreservesExistingMp4Path(string source, string expected)
    {
        Assert.Equal(expected, KaevoOptimizerCoordinator.DirectPlayOutputPath(source));
    }

    [Fact]
    public void OptimizerJobTracksPauseDeadlineAndResumesSameProgress()
    {
        var job = new OptimizerJob(Guid.NewGuid(), Guid.NewGuid(), "item", "Title", OptimizerConversionStrategy.AudioOnly);
        job.SetRunning(job.WorkStage);
        job.SetProgress(0.42);
        var deadline = DateTimeOffset.UtcNow.AddHours(6);

        job.Pause(deadline);

        Assert.Equal("paused", job.State);
        Assert.Equal(deadline, job.PausedUntil);
        Assert.Equal(0.42, job.Progress);

        job.SetResumePending();
        Assert.Equal("resume_pending", job.State);
        Assert.Equal("waiting_to_resume", job.Stage);
        Assert.Equal(0.42, job.Progress);

        job.Resume();

        Assert.Equal("running", job.State);
        Assert.Equal("converting_audio", job.Stage);
        Assert.Null(job.PausedUntil);
        Assert.Equal(0.42, job.Progress);
    }

    [Fact]
    public void QueueJournalRoundTripsWithoutApprovalToken()
    {
        var plan = new OptimizerPlan(
            Guid.NewGuid(), "must-not-persist", Guid.NewGuid().ToString("N"), "Tuner",
            "/media/Tuner.mkv", "/media/Tuner.mp4", "/media/Tuner.kaevo-partial.mp4",
            "/media/_kaevo_original_backup/Tuner.mkv", "/media/rollback", false,
            100, 1_000, 120, OptimizerConversionStrategy.FullVideo, "hevc", "eac3",
            DateTimeOffset.UtcNow.AddMinutes(30));
        var job = new OptimizerJob(Guid.NewGuid(), plan.PlanId, plan.ItemId, plan.Title, plan.Strategy);
        var deadline = DateTimeOffset.UtcNow.AddHours(6);
        job.RestorePaused(deadline);

        var json = JsonSerializer.Serialize(new OptimizerQueueSnapshot(1, new[] { OptimizerQueueEntry.From(plan, job, 0) }));
        var restored = JsonSerializer.Deserialize<OptimizerQueueSnapshot>(json)!;

        Assert.DoesNotContain("must-not-persist", json, StringComparison.Ordinal);
        Assert.Equal("Tuner", restored.Entries.Single().Title);
        Assert.Equal(deadline, restored.Entries.Single().PausedUntil);
        Assert.Equal(string.Empty, restored.Entries.Single().ToPlan().ApprovalToken);
    }
}
