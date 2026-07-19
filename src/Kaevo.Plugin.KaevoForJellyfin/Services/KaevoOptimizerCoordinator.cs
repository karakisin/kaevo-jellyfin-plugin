using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.MediaEncoding;
using Microsoft.Extensions.Logging;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

public sealed class KaevoOptimizerCoordinator
{
    private static readonly TimeSpan PlanLifetime = TimeSpan.FromMinutes(30);
    private readonly ConcurrentDictionary<Guid, OptimizerPlan> _plans = new();
    private readonly ConcurrentDictionary<Guid, OptimizerJob> _jobs = new();
    private readonly ILibraryManager _libraryManager;
    private readonly IMediaEncoder _mediaEncoder;
    private readonly ILogger<KaevoOptimizerCoordinator> _logger;
    private readonly object _queueLock = new();
    private readonly List<(OptimizerPlan Plan, OptimizerJob Job)> _pending = new();
    private readonly ConcurrentDictionary<Guid, CancellationTokenSource> _jobCancellations = new();
    private readonly ConcurrentDictionary<Guid, Process> _jobProcesses = new();
    private readonly ConcurrentDictionary<Guid, CancellationTokenSource> _pauseTimers = new();
    private readonly List<Guid> _pausedOrder = new();
    private readonly Dictionary<Guid, OptimizerPlan> _jobPlans = new();
    private readonly HashSet<Guid> _restartRequired = new();
    private readonly string _statePath;
    private Guid? _activeJobId;

    public KaevoOptimizerCoordinator(
        ILibraryManager libraryManager,
        IMediaEncoder mediaEncoder,
        IApplicationPaths applicationPaths,
        ILogger<KaevoOptimizerCoordinator> logger)
    {
        _libraryManager = libraryManager;
        _mediaEncoder = mediaEncoder;
        _logger = logger;
        _statePath = Path.Combine(applicationPaths.DataPath, "kaevo", "optimizer-queue.json");
        RestoreQueue();
    }

    internal OptimizerPlan CreatePlan(
        string itemId,
        string? displayTitle = null,
        OptimizerConversionStrategy strategy = OptimizerConversionStrategy.FullVideo,
        string sourceVideoCodec = "h264",
        string sourceAudioCodec = "aac",
        bool useProtectedOriginalAudio = false)
    {
        if (!Guid.TryParseExact(itemId, "N", out var id) && !Guid.TryParse(itemId, out id))
        {
            throw new InvalidOperationException("optimizerItemInvalid");
        }

        var item = _libraryManager.GetItemById(id) ?? throw new InvalidOperationException("optimizerItemMissing");
        var sourcePath = item.Path;
        if (string.IsNullOrWhiteSpace(sourcePath) || !Path.IsPathFullyQualified(sourcePath))
        {
            throw new InvalidOperationException("optimizerSourceUnavailable");
        }
        if (!File.Exists(sourcePath))
        {
            throw new InvalidOperationException("optimizerSourceMissing");
        }

        var source = new FileInfo(sourcePath);
        var directory = source.Directory ?? throw new InvalidOperationException("optimizerSourceUnavailable");
        // Preserve the exact Jellyfin path when the source is already MP4.
        // The source is moved to the protected backup before the verified
        // temporary output replaces it, so the original itself is not a
        // conflict and Jellyfin does not need to discover a renamed item.
        var outputPath = DirectPlayOutputPath(sourcePath);
        // Keep the media extension last so FFmpeg can select the MP4 muxer
        // without relying on an unsafe shell command or an implicit fallback.
        var temporaryPath = TemporaryOutputPath(sourcePath);
        var backupDirectory = Path.Combine(directory.FullName, "_kaevo_original_backup");
        var backupPath = Path.Combine(backupDirectory, source.Name);
        var backupAlreadyExists = File.Exists(backupPath);
        if (useProtectedOriginalAudio && !backupAlreadyExists)
        {
            throw new InvalidOperationException("optimizerOriginalBackupMissing");
        }
        var rollbackPath = Path.Combine(backupDirectory, source.Name + ".kaevo-reoptimization-rollback");
        if ((!string.Equals(outputPath, sourcePath, StringComparison.OrdinalIgnoreCase) && File.Exists(outputPath))
            || File.Exists(temporaryPath)
            || File.Exists(rollbackPath))
        {
            throw new InvalidOperationException("optimizerOutputConflict");
        }

        var drive = new DriveInfo(Path.GetPathRoot(sourcePath)!);
        var requiredBytes = checked(source.Length * 2);
        if (drive.AvailableFreeSpace < requiredBytes)
        {
            throw new InvalidOperationException("optimizerDiskSpaceInsufficient");
        }
        if (string.IsNullOrWhiteSpace(_mediaEncoder.EncoderPath) || !File.Exists(_mediaEncoder.EncoderPath))
        {
            throw new InvalidOperationException("optimizerEncoderUnavailable");
        }
        if (string.IsNullOrWhiteSpace(_mediaEncoder.ProbePath) || !File.Exists(_mediaEncoder.ProbePath))
        {
            throw new InvalidOperationException("optimizerProbeUnavailable");
        }

        RemoveExpiredPlans();
        var plan = new OptimizerPlan(
            Guid.NewGuid(),
            Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant(),
            itemId.ToLowerInvariant(),
            string.IsNullOrWhiteSpace(displayTitle) ? item.Name : displayTitle,
            sourcePath,
            outputPath,
            temporaryPath,
            backupPath,
            rollbackPath,
            backupAlreadyExists,
            source.Length,
            drive.AvailableFreeSpace,
            item.RunTimeTicks is > 0 ? TimeSpan.FromTicks(item.RunTimeTicks.Value).TotalSeconds : 0,
            strategy,
            sourceVideoCodec,
            sourceAudioCodec,
            DateTimeOffset.UtcNow.Add(PlanLifetime),
            useProtectedOriginalAudio);
        _plans[plan.PlanId] = plan;
        return plan;
    }

    internal OptimizerCleanupResult CleanInterruptedOutput(string itemId)
    {
        if (!Guid.TryParseExact(itemId, "N", out var id) && !Guid.TryParse(itemId, out id))
        {
            throw new InvalidOperationException("optimizerItemInvalid");
        }

        var item = _libraryManager.GetItemById(id) ?? throw new InvalidOperationException("optimizerItemMissing");
        var sourcePath = item.Path;
        if (string.IsNullOrWhiteSpace(sourcePath) || !Path.IsPathFullyQualified(sourcePath) || !File.Exists(sourcePath))
        {
            throw new InvalidOperationException("optimizerRecoverySourceUnavailable");
        }

        var source = new FileInfo(sourcePath);
        var directory = source.Directory ?? throw new InvalidOperationException("optimizerRecoverySourceUnavailable");
        var temporaryPath = TemporaryOutputPath(sourcePath);
        var outputPath = DirectPlayOutputPath(sourcePath);
        var backupPath = Path.Combine(directory.FullName, "_kaevo_original_backup", source.Name);

        // Only the exact Kaevo partial is recoverable automatically. If a
        // protected backup or second final output exists, refuse cleanup so an
        // interrupted replacement can be reviewed without risking media.
        if (File.Exists(backupPath)
            || (!string.Equals(outputPath, sourcePath, StringComparison.OrdinalIgnoreCase) && File.Exists(outputPath)))
        {
            throw new InvalidOperationException("optimizerRecoveryNeedsReview");
        }

        if (!File.Exists(temporaryPath))
        {
            return new OptimizerCleanupResult(false, "noInterruptedOutput");
        }

        File.Delete(temporaryPath);
        if (File.Exists(temporaryPath))
        {
            throw new InvalidOperationException("optimizerRecoveryCleanupFailed");
        }

        _logger.LogInformation("Kaevo removed one interrupted optimizer partial. ItemId={ItemId}", itemId);
        return new OptimizerCleanupResult(true, "interruptedOutputRemoved");
    }

    internal OptimizerJob Start(Guid planId, string approvalToken)
    {
        if (!_plans.TryGetValue(planId, out var plan) || plan.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            throw new InvalidOperationException("optimizerPlanExpired");
        }
        if (!CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.UTF8.GetBytes(plan.ApprovalToken),
                System.Text.Encoding.UTF8.GetBytes(approvalToken)))
        {
            throw new InvalidOperationException("optimizerApprovalInvalid");
        }
        _plans.TryRemove(planId, out _);
        var job = new OptimizerJob(Guid.NewGuid(), plan.PlanId, plan.ItemId, plan.Title, plan.Strategy);
        _jobs[job.JobId] = job;
        lock (_queueLock)
        {
            _jobPlans[job.JobId] = plan;
            if (_activeJobId is null)
            {
                _activeJobId = job.JobId;
                StartExecution(plan, job);
            }
            else
            {
                _pending.Add((plan, job));
                RefreshQueuePositions();
            }
            SaveStateLocked();
        }
        return job;
    }

    internal OptimizerJob Status(Guid jobId)
        => _jobs.TryGetValue(jobId, out var job)
            ? job
            : throw new InvalidOperationException("optimizerJobMissing");

    internal IReadOnlyList<OptimizerJob> Jobs()
        => _jobs.Values
            .Where(job => job.State is "running" or "paused" or "resume_pending" or "queued")
            .OrderBy(job => job.State == "running" ? -2 : job.State is "paused" or "resume_pending" ? -1 : job.QueuePosition ?? int.MaxValue)
            .ToArray();

    internal OptimizerJob Pause(Guid jobId, TimeSpan? duration)
    {
        lock (_queueLock)
        {
            if (!_jobs.TryGetValue(jobId, out var job)) throw new InvalidOperationException("optimizerJobMissing");
            if (job.State == "paused")
            {
                ScheduleResume(jobId, duration);
                job.Pause(duration is { } existingDuration ? DateTimeOffset.UtcNow.Add(existingDuration) : null);
                SaveStateLocked();
                return job;
            }
            var pendingIndex = _pending.FindIndex(entry => entry.Job.JobId == jobId);
            if (job.State == "queued" && pendingIndex >= 0)
            {
                _pending.RemoveAt(pendingIndex);
                RefreshQueuePositions();
                // A paused queued job has no FFmpeg process yet. Treat it as
                // restartable work so Resume starts the preserved plan when
                // the active slot next becomes available.
                _restartRequired.Add(jobId);
                if (!_pausedOrder.Contains(jobId)) _pausedOrder.Add(jobId);
                ScheduleResume(jobId, duration);
                job.Pause(duration is { } queuedDuration ? DateTimeOffset.UtcNow.Add(queuedDuration) : null);
                StartNextAvailableLocked();
                SaveStateLocked();
                return job;
            }
            if (job.State != "running" || !_jobProcesses.TryGetValue(jobId, out var process) || process.HasExited)
            {
                throw new InvalidOperationException("optimizerJobNotPausable");
            }
            if (!TrySignal(process.Id, SigStop)) throw new InvalidOperationException("optimizerPauseUnavailable");
            DateTimeOffset? pausedUntil = duration is { } pauseDuration
                ? DateTimeOffset.UtcNow.Add(pauseDuration)
                : null;
            job.Pause(pausedUntil);
            if (!_pausedOrder.Contains(jobId)) _pausedOrder.Add(jobId);
            if (_activeJobId == jobId) _activeJobId = null;
            ScheduleResume(jobId, duration);
            StartNextAvailableLocked();
            SaveStateLocked();
            return job;
        }
    }

    internal OptimizerJob Resume(Guid jobId)
    {
        lock (_queueLock)
        {
            if (!_jobs.TryGetValue(jobId, out var job)) throw new InvalidOperationException("optimizerJobMissing");
            if (job.State != "paused") return job;
            if (!_restartRequired.Contains(jobId)
                && (!_jobProcesses.TryGetValue(jobId, out var process) || process.HasExited))
            {
                throw new InvalidOperationException("optimizerJobNotResumable");
            }
            CancelPauseTimer(jobId);
            job.SetResumePending();
            StartNextAvailableLocked();
            SaveStateLocked();
            return job;
        }
    }

    internal OptimizerJob Reorder(Guid jobId, int priorityIndex)
    {
        lock (_queueLock)
        {
            var current = _pending.FindIndex(entry => entry.Job.JobId == jobId);
            if (current < 0) throw new InvalidOperationException("optimizerJobNotPending");
            var entry = _pending[current];
            _pending.RemoveAt(current);
            _pending.Insert(Math.Clamp(priorityIndex, 0, _pending.Count), entry);
            RefreshQueuePositions();
            SaveStateLocked();
            return entry.Job;
        }
    }

    internal OptimizerJob Cancel(Guid jobId)
    {
        lock (_queueLock)
        {
            var pendingIndex = _pending.FindIndex(entry => entry.Job.JobId == jobId);
            if (pendingIndex >= 0)
            {
                var pending = _pending[pendingIndex].Job;
                _pending.RemoveAt(pendingIndex);
                pending.Cancel();
                _jobPlans.Remove(jobId);
                RefreshQueuePositions();
                SaveStateLocked();
                return pending;
            }
            if (!_jobs.TryGetValue(jobId, out var job)) throw new InvalidOperationException("optimizerJobMissing");
            if (job.State is "completed" or "failed" or "cancelled") return job;
            if (_restartRequired.Contains(jobId))
            {
                _restartRequired.Remove(jobId);
                _pausedOrder.Remove(jobId);
                CancelPauseTimer(jobId);
                if (_jobPlans.Remove(jobId, out var restoredPlan)) TryDelete(restoredPlan.TemporaryPath);
                job.Cancel();
                StartNextAvailableLocked();
                SaveStateLocked();
                return job;
            }
            if (!_jobCancellations.TryGetValue(jobId, out var cancellation))
            {
                throw new InvalidOperationException("optimizerJobNotCancellable");
            }
            if (job.State is "paused" or "resume_pending" && _jobProcesses.TryGetValue(jobId, out var process) && !process.HasExited)
            {
                TrySignal(process.Id, SigContinue);
            }
            _pausedOrder.Remove(jobId);
            CancelPauseTimer(jobId);
            job.SetCancelling();
            cancellation.Cancel();
            SaveStateLocked();
            return job;
        }
    }

    internal static string TemporaryOutputPath(string sourcePath)
    {
        var directory = Path.GetDirectoryName(sourcePath)
            ?? throw new InvalidOperationException("optimizerSourceUnavailable");
        return Path.Combine(
            directory,
            Path.GetFileNameWithoutExtension(sourcePath) + ".kaevo-partial.mp4");
    }

    internal static string DirectPlayOutputPath(string sourcePath)
    {
        if (string.Equals(Path.GetExtension(sourcePath), ".mp4", StringComparison.OrdinalIgnoreCase))
        {
            return sourcePath;
        }
        var directory = Path.GetDirectoryName(sourcePath)
            ?? throw new InvalidOperationException("optimizerSourceUnavailable");
        return Path.Combine(directory, Path.GetFileNameWithoutExtension(sourcePath) + ".mp4");
    }

    private void StartExecution(OptimizerPlan plan, OptimizerJob job)
    {
        var cancellation = new CancellationTokenSource();
        _jobCancellations[job.JobId] = cancellation;
        _ = Task.Run(() => ExecuteAsync(plan, job, cancellation.Token));
    }

    private async Task ExecuteAsync(OptimizerPlan plan, OptimizerJob job, CancellationToken cancellationToken)
    {
        try
        {
            job.SetRunning(job.WorkStage);
            Directory.CreateDirectory(Path.GetDirectoryName(plan.BackupPath)!);
            await File.WriteAllTextAsync(Path.Combine(Path.GetDirectoryName(plan.BackupPath)!, ".ignore"), string.Empty)
                .ConfigureAwait(false);

            var arguments = new List<string>
            {
                "-hide_banner", "-nostdin", "-y", "-progress", "pipe:1", "-nostats", "-i", plan.SourcePath
            };
            if (plan.UseProtectedOriginalAudio)
            {
                arguments.AddRange(new[] { "-i", plan.BackupPath });
            }
            arguments.AddRange(new[] {
                "-map", "0:v:0",
                "-map", plan.UseProtectedOriginalAudio ? "1:a:0?" : "0:a:0?",
                "-map_metadata", "0", "-map_chapters", "0"
            });
            if (plan.Strategy == OptimizerConversionStrategy.FullVideo)
            {
                // Full 4K software conversion with x264 medium can take many
                // hours on a home server. Veryfast remains deterministic and
                // Apple-compatible while making one-title optimization
                // practical without assuming a specific GPU is installed.
                arguments.AddRange(new[] { "-c:v", "libx264", "-preset", "veryfast", "-crf", "20", "-pix_fmt", "yuv420p" });
            }
            else
            {
                arguments.AddRange(new[] { "-c:v", "copy" });
            }
            if (plan.Strategy == OptimizerConversionStrategy.RemuxOnly)
            {
                arguments.AddRange(new[] { "-c:a", "copy" });
            }
            else
            {
                arguments.AddRange(new[] {
                    "-c:a", "aac",
                    "-ac", "2",
                    "-ar", "48000",
                    "-b:a", "256k"
                });
            }
            arguments.AddRange(new[] { "-movflags", "+faststart", plan.TemporaryPath });
            var conversion = await RunConversionAsync(
                _mediaEncoder.EncoderPath,
                arguments,
                TimeSpan.FromHours(24),
                plan.DurationSeconds,
                job,
                cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (conversion.ExitCode != 0 || !File.Exists(plan.TemporaryPath))
            {
                throw new OptimizerExecutionException(
                    plan.Strategy == OptimizerConversionStrategy.FullVideo
                        ? "conversionFailed"
                        : "fastPathFailed");
            }

            job.SetRunning("verifying");
            cancellationToken.ThrowIfCancellationRequested();
            var probe = await RunAsync(
                _mediaEncoder.ProbePath,
                new[] { "-v", "error", "-show_entries", "stream=codec_type,codec_name,channels", "-of", "csv=p=0", plan.TemporaryPath },
                TimeSpan.FromMinutes(5)).ConfigureAwait(false);
            var streams = probe.StandardOutput
                .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var expectedVideoCodec = plan.Strategy == OptimizerConversionStrategy.FullVideo ? "h264" : plan.SourceVideoCodec;
            var expectedAudioCodec = plan.Strategy == OptimizerConversionStrategy.RemuxOnly ? plan.SourceAudioCodec : "aac";
            var hasExpectedVideo = streams.Any(line => line.Contains(expectedVideoCodec, StringComparison.OrdinalIgnoreCase)
                && line.Contains("video", StringComparison.OrdinalIgnoreCase));
            var hasExpectedAudio = streams.Any(line => line.Contains(expectedAudioCodec, StringComparison.OrdinalIgnoreCase)
                && line.Contains("audio", StringComparison.OrdinalIgnoreCase));
            var hasAppleStereoAudio = plan.Strategy == OptimizerConversionStrategy.RemuxOnly
                || streams.Any(line => line.Contains("aac", StringComparison.OrdinalIgnoreCase)
                    && line.Contains("audio", StringComparison.OrdinalIgnoreCase)
                    && line.Split(',', StringSplitOptions.TrimEntries).Contains("2"));
            if (probe.ExitCode != 0 || !hasExpectedVideo || !hasExpectedAudio || !hasAppleStereoAudio || new FileInfo(plan.TemporaryPath).Length <= 0)
            {
                throw new OptimizerExecutionException("verificationFailed");
            }

            job.SetRunning("replacing");
            cancellationToken.ThrowIfCancellationRequested();
            var replacementBackupPath = plan.BackupAlreadyExists ? plan.RollbackPath : plan.BackupPath;
            File.Move(plan.SourcePath, replacementBackupPath);
            try
            {
                File.Move(plan.TemporaryPath, plan.OutputPath);
            }
            catch
            {
                File.Move(replacementBackupPath, plan.SourcePath);
                throw;
            }

            if (plan.BackupAlreadyExists)
            {
                TryDelete(plan.RollbackPath);
            }

            job.SetRunning("refreshing_library");
            try
            {
                var refreshedItem = _libraryManager.GetItemById(Guid.Parse(plan.ItemId));
                if (refreshedItem is not null && string.Equals(plan.SourcePath, plan.OutputPath, StringComparison.OrdinalIgnoreCase))
                {
                    await refreshedItem.RefreshMetadata(cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    _libraryManager.QueueLibraryScan();
                }
            }
            catch (Exception refreshException)
            {
                // The verified media is already installed. Fall back to a
                // library scan rather than reporting the conversion itself as
                // failed because an immediate metadata refresh was unavailable.
                _logger.LogWarning(refreshException, "Kaevo could not immediately refresh optimized metadata. ItemId={ItemId}", plan.ItemId);
                _libraryManager.QueueLibraryScan();
            }

            job.Complete(plan.SourceBytes, new FileInfo(plan.OutputPath).Length);
            _logger.LogInformation("Kaevo optimizer completed one approved title. ItemId={ItemId} JobId={JobId}", plan.ItemId, job.JobId);
        }
        catch (Exception exception)
        {
            TryDelete(plan.TemporaryPath);
            var replacementBackupPath = plan.BackupAlreadyExists ? plan.RollbackPath : plan.BackupPath;
            if (!File.Exists(plan.SourcePath) && File.Exists(replacementBackupPath) && !File.Exists(plan.OutputPath))
            {
                try { File.Move(replacementBackupPath, plan.SourcePath); } catch { }
            }
            if (exception is OperationCanceledException || cancellationToken.IsCancellationRequested)
            {
                job.Cancel();
            }
            else
            {
                job.Fail(exception is OptimizerExecutionException known ? known.Code : "optimizerExecutionFailed");
            }
            _logger.LogWarning("Kaevo optimizer stopped safely. ItemId={ItemId} JobId={JobId} Reason={Reason}", plan.ItemId, job.JobId, job.Error);
        }
        finally
        {
            if (_jobCancellations.TryRemove(job.JobId, out var cancellation)) cancellation.Dispose();
            _jobProcesses.TryRemove(job.JobId, out _);
            CancelPauseTimer(job.JobId);
            StartNextOrRelease(job.JobId);
        }
    }

    private void StartNextOrRelease(Guid completedJobId)
    {
        lock (_queueLock)
        {
            // A cancelled paused process can finish while another job owns the
            // conversion slot. It must not release that other job's slot.
            if (_activeJobId == completedJobId) _activeJobId = null;
            _pausedOrder.Remove(completedJobId);
            _restartRequired.Remove(completedJobId);
            _jobPlans.Remove(completedJobId);
            StartNextAvailableLocked();
            SaveStateLocked();
        }
    }

    private void StartNextAvailableLocked()
    {
        if (_activeJobId is not null) return;

        foreach (var jobId in _pausedOrder.ToArray())
        {
            if (!_jobs.TryGetValue(jobId, out var pausedJob) || pausedJob.State != "resume_pending") continue;
            if (_restartRequired.Contains(jobId) && _jobPlans.TryGetValue(jobId, out var restartPlan))
            {
                TryDelete(restartPlan.TemporaryPath);
                _restartRequired.Remove(jobId);
                _pausedOrder.Remove(jobId);
                _activeJobId = jobId;
                pausedJob.Restart();
                StartExecution(restartPlan, pausedJob);
                return;
            }
            if (!_jobProcesses.TryGetValue(jobId, out var pausedProcess) || pausedProcess.HasExited)
            {
                _pausedOrder.Remove(jobId);
                pausedJob.Fail("optimizerJobNotResumable");
                continue;
            }
            if (!TrySignal(pausedProcess.Id, SigContinue))
            {
                pausedJob.Fail("optimizerResumeUnavailable");
                _pausedOrder.Remove(jobId);
                continue;
            }
            _pausedOrder.Remove(jobId);
            _activeJobId = jobId;
            pausedJob.Resume();
            return;
        }

        if (_pending.Count == 0) return;
        var next = _pending[0];
        _pending.RemoveAt(0);
        RefreshQueuePositions();
        _activeJobId = next.Job.JobId;
        StartExecution(next.Plan, next.Job);
    }

    private void RefreshQueuePositions()
    {
        for (var index = 0; index < _pending.Count; index++)
        {
            _pending[index].Job.SetQueuePosition(index);
        }
    }

    private static async Task<ProcessResult> RunAsync(string executable, IReadOnlyList<string> arguments, TimeSpan timeout)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = executable,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            }
        };
        foreach (var argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }
        process.Start();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var cancellation = new CancellationTokenSource(timeout);
        try
        {
            await process.WaitForExitAsync(cancellation.Token).ConfigureAwait(false);
            await Task.WhenAll(stdout, stderr).ConfigureAwait(false);
            return new ProcessResult(process.ExitCode, await stdout.ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            return new ProcessResult(-1, string.Empty);
        }
    }

    private async Task<ProcessResult> RunConversionAsync(
        string executable,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        double durationSeconds,
        OptimizerJob job,
        CancellationToken cancellationToken)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = executable,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            }
        };
        foreach (var argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }
        process.Start();
        _jobProcesses[job.JobId] = process;
        var stderr = process.StandardError.ReadToEndAsync();
        var progressReader = Task.Run(async () =>
        {
            while (await process.StandardOutput.ReadLineAsync().ConfigureAwait(false) is { } line)
            {
                if (durationSeconds > 0
                    && TryParseProgressSeconds(line, out var progressSeconds))
                {
                    job.SetProgress(Math.Clamp(progressSeconds / durationSeconds, 0, 0.99));
                }
            }
        });
        using var timeoutCancellation = new CancellationTokenSource(timeout);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(timeoutCancellation.Token, cancellationToken);
        try
        {
            await process.WaitForExitAsync(cancellation.Token).ConfigureAwait(false);
            await Task.WhenAll(progressReader, stderr).ConfigureAwait(false);
            return new ProcessResult(process.ExitCode, string.Empty);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            return new ProcessResult(-1, string.Empty);
        }
        finally
        {
            _jobProcesses.TryRemove(job.JobId, out _);
        }
    }

    private static bool TryParseProgressSeconds(string line, out double seconds)
    {
        seconds = 0;
        if (line.StartsWith("out_time_us=", StringComparison.Ordinal)
            && long.TryParse(line.AsSpan("out_time_us=".Length), out var microseconds))
        {
            seconds = microseconds / 1_000_000d;
            return true;
        }
        // Some Jellyfin FFmpeg builds expose the same microsecond value using
        // the older out_time_ms key.
        if (line.StartsWith("out_time_ms=", StringComparison.Ordinal)
            && long.TryParse(line.AsSpan("out_time_ms=".Length), out var legacyMicroseconds))
        {
            seconds = legacyMicroseconds / 1_000_000d;
            return true;
        }
        if (line.StartsWith("out_time=", StringComparison.Ordinal)
            && TimeSpan.TryParse(line.AsSpan("out_time=".Length), out var timestamp))
        {
            seconds = timestamp.TotalSeconds;
            return true;
        }
        return false;
    }

    private void ScheduleResume(Guid jobId, TimeSpan? duration)
    {
        CancelPauseTimer(jobId);
        if (duration is null) return;
        var timer = new CancellationTokenSource();
        _pauseTimers[jobId] = timer;
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(duration.Value, timer.Token).ConfigureAwait(false);
                Resume(jobId);
            }
            catch (OperationCanceledException) { }
            catch (Exception exception)
            {
                _logger.LogWarning(exception, "Kaevo optimizer could not auto-resume JobId={JobId}", jobId);
            }
        });
    }

    private void CancelPauseTimer(Guid jobId)
    {
        if (_pauseTimers.TryRemove(jobId, out var timer))
        {
            timer.Cancel();
            timer.Dispose();
        }
    }

    private void RestoreQueue()
    {
        if (!File.Exists(_statePath)) return;
        try
        {
            var snapshot = JsonSerializer.Deserialize<OptimizerQueueSnapshot>(File.ReadAllText(_statePath));
            if (snapshot?.Entries is null) return;
            lock (_queueLock)
            {
                foreach (var entry in snapshot.Entries.OrderBy(value => value.Order))
                {
                    if (!File.Exists(entry.SourcePath)) continue;
                    var plan = entry.ToPlan();
                    var job = new OptimizerJob(entry.JobId, entry.PlanId, entry.ItemId, entry.Title, entry.Strategy);
                    _jobs[job.JobId] = job;
                    _jobPlans[job.JobId] = plan;
                    if (entry.State == "queued")
                    {
                        _pending.Add((plan, job));
                        continue;
                    }

                    job.RestorePaused(entry.PausedUntil);
                    _pausedOrder.Add(job.JobId);
                    _restartRequired.Add(job.JobId);
                    if (entry.PausedUntil is { } deadline)
                    {
                        if (deadline <= DateTimeOffset.UtcNow) job.SetResumePending();
                        else ScheduleResume(job.JobId, deadline - DateTimeOffset.UtcNow);
                    }
                }
                RefreshQueuePositions();
                StartNextAvailableLocked();
                SaveStateLocked();
            }
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Kaevo could not restore its local optimizer queue journal.");
        }
    }

    private void SaveStateLocked()
    {
        try
        {
            var entries = new List<OptimizerQueueEntry>();
            var order = 0;
            foreach (var jobId in _pausedOrder)
            {
                if (_jobs.TryGetValue(jobId, out var job) && _jobPlans.TryGetValue(jobId, out var plan))
                    entries.Add(OptimizerQueueEntry.From(plan, job, order++));
            }
            foreach (var (plan, job) in _pending)
                entries.Add(OptimizerQueueEntry.From(plan, job, order++));
            if (_activeJobId is { } activeId
                && _jobs.TryGetValue(activeId, out var activeJob)
                && _jobPlans.TryGetValue(activeId, out var activePlan)
                && entries.All(entry => entry.JobId != activeId))
                entries.Insert(0, OptimizerQueueEntry.From(activePlan, activeJob, -1));

            Directory.CreateDirectory(Path.GetDirectoryName(_statePath)!);
            var temporary = _statePath + ".tmp";
            File.WriteAllText(temporary, JsonSerializer.Serialize(new OptimizerQueueSnapshot(1, entries)));
            File.Move(temporary, _statePath, overwrite: true);
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Kaevo could not update its local optimizer queue journal.");
        }
    }

    private const int SigStop = 19;
    private const int SigContinue = 18;

    [DllImport("libc", SetLastError = true)]
    private static extern int kill(int processId, int signal);

    private static bool TrySignal(int processId, int signal)
        => OperatingSystem.IsLinux() && kill(processId, signal) == 0;

    private void RemoveExpiredPlans()
    {
        foreach (var entry in _plans.Where(entry => entry.Value.ExpiresAt <= DateTimeOffset.UtcNow))
        {
            _plans.TryRemove(entry.Key, out _);
        }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}

internal sealed record ProcessResult(int ExitCode, string StandardOutput);

internal sealed record OptimizerCleanupResult(bool Removed, string State);

internal sealed record OptimizerQueueSnapshot(int Version, IReadOnlyList<OptimizerQueueEntry> Entries);

internal sealed record OptimizerQueueEntry(
    Guid PlanId, Guid JobId, string ItemId, string Title, string SourcePath, string OutputPath,
    string TemporaryPath, string BackupPath, string RollbackPath, bool BackupAlreadyExists,
    long SourceBytes, long AvailableBytes, double DurationSeconds, OptimizerConversionStrategy Strategy,
    string SourceVideoCodec, string SourceAudioCodec, bool UseProtectedOriginalAudio,
    string State, DateTimeOffset? PausedUntil, int Order)
{
    internal static OptimizerQueueEntry From(OptimizerPlan plan, OptimizerJob job, int order)
        => new(plan.PlanId, job.JobId, plan.ItemId, plan.Title, plan.SourcePath, plan.OutputPath,
            plan.TemporaryPath, plan.BackupPath, plan.RollbackPath, plan.BackupAlreadyExists,
            plan.SourceBytes, plan.AvailableBytes, plan.DurationSeconds, plan.Strategy,
            plan.SourceVideoCodec, plan.SourceAudioCodec, plan.UseProtectedOriginalAudio,
            job.State, job.PausedUntil, order);

    internal OptimizerPlan ToPlan()
        => new(PlanId, string.Empty, ItemId, Title, SourcePath, OutputPath, TemporaryPath,
            BackupPath, RollbackPath, BackupAlreadyExists, SourceBytes, AvailableBytes,
            DurationSeconds, Strategy, SourceVideoCodec, SourceAudioCodec,
            DateTimeOffset.MaxValue, UseProtectedOriginalAudio);
}

internal sealed record OptimizerPlan(
    Guid PlanId,
    string ApprovalToken,
    string ItemId,
    string Title,
    string SourcePath,
    string OutputPath,
    string TemporaryPath,
    string BackupPath,
    string RollbackPath,
    bool BackupAlreadyExists,
    long SourceBytes,
    long AvailableBytes,
    double DurationSeconds,
    OptimizerConversionStrategy Strategy,
    string SourceVideoCodec,
    string SourceAudioCodec,
    DateTimeOffset ExpiresAt,
    bool UseProtectedOriginalAudio = false);

internal enum OptimizerConversionStrategy
{
    RemuxOnly,
    AudioOnly,
    FullVideo
}

internal sealed class OptimizerJob
{
    public OptimizerJob(Guid jobId, Guid planId, string itemId, string title, OptimizerConversionStrategy strategy)
    {
        JobId = jobId;
        PlanId = planId;
        ItemId = itemId;
        Title = title;
        WorkStage = strategy switch
        {
            OptimizerConversionStrategy.RemuxOnly => "remuxing",
            OptimizerConversionStrategy.AudioOnly => "converting_audio",
            _ => "converting_video"
        };
    }

    public Guid JobId { get; }
    public Guid PlanId { get; }
    public string ItemId { get; }
    public string Title { get; }
    public string WorkStage { get; }
    public string State { get; private set; } = "queued";
    public string Stage { get; private set; } = "queued";
    public string? Error { get; private set; }
    public long? SourceBytes { get; private set; }
    public long? OutputBytes { get; private set; }
    public double Progress { get; private set; }
    public int? QueuePosition { get; private set; }
    public DateTimeOffset? PausedUntil { get; private set; }

    public void SetRunning(string stage) { State = "running"; Stage = stage; QueuePosition = null; PausedUntil = null; }
    public void SetQueuePosition(int position) { State = "queued"; Stage = "queued"; QueuePosition = position; PausedUntil = null; }
    public void SetCancelling() { State = "cancelling"; Stage = "stopping"; }
    public void Pause(DateTimeOffset? pausedUntil) { State = "paused"; Stage = "paused"; PausedUntil = pausedUntil; }
    public void SetResumePending() { State = "resume_pending"; Stage = "waiting_to_resume"; PausedUntil = null; }
    public void Resume() { State = "running"; Stage = WorkStage; PausedUntil = null; }
    public void Restart() { State = "running"; Stage = WorkStage; Progress = 0; PausedUntil = null; }
    public void RestorePaused(DateTimeOffset? pausedUntil) { State = "paused"; Stage = "restart_required"; Progress = 0; PausedUntil = pausedUntil; }
    public void Cancel() { State = "cancelled"; Stage = "cancelled"; Error = null; PausedUntil = null; }
    public void SetProgress(double progress) { Progress = progress; }
    public void Complete(long sourceBytes, long outputBytes) { State = "completed"; Stage = "completed"; Progress = 1; SourceBytes = sourceBytes; OutputBytes = outputBytes; PausedUntil = null; }
    public void Fail(string error) { State = "failed"; Stage = "failed"; Error = error; PausedUntil = null; }
}

internal sealed class OptimizerExecutionException(string code) : Exception(code)
{
    internal string Code { get; } = code;
}
