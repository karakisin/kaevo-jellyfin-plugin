using System.Text.Json;
using System.Diagnostics;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using MediaBrowser.Controller.MediaEncoding;
using MediaBrowser.Controller.Streaming;
using MediaBrowser.Model.Dto;
using MediaBrowser.Model.Entities;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class ValidatedTransportProbeTests
{
    private const string Probe = "{\"streams\":[{\"index\":0,\"codec_name\":\"hevc\",\"codec_type\":\"video\",\"width\":3840,\"height\":2160,\"pix_fmt\":\"yuv420p10le\",\"profile\":\"Main 10\"},{\"index\":1,\"codec_name\":\"truehd\",\"codec_type\":\"audio\",\"sample_rate\":\"48000\",\"channels\":8}]}";
    private static StreamState State(string path) => new(null!, TranscodingJobType.Hls, null!)
    {
        MediaSource = new MediaSourceInfo { Path = path, Container = "ts", IsRemote = false },
        VideoStream = new MediaStream { Index = 0, Codec = "hevc", Width = 3840, Height = 2160, BitDepth = 10, Profile = "Main 10" },
        AudioStream = new MediaStream { Index = 1, Codec = "truehd", Channels = 8, SampleRate = 48000 }
    };
    private static string Command(string path) => KaevoValidatedTransportProbe.OriginalPrefix
        + $"-f mpegts -i file:\"{path}\" -map 0:0 -map 0:1 -map -0:s -f hls /tmp/output.m3u8";

    [Fact]
    public void SelectedStreamsMustBeFullyRecovered()
    {
        var state = State("/media/movie.m2ts");
        using var valid = JsonDocument.Parse(Probe);
        Assert.True(KaevoValidatedTransportProbe.Matches(valid.RootElement, state.VideoStream, state.AudioStream));
        foreach (var bad in new[] { Probe.Replace("48000", "44100"), Probe.Replace("3840", "1920"), Probe.Replace("truehd", "aac"),
            Probe.Replace("Main 10", "Main"), Probe.Replace("yuv420p10le", "yuv420p"), "{\"streams\":[null]}", "{\"streams\":[]}" })
        {
            using var parsed = JsonDocument.Parse(bad);
            Assert.False(KaevoValidatedTransportProbe.Matches(parsed.RootElement, state.VideoStream, state.AudioStream));
        }
    }

    [Fact]
    public void UnknownInputOptionsAndStreamMappingsKeepFullProbe()
    {
        const string path = "/media/movie.m2ts";
        var state = State(path); var command = Command(path);
        Assert.True(KaevoValidatedTransportProbe.Eligible(state, command));
        Assert.False(KaevoValidatedTransportProbe.Eligible(state, command.Replace("200M", "100M")));
        Assert.False(KaevoValidatedTransportProbe.Eligible(state, command.Replace("-map -0:s ", "")));
        Assert.False(KaevoValidatedTransportProbe.Eligible(state, command.Replace("-map 0:1", "-map 0:2")));
        Assert.False(KaevoValidatedTransportProbe.Eligible(state, command.Replace(path, "/media/other.m2ts")));
        state.MediaSource.IsRemote = true;
        Assert.False(KaevoValidatedTransportProbe.Eligible(state, command));
        state.MediaSource.IsRemote = false; state.MediaSource.Container = "mkv";
        Assert.False(KaevoValidatedTransportProbe.Eligible(state, command));
    }

    [Fact]
    public async Task SuccessfulProbeCachesOnlyUnchangedFileAndSelectedStreams()
    {
        if (OperatingSystem.IsWindows()) return;
        var directory = Directory.CreateTempSubdirectory("kaevo-probe-test-");
        try
        {
            var path = Path.Combine(directory.FullName, "movie.m2ts");
            await File.WriteAllTextAsync(path, "test source fingerprint");
            var probePath = Path.Combine(directory.FullName, "probe");
            await File.WriteAllTextAsync(probePath, "#!/bin/sh\nprintf '%s' '" + Probe + "'\n");
            File.SetUnixFileMode(probePath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var probe = new KaevoValidatedTransportProbe(); var state = State(path); var command = Command(path);
            var expected = KaevoValidatedTransportProbe.ValidatedPrefix + command[KaevoValidatedTransportProbe.OriginalPrefix.Length..];
            Assert.Equal(expected, await probe.ApplyAsync(state, command, probePath, default, _ => { }));
            await File.WriteAllTextAsync(probePath, "#!/bin/sh\nexit 1\n");
            Assert.Equal(expected, await probe.ApplyAsync(state, command, probePath, default, _ => { }));
            state.AudioStream.Index = 2;
            var differentAudio = command.Replace("-map 0:1", "-map 0:2");
            Assert.Equal(differentAudio, await probe.ApplyAsync(state, differentAudio, probePath, default, _ => { }));
            state.AudioStream.Index = 1;
            await File.AppendAllTextAsync(path, "changed");
            Assert.Equal(command, await probe.ApplyAsync(state, command, probePath, default, _ => { }));
        }
        finally { directory.Delete(recursive: true); }
    }

    [Fact]
    public async Task SlowProbeFallsBackWithinBoundedTime()
    {
        if (OperatingSystem.IsWindows()) return;
        var directory = Directory.CreateTempSubdirectory("kaevo-probe-timeout-");
        try
        {
            var path = Path.Combine(directory.FullName, "movie.m2ts"); await File.WriteAllTextAsync(path, "data");
            var probePath = Path.Combine(directory.FullName, "probe");
            await File.WriteAllTextAsync(probePath, "#!/bin/sh\nexec sleep 20\n");
            File.SetUnixFileMode(probePath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var began = Stopwatch.StartNew(); var command = Command(path);
            Assert.Equal(command, await new KaevoValidatedTransportProbe().ApplyAsync(State(path), command, probePath, default, _ => { }));
            Assert.True(began.Elapsed < TimeSpan.FromSeconds(4));
        }
        finally { directory.Delete(recursive: true); }
    }
}
