using Kaevo.Plugin.KaevoForJellyfin.Services;
using MediaBrowser.Controller.MediaEncoding;
using MediaBrowser.Controller.Streaming;
using MediaBrowser.Model.Dlna;
using MediaBrowser.Model.Dto;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class HardwareDependencyPlanTests
{
    internal const string Command = "-analyzeduration 200M -probesize 1G -ss 00:49:52.000 -f matroska "
        + "-init_hw_device vaapi=va:,vendor_id=0x8086,driver=iHD -init_hw_device qsv=qs@va "
        + "-init_hw_device opencl=ocl@va -filter_hw_device qs -hwaccel vaapi -hwaccel_output_format vaapi "
        + "-i \"file:/test/A movie's source.mkv\" -codec:v:0 h264_qsv -low_power 1 -preset veryfast -b:v 11808000 "
        + "-maxrate 11808001 -g:v:0 96 -keyint_min:v:0 96 "
        + "-vf \"setparams=color_primaries=bt2020,scale_vaapi=w=1920:h=1080:extra_hw_frames=24,procamp_vaapi=b=16,"
        + "tonemap_vaapi=format=nv12:p=bt709:extra_hw_frames=32,hwmap=derive_device=qsv,format=qsv\" "
        + "-codec:a:0 libfdk_aac -ac 6 -vbr:a 2 -copyts -avoid_negative_ts disabled -f hls "
        + "-hls_time 4 -hls_segment_type mpegts -hls_segment_filename \"/cache/safe%d.ts\" -y \"/cache/safe.m3u8\"";
    private static readonly Guid User = Guid.Parse("11111111-2222-3333-4444-555555555555");
    private const string Item = "12345678123412341234123456781234";
    private static PlaybackOriginScope Scope(string session = "session") => new("connector", "device", Item, "source", session, 12_000_000, 1, 0);
    private static StreamState State(string session = "session", string device = "device", string source = "source")
        => new(null!, TranscodingJobType.Hls, null!)
        {
            Request = new VideoRequestDto { Id = Guid.Parse(Item), PlaySessionId = session, DeviceId = device, MediaSourceId = source },
            MediaSource = new MediaSourceInfo { Id = source }
        };

    [Fact]
    public void RemovesOnlyTheUnusedDeclarationPreservingEveryMediaArgument()
        => Assert.Equal(Command.Replace("-init_hw_device opencl=ocl@va", ""), KaevoHardwareDependencyPlan.WithoutUnusedOpenCl(Command));

    [Theory]
    [InlineData("-hwaccel vaapi", "-hwaccel qsv")]
    [InlineData("-codec:v:0 h264_qsv", "-codec:v:0 hevc_qsv")]
    [InlineData("-filter_hw_device qs", "-filter_hw_device ocl")]
    [InlineData("qsv=qs@va", "qsv=qs:0")]
    [InlineData("tonemap_vaapi", "tonemap_opencl")]
    [InlineData("tonemap_vaapi", "tonemap")]
    [InlineData("hwmap=derive_device=qsv", "hwmap=derive_device=opencl")]
    [InlineData("-hls_segment_type mpegts", "-hls_segment_type fmp4")]
    [InlineData("-vf", "-filter_complex")]
    [InlineData("opencl=ocl@va", "opencl=other@va")]
    [InlineData("-init_hw_device opencl=ocl@va", "")]
    [InlineData("-filter_hw_device qs", "-filter_hw_device qs -filter_hw_device qs")]
    [InlineData("-init_hw_device opencl=ocl@va", "-init_hw_device opencl=ocl@va -init_hw_device opencl=ocl@va")]
    [InlineData("format=qsv", "format=qsv;movie=/other")]
    [InlineData("-vf", "-/filter")]
    [InlineData("A movie's", "ocl dependency")]
    public void DifferentOrDependentPipelinesAreUntouched(string before, string after)
        => Assert.Null(KaevoHardwareDependencyPlan.WithoutUnusedOpenCl(Command.Replace(before, after)));

    [Theory]
    [InlineData(" -filter_complex_script /tmp/graph")]
    [InlineData(" -filter_script:v /tmp/graph")]
    [InlineData(" -init_hw_device vaapi=other@ocl")]
    [InlineData(" -af \"something=opencl\"")]
    [InlineData("\n")]
    [InlineData("\t")]
    [InlineData("\\")]
    [InlineData("\"")]
    public void AmbiguousSyntaxOrAdditionalDependenciesKeepOriginal(string suffix)
        => Assert.Null(KaevoHardwareDependencyPlan.WithoutUnusedOpenCl(Command + suffix));

    [Fact]
    public void NoAdmissionMeansNoChangeEvenForMatchingClientIdentifiers()
        => Assert.Equal(Command, new KaevoHardwareTranscodeManager(null!).Plan(State(), Command, User, TranscodingJobType.Hls, true));

    [Fact]
    public void ExactAdmissionIsConsumedOnceAndDisposalCannotAuthorizeLaterStarts()
    {
        var manager = new KaevoHardwareTranscodeManager(null!); var calls = 0;
        using var lease = manager.Admit(Scope(), User.ToString(), DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 20, default, () => calls++);
        Assert.NotNull(lease);
        Assert.NotEqual(Command, manager.Plan(State(), Command, User, TranscodingJobType.Hls, true));
        Assert.Equal(Command, manager.Plan(State(), Command, User, TranscodingJobType.Hls, true));
        Assert.Equal(1, calls);
    }

    [Theory]
    [InlineData("device")]
    [InlineData("source")]
    [InlineData("session")]
    [InlineData("user")]
    [InlineData("item")]
    [InlineData("request-source")]
    [InlineData("platform")]
    public void ExactServerOwnedIdentityAndSupportedPlatformAreRequired(string mismatch)
    {
        var manager = new KaevoHardwareTranscodeManager(null!);
        using var lease = manager.Admit(Scope(), User.ToString(), DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 20, default, () => throw new Exception("should not apply"));
        var state = State(mismatch == "session" ? "other" : "session", mismatch == "device" ? "other" : "device", mismatch == "source" ? "other" : "source");
        if (mismatch == "item") state.Request.Id = Guid.NewGuid();
        if (mismatch == "request-source") state.Request.MediaSourceId = "other";
        Assert.Equal(Command, manager.Plan(state, Command, mismatch == "user" ? Guid.NewGuid() : User, TranscodingJobType.Hls, mismatch != "platform"));
    }

    [Fact]
    public void CancellationAndLeaseDisposalRemoveEligibility()
    {
        var manager = new KaevoHardwareTranscodeManager(null!);
        using var cancel = new CancellationTokenSource();
        using var lease = manager.Admit(Scope(), User.ToString(), DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 20, cancel.Token, () => { });
        cancel.Cancel();
        Assert.Equal(Command, manager.Plan(State(), Command, User, TranscodingJobType.Hls, true));
        lease!.Dispose();
        using var next = manager.Admit(Scope(), User.ToString(), DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 20, default, () => { });
        Assert.NotNull(next); next.Dispose();
        Assert.Equal(Command, manager.Plan(State(), Command, User, TranscodingJobType.Hls, true));
    }

    [Fact]
    public void OldLeaseCannotRemoveANewAdmission()
    {
        var manager = new KaevoHardwareTranscodeManager(null!);
        using var old = manager.Admit(Scope(), User.ToString(), DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 20, default, () => { });
        manager.Plan(State(), Command, User, TranscodingJobType.Hls, true);
        using var next = manager.Admit(Scope(), User.ToString(), DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 20, default, () => { });
        old!.Dispose();
        Assert.NotEqual(Command, manager.Plan(State(), Command, User, TranscodingJobType.Hls, true));
    }

    [Fact]
    public void ExpiredExcessiveAndInvalidAdmissionsAreRejected()
    {
        var manager = new KaevoHardwareTranscodeManager(null!); var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        Assert.Null(manager.Admit(Scope(), User.ToString(), now, default, () => { }));
        Assert.Null(manager.Admit(Scope(), User.ToString(), now + 32, default, () => { }));
        Assert.Null(manager.Admit(Scope(), "invalid", now + 20, default, () => { }));
        for (var n = 0; n < 8; n++) Assert.NotNull(manager.Admit(Scope(n.ToString()), User.ToString(), now + 20, default, () => { }));
        Assert.Null(manager.Admit(Scope("overflow"), User.ToString(), now + 20, default, () => { }));
        Assert.Null(manager.Admit(Scope("0"), User.ToString(), now + 20, default, () => { }));
    }
}
