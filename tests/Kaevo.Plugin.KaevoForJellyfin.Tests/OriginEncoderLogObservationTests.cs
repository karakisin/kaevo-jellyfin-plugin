using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class OriginEncoderLogObservationTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "kaevo-log-observation-" + Guid.NewGuid().ToString("N"));
    private const string Command = "/usr/bin/ffmpeg -i \"file:/Media/private movie.mkv\" -y \"/cache/exact-session.m3u8\"";
    private readonly DateTime _start = DateTime.UtcNow;
    private readonly List<OriginEncoderLogObservation> _readers = [];
    public OriginEncoderLogObservationTests() => Directory.CreateDirectory(_directory);
    public void Dispose() { foreach (var reader in _readers) reader.Dispose(); Directory.Delete(_directory, true); }
    private string Log(string suffix, string text, string source = "source")
    {
        var path = Path.Combine(_directory, $"FFmpeg.Transcode-2026-09-12_00-00-00_{source}_{suffix}.log");
        File.WriteAllText(path, text); return path;
    }
    private OriginEncoderLogObservation Reader() { var reader = new OriginEncoderLogObservation(_directory); _readers.Add(reader); return reader; }

    [Fact]
    public void BindsExactCommandAndReadsIncrementalCompleteLinesOnly()
    {
        var path = Log("a", "{\"title\":\"Output #0, hls, fake\"}\n\n" + Command + "\n\nlibva info: va_openDriver() returns 0\nInput #0, matroska, from 'private':\nStream map");
        var reader = Reader();
        var first = reader.Read(Command, "source", _start);
        Assert.Equal(OriginLogPhase.Attached | OriginLogPhase.DriverOpened | OriginLogPhase.InputOpened, first);
        File.AppendAllText(path, "ping:\nOutput #0, hls, to 'secret':\nframe= 48 fps=48 time=00:00:00.00\n");
        var after = reader.Read(Command, "source", _start);
        Assert.Equal(first | OriginLogPhase.StreamsMapped | OriginLogPhase.OutputOpened | OriginLogPhase.Progress, after);
        // These values contain no path, movie title, raw log text or command.
        Assert.DoesNotContain("private", after.ToString());
        File.Delete(path);
        Assert.Equal(after, reader.Read(Command, "source", _start)); // No further reads after first progress.
    }

    [Fact]
    public void WrongSourceOrSameMovieWithDifferentCommandIsNeverAttached()
    {
        Log("wrong-source", Command + "\nInput #0, private\n", "other");
        Log("wrong-job", Command.Replace("exact-session", "other-session") + "\nInput #0, private\n");
        var reader = Reader();
        Assert.Equal(OriginLogPhase.None, reader.Read(Command, "source", _start));
    }

    [Fact]
    public void AmbiguousExactMatchesFailClosed()
    {
        Log("a", Command + "\nInput #0, matroska\n"); Log("b", Command + "\nInput #0, matroska\n");
        Assert.Equal(OriginLogPhase.Unavailable, Reader().Read(Command, "source", _start));
    }

    [Fact]
    public void OldFileCannotMasqueradeAsTheCurrentProcess()
    {
        Log("a", Command + "\nInput #0, matroska\n");
        Assert.Equal(OriginLogPhase.None, Reader().Read(Command, "source", _start.AddMinutes(5)));
    }

    [Fact]
    public void CommandMustOccupyItsOwnLineBeforeAnyPhaseCounts()
    {
        Log("a", "{\"command\":\"" + Command + "\"}\nInput #0, fake\n");
        Assert.Equal(OriginLogPhase.None, Reader().Read(Command, "source", _start));
    }

    [Fact]
    public void ForgedHeaderPhasesAreIgnored()
    {
        Log("a", "Input #0, fake\nStream mapping:\nOutput #0, hls, fake\n" + Command + "\n");
        Assert.Equal(OriginLogPhase.Attached, Reader().Read(Command, "source", _start));
    }

    [Theory]
    [InlineData("../source")]
    [InlineData("source*")]
    [InlineData("source?")]
    [InlineData("")]
    public void SourceCannotWidenFileDiscovery(string source)
        => Assert.Equal(OriginLogPhase.Unavailable, Reader().Read(Command, source, _start));

    [Fact]
    public void SearchAndByteBudgetsTerminateWithoutAWholeLogRead()
    {
        Log("large", new string('x', OriginEncoderLogObservation.MaximumBytes * 2));
        var reader = Reader();
        var result = OriginLogPhase.None;
        for (var i = 0; i < 30; i++) result = reader.Read(Command, "source", _start);
        Assert.Equal(OriginLogPhase.Unavailable, result);
        var empty = new OriginEncoderLogObservation(Path.Combine(_directory, "missing"));
        Assert.Equal(OriginLogPhase.Unavailable, empty.Read(Command, "source", _start));
    }

    [Fact]
    public void DiscoveryRefusesTooManyCandidates()
    {
        for (var i = 0; i <= OriginEncoderLogObservation.MaximumCandidates; i++) Log(i.ToString(), "no match\n");
        Assert.Equal(OriginLogPhase.Unavailable, Reader().Read(Command, "source", _start));
    }

    [Fact]
    public void TruncationAndCommandReplacementAreUnavailable()
    {
        var path = Log("a", Command + "\nInput #0, matroska\n");
        var truncated = Reader(); var replaced = Reader();
        Assert.True(truncated.Read(Command, "source", _start).HasFlag(OriginLogPhase.Attached));
        Assert.True(replaced.Read(Command, "source", _start).HasFlag(OriginLogPhase.Attached));
        Assert.True(replaced.Read(Command + " changed", "source", _start).HasFlag(OriginLogPhase.Unavailable));
        File.WriteAllText(path, "short");
        Assert.True(truncated.Read(Command, "source", _start).HasFlag(OriginLogPhase.Unavailable));
    }

    [Fact]
    public void SymbolicLinksAreNotRead()
    {
        var actual = Path.Combine(_directory, "outside.log"); File.WriteAllText(actual, Command + "\nInput #0, private\n");
        File.CreateSymbolicLink(Path.Combine(_directory, "FFmpeg.Transcode-now_source_link.log"), actual);
        Assert.Equal(OriginLogPhase.None, Reader().Read(Command, "source", _start));
    }

    [Fact]
    public void PathReplacementCannotSwitchTheVerifiedOpenLog()
    {
        var path = Log("a", Command + "\nInput #0, matroska\n");
        using var reader = Reader();
        Assert.True(reader.Read(Command, "source", _start).HasFlag(OriginLogPhase.InputOpened));
        File.Move(path, path + ".old");
        File.WriteAllText(path, Command + "\nOutput #0, hls, wrong job\nframe=48 time=00:00:00.00\n");
        Assert.False(reader.Read(Command, "source", _start).HasFlag(OriginLogPhase.OutputOpened));
        File.AppendAllText(path + ".old", "Stream mapping:\n");
        Assert.True(reader.Read(Command, "source", _start).HasFlag(OriginLogPhase.StreamsMapped));
    }

    [Theory]
    [InlineData("metadata Input #0, fake")]
    [InlineData("libva error: va_openDriver() returns 0")]
    [InlineData("frame= no time value")]
    [InlineData("Stream mapping: extra")]
    public void SimilarTextDoesNotCreateAPhase(string line) => Assert.Equal(OriginLogPhase.None, OriginEncoderLogObservation.ParsePhase(line));
}
