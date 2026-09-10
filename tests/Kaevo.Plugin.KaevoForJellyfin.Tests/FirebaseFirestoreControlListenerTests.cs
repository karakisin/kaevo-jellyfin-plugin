using Google.Cloud.Firestore.V1;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class FirebaseFirestoreControlListenerTests
{
    private const string Path = "projects/demo-kaevo-migration/databases/(default)/documents/connector_signals/channel";
    private static Document Snapshot(long revision, params string[] ids) => new()
    {
        Name = Path,
        Fields = { ["epoch"] = new Value { StringValue = "epoch" },
            ["revision"] = new Value { IntegerValue = revision },
            ["request_ids"] = new Value { ArrayValue = new ArrayValue
                { Values = { ids.Select(id => new Value { StringValue = id }) } } } },
    };

    [Fact]
    public void InitialEmptyAndRepeatedSnapshotsDoNotCreateWork()
    {
        var state = new FirebaseFirestoreSignalState(Path, "epoch");
        Assert.Empty(state.Accept(Snapshot(0)));
        Assert.Equal(new[] { "r.1:ok", "r-2" }, state.Accept(Snapshot(1, "r.1:ok", "r-2")));
        Assert.Empty(state.Accept(Snapshot(1, "r.1:ok", "r-2")));
        Assert.Equal(new[] { "r3" }, state.Accept(Snapshot(2, "r-2", "r3")));
        Assert.Empty(state.Accept(Snapshot(3)));
    }

    [Theory]
    [InlineData("scope")]
    [InlineData("epoch")]
    [InlineData("extra")]
    [InlineData("duplicate")]
    [InlineData("large")]
    [InlineData("negative")]
    [InlineData("type")]
    [InlineData("bad-id")]
    public void WholeInvalidSnapshotIsRejectedWithoutAdvancingState(string mode)
    {
        var state = new FirebaseFirestoreSignalState(Path, "epoch");
        var bad = Snapshot(1, "valid-first");
        switch (mode)
        {
            case "scope": bad.Name += "other"; break;
            case "epoch": bad.Fields["epoch"].StringValue = "other"; break;
            case "extra": bad.Fields["payload"] = new Value { StringValue = "private" }; break;
            case "duplicate": bad = Snapshot(1, "r1", "r1"); break;
            case "large": bad = Snapshot(1, Enumerable.Range(0, 65).Select(n => "r" + n).ToArray()); break;
            case "negative": bad.Fields["revision"].IntegerValue = -1; break;
            case "type": bad.Fields["revision"] = new Value { DoubleValue = 1 }; break;
            case "bad-id": bad = Snapshot(1, "valid-first", "private/url"); break;
        }
        var error = Assert.Throws<InvalidOperationException>(() => state.Accept(bad));
        Assert.Equal("firebaseControlSignalInvalid", error.Message);
        Assert.Null(error.InnerException);
        Assert.Equal(new[] { "valid-first" }, state.Accept(Snapshot(1, "valid-first")));
    }

    [Fact]
    public void RollbackAndSameRevisionMutationFailClosed()
    {
        var state = new FirebaseFirestoreSignalState(Path, "epoch");
        state.Accept(Snapshot(2, "r1"));
        Assert.Throws<InvalidOperationException>(() => state.Accept(Snapshot(1, "r2")));
        Assert.Throws<InvalidOperationException>(() => state.Accept(Snapshot(2, "r2")));
    }

    [Theory]
    [InlineData("project")]
    [InlineData("channel")]
    [InlineData("epoch")]
    [InlineData("token")]
    [InlineData("expired")]
    [InlineData("unbounded")]
    public async Task InvalidAdmissionFailsBeforeAnyClientAccess(string mode)
    {
        var project = mode == "project" ? "wrong-project" : FirebaseFirestoreControlListener.DevelopmentProject;
        var channel = mode == "channel" ? "wrong/path" : new string('a', 43);
        var epoch = mode == "epoch" ? "wrong" : new string('b', 32);
        var token = mode == "token" ? "secret\r\nheader" : "test.token";
        var expiry = DateTimeOffset.UtcNow.AddSeconds(mode == "expired" ? -1 : mode == "unbounded" ? 301 : 60);
        // Null client deliberately proves validation precedes any RPC.
        await using var reader = FirebaseFirestoreControlListener.ReadAsync(null!, project, channel, epoch, token, expiry)
            .GetAsyncEnumerator();
        var error = await Assert.ThrowsAsync<InvalidOperationException>(async () => { await reader.MoveNextAsync(); });
        Assert.Equal("firebaseControlAdmissionInvalid", error.Message);
        Assert.Null(error.InnerException);
    }
}
