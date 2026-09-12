using System.Text.Json;
using Google.Cloud.Firestore.V1;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class FirebasePlaybackMailboxTests
{
    private const string Channel = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string Epoch = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private static readonly string Path = "projects/demo-kaevo-migration/databases/(default)/documents/connector_signals/" + Channel;
    private static long Expiry => DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 20;
    private static Dictionary<string, object> Envelope(long? expires = null)
    {
        var end=expires??Expiry;
        return new() { ["protocol"]=1, ["channel"]=Channel, ["epoch"]=Epoch, ["expires_at"]=end,
            ["request"]=new Dictionary<string, object> { ["request_id"]="r1", ["profile_id"]="exact-profile",
                ["connector_id"]="exact-connector", ["status"]="in_progress", ["method"]="COMMAND", ["provider"]="home_server",
                ["path"]="/commands/jellyfin.prepare_playback", ["operation"]="jellyfin.prepare_playback",
                ["origin_start_expires_at"]=end, ["parameters"]=new { origin_start_ticks=1234000000 },
                ["profile_provider_binding"]=new { provider="jellyfin",connector_id="exact-connector",provider_user_id=new string('c',32) } } };
    }
    private static Document Snapshot(Dictionary<string,object>? envelope=null,long revision=1) => new()
    { Name=Path,Fields={ ["epoch"]=new Value{StringValue=Epoch},["revision"]=new Value{IntegerValue=revision},
        ["request_ids"]=new Value{ArrayValue=new ArrayValue{Values={new Value{StringValue="r1"}}}},
        ["playback_commands"]=new Value{MapValue=new MapValue{Fields={ ["r1"]=new Value{StringValue=JsonSerializer.Serialize(envelope??Envelope())} }}} } };
    private static FirebaseControlAdmission Admission(string? epoch=null) => new()
    { Channel=Channel,Epoch=epoch??Epoch,PushUid="connector-push-"+new string('c',43),CustomToken="synthetic",ExpiresAt=DateTimeOffset.UtcNow.AddSeconds(60) };

    [Fact] public void ServerProjectionPreservesExactProfileAndResume()
    {
        var command=Assert.Single(FirebasePlaybackMailbox.Parse(Snapshot(),Channel,Epoch)).Value;
        Assert.Equal("exact-profile",command.Request.ProfileId);
        Assert.Equal(new string('c',32),command.Request.ProfileProviderBinding!.ProviderUserId);
        Assert.Equal(1234000000,command.Request.Parameters!["origin_start_ticks"].GetInt64());
    }
    [Theory]
    [InlineData("channel")][InlineData("epoch")][InlineData("protocol")][InlineData("unknown")]
    [InlineData("request_id")][InlineData("operation")][InlineData("method")][InlineData("deadline")][InlineData("binding")]
    public void InvalidProjectionCannotAdvanceListenerOrExecute(string kind)
    {
        var data=Envelope();var request=(Dictionary<string,object>)data["request"];
        switch(kind)
        {
            case "channel":data["channel"]=new string('z',43);break;
            case "epoch":data["epoch"]=new string('z',32);break;
            case "protocol":data["protocol"]=2;break;
            case "unknown":data["authority"]="forged";break;
            case "request_id":request["request_id"]="other";break;
            case "operation":request["operation"]="jellyfin.delete_user";break;
            case "method":request["method"]="GET";break;
            case "deadline":data["expires_at"]=Expiry+100;break;
            case "binding":request["connector_id"]="other";break;
        }
        var state=new FirebaseFirestoreSignalState(Path,Epoch);
        Assert.Throws<InvalidOperationException>(()=>state.Accept(Snapshot(data)));
        Assert.Equal(new[]{"r1"},state.Accept(Snapshot()));
    }
    [Fact] public void DuplicateSnapshotOrReconnectDoesNotExecuteTwice()
    {
        var box=new FirebasePlaybackMailbox(null!,null!);var doc=Snapshot();var admission=Admission();
        box.Accept(doc,admission,"private-token");var command=box.Take("r1");Assert.NotNull(command);
        Assert.DoesNotContain("private-token",command.ToString());
        Assert.Null(box.Take("r1"));box.Accept(doc,admission,"private-token");Assert.Null(box.Take("r1"));
    }
    [Fact] public void ExpiredProjectionIsNotExecutedOrRevived()
    {
        var box=new FirebasePlaybackMailbox(null!,null!);
        box.Accept(Snapshot(Envelope(DateTimeOffset.UtcNow.ToUnixTimeSeconds()-1)),Admission(),"private-token");
        Assert.Null(box.Take("r1"));
    }
    [Fact] public void SameRevisionPayloadMutationIsRejected()
    {
        var state=new FirebaseFirestoreSignalState(Path,Epoch);var envelope=Envelope();state.Accept(Snapshot(envelope));
        ((Dictionary<string,object>)envelope["request"])["profile_id"]="other-profile";
        Assert.Throws<InvalidOperationException>(()=>state.Accept(Snapshot(envelope)));
    }
    [Fact] public async Task ExpiredDeliveryFallsBackWithoutReadingKeyOrSendingAnything()
    {
        var box=new FirebasePlaybackMailbox(null!,null!);
        var request=Assert.Single(FirebasePlaybackMailbox.Parse(Snapshot(),Channel,Epoch)).Value.Request;
        var delivery=new FirebasePlaybackMailbox.Delivery(request,Channel,Epoch,"private-token",DateTimeOffset.UtcNow.AddSeconds(-1),Expiry);
        Assert.False(await box.DeliverAsync(delivery,"complete",new{},default));
    }
    [Fact] public void OtherCommandsRemainOpaqueHints()
    {
        var snapshot=Snapshot();snapshot.Fields.Remove("playback_commands");
        Assert.Empty(FirebasePlaybackMailbox.Parse(snapshot,Channel,Epoch));
        Assert.Equal(new[]{"r1"},new FirebaseFirestoreSignalState(Path,Epoch).Accept(snapshot));
    }
}
