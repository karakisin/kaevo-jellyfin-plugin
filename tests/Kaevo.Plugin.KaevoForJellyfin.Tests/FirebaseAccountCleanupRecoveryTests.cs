using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class FirebaseAccountCleanupRecoveryTests
{
    private const string Cid = "connector-1";
    private const string Oid = "ald2_01234567890123456789012345678901";
    private const string Rid = "01234567-0123-4567-89ab-012345678901";
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1800000000);
    private sealed class Clock : TimeProvider
    {
        internal DateTimeOffset NowValue = Now;
        public override DateTimeOffset GetUtcNow() => NowValue;
    }
    private static Dictionary<string, object> Body() => new()
    {
        ["state"]="account_cleanup", ["connector_control_protocol"]=2,
        ["connector_control_transport"]=FirebaseAccountCleanupRecovery.Transport,
        ["project_id"]=FirebaseFirestoreControlListener.DevelopmentProject, ["connector_id"]=Cid,
        ["operation_id"]=Oid, ["plan_digest"]="alfp1_"+new string('a',64), ["request_ids"]=new[]{Rid},
        ["expires_at"]=Now.AddSeconds(30).ToUnixTimeSeconds(), ["retry_after_seconds"]=15,
        ["cleanup_authorized"]=true, ["activation_allowed"]=false,
    };
    private static FirebaseAccountCleanupRecovery Receipt(Dictionary<string, object>? body = null) =>
        FirebaseAccountCleanupRecovery.Parse(JsonSerializer.SerializeToElement(body??Body()),Cid,Now);
    private static CloudRequest Request() => new(Rid, "COMMAND", "home_server",
        "/commands/"+KaevoCloudConnectorService.LifecycleV2JellyfinVerify, [],
        KaevoCloudConnectorService.LifecycleV2JellyfinVerify,
        new() { ["operation_id"]=JsonSerializer.SerializeToElement(Oid) }, "profile-1",new("jellyfin",Cid,new string('c',32)));

    [Fact]
    public void ReceiptCarriesNoOrdinaryMediaOrFirebaseLoginAuthority()
    {
        var value=Receipt(); value.RequireClaim(Request());
        Assert.Equal(new[]{Rid},value.RequestIds);
        Assert.DoesNotContain(Oid,value.ToString());
        Assert.Contains(FirebaseAccountCleanupRecovery.Capability,KaevoCloudConnectorService.ConnectorCapabilities);
    }

    [Theory]
    [InlineData("state","issued")]
    [InlineData("project_id","foreign-project")]
    [InlineData("connector_id","foreign")]
    [InlineData("connector_control_transport","firestore-signals-v1")]
    [InlineData("operation_id","ald2_short")]
    [InlineData("plan_digest","changed")]
    [InlineData("cleanup_authorized",false)]
    [InlineData("activation_allowed",true)]
    [InlineData("retry_after_seconds",0)]
    [InlineData("retry_after_seconds",16)]
    [InlineData("custom_token","forbidden")]
    [InlineData("connection_id","forbidden")]
    public void MalformedOrForeignReceiptCannotBecomeACommand(string field,object value)
    {
        var body=Body();body[field]=value;
        Assert.Throws<InvalidOperationException>(()=>Receipt(body));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    public void ExpiredOrExtendedHintWindowIsRejected(int seconds)
    {
        var body=Body();body["expires_at"]=Now.AddSeconds(seconds).ToUnixTimeSeconds();
        Assert.Throws<InvalidOperationException>(()=>Receipt(body));
    }

    [Fact]
    public void DuplicateJsonFieldsAndDuplicateOrMediaHintsAreRejected()
    {
        var json=JsonSerializer.Serialize(Body()).Replace("\"state\":", "\"state\":\"account_cleanup\",\"state\":");
        using var parsed=JsonDocument.Parse(json);
        Assert.Throws<InvalidOperationException>(()=>FirebaseAccountCleanupRecovery.Parse(parsed.RootElement,Cid,Now));
        foreach(var ids in new[]{new[]{Rid,Rid},new[]{"relay-demand:"+Rid},Enumerable.Repeat(Rid,33).ToArray()})
        {
            var body=Body();body["request_ids"]=ids;Assert.Throws<InvalidOperationException>(()=>Receipt(body));
        }
    }

    [Theory]
    [InlineData("media")]
    [InlineData("foreign-operation")]
    [InlineData("foreign-connector")]
    [InlineData("foreign-request")]
    [InlineData("eligibility")]
    public async Task WrongClaimNeverReachesProviderHandler(string change)
    {
        var request=Request();
        request=change switch
        {
            "media"=>request with {Operation="jellyfin.prepare_playback"},
            "foreign-operation"=>request with {Parameters=new(){["operation_id"]=JsonSerializer.SerializeToElement("ald2_foreign")}},
            "foreign-connector"=>request with {ProfileProviderBinding=new("jellyfin","foreign",new string('c',32))},
            "foreign-request"=>request with {RequestId="11234567-0123-4567-89ab-012345678901"},
            _=>request with {Operation=KaevoCloudConnectorService.LifecycleV2JellyfinEligibility},
        };
        var handled=0;var delays=0;
        await Assert.ThrowsAsync<InvalidOperationException>(()=>FirebaseAccountCleanupRecovery.RunBatchAsync(Receipt(),
            (_,_)=>Task.FromResult<CloudRequest?>(request),(_,_)=>{handled++;return Task.CompletedTask;},
            CancellationToken.None,new Clock(),(_,_)=>{delays++;return Task.CompletedTask;}));
        Assert.Equal(0,handled);Assert.Equal(1,delays);
    }

    [Fact]
    public async Task ClaimedCommandDrainsAfterReceiptExpiryAndNullClaimIsNotRetried()
    {
        var body=Body();var second="11234567-0123-4567-89ab-012345678901";body["request_ids"]=new[]{second,Rid};
        var receipt=Receipt(body);var clock=new Clock();var calls=new List<string>();var handled=0;
        await FirebaseAccountCleanupRecovery.RunBatchAsync(receipt,(id,_)=>
        {
            calls.Add(id);if(id==second)return Task.FromResult<CloudRequest?>(null);
            clock.NowValue=Now.AddSeconds(31);return Task.FromResult<CloudRequest?>(Request());
        },(_,_)=>{handled++;return Task.CompletedTask;},CancellationToken.None,clock,
            (duration,_)=>{Assert.Equal(15,duration.TotalSeconds);return Task.CompletedTask;});
        Assert.Equal(new[]{second,Rid},calls);Assert.Equal(1,handled);
    }

    [Fact]
    public async Task HostCancellationPreventsAnyNewClaim()
    {
        using var stop=new CancellationTokenSource();stop.Cancel();var claimed=0;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>FirebaseAccountCleanupRecovery.RunBatchAsync(Receipt(),
            (_,_)=>{claimed++;return Task.FromResult<CloudRequest?>(Request());},(_,_)=>Task.CompletedTask,
            stop.Token,new Clock(),(_,token)=>Task.FromCanceled(token)));
        Assert.Equal(0,claimed);
    }

    [Fact]
    public async Task FailedNormalStartupDrainsBeforeCleanupAndHealthyStartupNeverUsesIt()
    {
        var events=new List<string>();
        await FirebaseAccountCleanupRecovery.RunSessionAsync(async () =>
        {
            try { events.Add("normal");await Task.Yield();throw new InvalidOperationException(); }
            finally { events.Add("drained"); }
        },()=>{events.Add("cleanup");return Task.CompletedTask;},CancellationToken.None);
        Assert.Equal(new[]{"normal","drained","cleanup"},events);
        await FirebaseAccountCleanupRecovery.RunSessionAsync(()=>Task.CompletedTask,
            ()=>throw new Exception("cleanup must not run"),CancellationToken.None);
    }

    [Fact]
    public async Task CancelledStartupCannotStartCleanupAndRejectedCleanupPropagates()
    {
        using var stop=new CancellationTokenSource();stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>FirebaseAccountCleanupRecovery.RunSessionAsync(
            ()=>Task.FromCanceled(stop.Token),()=>throw new Exception("cleanup must not run"),stop.Token));
        await Assert.ThrowsAsync<InvalidOperationException>(()=>FirebaseAccountCleanupRecovery.RunSessionAsync(
            ()=>Task.FromException(new Exception()),()=>Task.FromException(new InvalidOperationException()),CancellationToken.None));
    }
}
