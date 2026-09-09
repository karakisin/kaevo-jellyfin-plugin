using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Kaevo.Plugin.KaevoForJellyfin.Configuration;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;
namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class FirebaseMigrationTests : IDisposable
{
    readonly string directory = Path.Combine(Path.GetTempPath(), "kaevo-migration-" + Guid.NewGuid().ToString("N"));
    const string User = "bf37113a073e40e8a22cd100cb3b8ac2";
    readonly KaevoPairingV3Identity identity;
    readonly KaevoPairingV3Connector before;
    public FirebaseMigrationTests()
    {
        var seed = new byte[32]; seed[0] = 17;
        var key = KaevoPairingV3Crypto.PublicKeyFromSeed(seed);
        identity = new("a1111111-1111-4111-8111-111111111111", KaevoPairingV3Crypto.Base64Url(seed), KaevoPairingV3Crypto.Base64Url(key), KaevoPairingV3Crypto.Fingerprint(key), DateTimeOffset.UtcNow);
        before = new("old-connector", identity.PluginInstanceId, identity.PublicKeyBase64Url, identity.Fingerprint, 1, "old-account", "old-family", "server", User, DateTimeOffset.UtcNow, "active", "attempt", KaevoPairingV3Crypto.Protocol);
    }
    JsonObject Payload() => new()
    {
        ["state"]="connector_migration_prepared", ["project_id"]=FirebaseFirestoreControlListener.DevelopmentProject,
        ["transition_id"]=new string('a',64), ["old_connector_id"]=before.ConnectorId,
        ["expires_at"]=DateTimeOffset.UtcNow.ToUnixTimeSeconds()+600, ["activation_allowed"]=false,
        ["jellyfin_user_id"]=User, ["profile_bindings"]=new JsonObject { ["original-profile"]=User },
        ["binding"]=new JsonObject { ["connector_id"]="original-connector", ["plugin_instance_id"]=before.PluginInstanceId,
            ["plugin_key_id"]="1", ["plugin_public_key_fingerprint"]=before.PluginFingerprint, ["jellyfin_server_id"]=before.JellyfinServerId,
            ["account_id"]="original-account", ["household_id"]="original-household", ["profile_id"]="original-profile",
            ["account_binding"]="original-account-binding", ["family_binding"]="original-family-binding" }
    };
    KaevoFirebaseMigrationJournal Validate(JsonObject payload) => KaevoPairingV3Service.ValidateFirebaseMigration(
        JsonSerializer.SerializeToElement(payload), before, "https://old.example", "old-profile", "{}", User, id=>id==User);
    public sealed class Jellyfin11Users
    {
        public IEnumerable<Guid> GetUsersIds() => new[] { Guid.ParseExact(User,"N") };
    }
    [Fact] public void TransferValidatesJellyfin11UserIdsWithoutLegacyUsersProperty()
    {
        var manager=new Jellyfin11Users();
        Assert.Null(manager.GetType().GetProperty("Users"));
        var result=KaevoPairingV3Service.ValidateFirebaseMigration(JsonSerializer.SerializeToElement(Payload()),
            before,"https://old.example","old-profile","{}",User,
            id=>Guid.TryParseExact(id,"N",out var value)&&KaevoJellyfinUserLookup.Exists(manager,value));
        Assert.Equal(User,result.JellyfinUserId);
    }
    [Fact] public void ExactTransferPreservesKeyAndPairingProvenance()
    {
        var result=Validate(Payload());
        Assert.Equal(before with { ConnectorId="original-connector", AccountBinding="original-account-binding", FamilyBinding="original-family-binding", LastContactState="firebase_migrated_paused" }, result.After);
    }
    [Theory]
    [InlineData("project_id")][InlineData("old_connector_id")][InlineData("transition_id")][InlineData("jellyfin_user_id")]
    public void ForeignRootIdentityRejected(string field) { var p=Payload();p[field]="foreign";Assert.ThrowsAny<Exception>(()=>Validate(p)); }
    [Theory]
    [InlineData("plugin_instance_id")][InlineData("plugin_key_id")][InlineData("plugin_public_key_fingerprint")][InlineData("jellyfin_server_id")]
    public void ChangedKeyOrServerRejected(string field) { var p=Payload();p["binding"]![field]="foreign";Assert.ThrowsAny<Exception>(()=>Validate(p)); }
    [Fact] public void ActivationAndExpiredPlansRejected()
    {
        var p=Payload();p["activation_allowed"]=true;Assert.ThrowsAny<Exception>(()=>Validate(p));
        p=Payload();p["expires_at"]=1;Assert.ThrowsAny<Exception>(()=>Validate(p));
        p=Payload();p["profile_bindings"]!["foreign-profile"]=new string('b',32);Assert.ThrowsAny<Exception>(()=>Validate(p));
    }
    sealed class Handler(Func<HttpRequestMessage,HttpResponseMessage> reply):HttpMessageHandler
    { public int Calls; protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage r,CancellationToken c) { Calls++;return Task.FromResult(reply(r)); } }
    [Fact] public async Task InterruptedConfigurationSaveRecoversWithoutAnotherCloudRequest()
    {
        var store=new KaevoPairingV3Store(directory);
        await store.MutateAsync(s=> {s.Identity=identity;s.Connector=before;return true;});
        var handler=new Handler(r=> {Assert.StartsWith(KaevoFirebaseRuntime.Endpoint,r.RequestUri!.AbsoluteUri); Assert.True(r.Headers.Contains("X-Kaevo-Plugin-Signature"));return new(HttpStatusCode.OK){RequestMessage=r,Content=new StringContent(Payload().ToJsonString(),Encoding.UTF8,"application/json")};});
        var service=new KaevoPairingV3Service(store,new KaevoPairingV3CloudClient(),()=>true,()=>"",connectorHttp:new HttpClient(handler));
        PluginConfiguration Config()=>new(){CloudConnectorEnabled=false,ConnectorId=before.ConnectorId,CloudBaseUrl="https://old.example",ProfileId="old-profile",ProfileJellyfinBindingsJson="{}",JellyfinUserId=User};
        var config=Config();
        await Assert.ThrowsAsync<IOException>(()=>service.MigrateFirebaseAsync(config,()=>true,()=>throw new IOException("disk"),id=>id==User,default));
        Assert.Equal("https://old.example",config.CloudBaseUrl);
        Assert.Equal(before.ConnectorId,config.ConnectorId);
        var recovered=Config();var saved=false;
        await service.MigrateFirebaseAsync(recovered,()=>true,()=>saved=true,id=>id==User,default);
        Assert.True(saved);Assert.False(recovered.CloudConnectorEnabled);Assert.Equal("original-profile",recovered.ProfileId);Assert.Equal(1,handler.Calls);
        Assert.Equal(identity,await store.ReadAsync(s=>s.Identity));
        recovered.ProfileId="foreign-profile";
        await Assert.ThrowsAsync<InvalidOperationException>(()=>service.MigrateFirebaseAsync(recovered,()=>true,()=>{},id=>true,default));
    }
    [Fact] public async Task EnabledConnectionCannotSendMigration()
    {
        var handler=new Handler(_=>throw new Exception("must not send"));
        var service=new KaevoPairingV3Service(new(directory),new KaevoPairingV3CloudClient(),()=>true,()=>"",connectorHttp:new HttpClient(handler));
        await Assert.ThrowsAsync<InvalidOperationException>(()=>service.MigrateFirebaseAsync(new(){CloudConnectorEnabled=true},()=>true,()=>{},_=>true,default));
        Assert.Equal(0,handler.Calls);
    }
    public void Dispose(){if(Directory.Exists(directory))Directory.Delete(directory,true);}
}
