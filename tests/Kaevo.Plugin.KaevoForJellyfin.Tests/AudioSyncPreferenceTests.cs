using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class AudioSyncPreferenceTests
{
    private const string Item = "123456781234123412341234567890ab";
    [Fact]
    public void UserIsolationAccountSharingAndRestartPersistence()
    {
        var path = Path.Combine(Path.GetTempPath(), "kaevo-audio-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new KaevoAudioSyncPreferenceStore(path);
            string Key(string profile, string scope, string account = "account1") => KaevoAudioSyncPreferenceStore.Key("connector1", account, profile, Item, scope);
            Assert.Null(store.Read(Key("profile1", "user")));
            Assert.Equal(-120, store.Write(Key("profile1", "user"), -120));
            Assert.Null(store.Read(Key("profile2", "user")));
            Assert.Equal(250, store.Write(Key("profile1", "account"), 250));
            Assert.Equal(250, store.Read(Key("profile2", "account")));
            Assert.Null(store.Read(Key("profile1", "account", "account2")));
            var reopened = new KaevoAudioSyncPreferenceStore(path);
            Assert.Equal(-120, reopened.Read(Key("profile1", "user")));
            Assert.Equal(0, reopened.Write(Key("profile1", "user"), 0));
            Assert.Equal(0, new KaevoAudioSyncPreferenceStore(path).Read(Key("profile1", "user")));
            Assert.Throws<InvalidOperationException>(() => store.Write(Key("profile1", "user"), 5001));
        }
        finally { Directory.Delete(path, true); }
    }
    [Fact]
    public void CorruptionDoesNotBecomeASuccessfulDefault()
    {
        var path = Path.Combine(Path.GetTempPath(), "kaevo-audio-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new KaevoAudioSyncPreferenceStore(path);
            var key = KaevoAudioSyncPreferenceStore.Key("connector", "account", "profile", Item, "user");
            File.WriteAllText(Path.Combine(path, key + ".json"), "{}");
            Assert.Throws<InvalidOperationException>(() => store.Read(key));
            Assert.Throws<InvalidOperationException>(() => store.Write(key, 10));
            Assert.Throws<InvalidOperationException>(() => store.Read("../outside"));
        }
        finally { Directory.Delete(path, true); }
    }
    [Fact]
    public void CommandRequiresTrustedAccountAndExactProviderBinding()
    {
        var request = new CloudRequest("request", "COMMAND", "home_server", "/commands/jellyfin.audio_sync_set", null,
            "jellyfin.audio_sync_set", new() { ["item_id"] = JsonSerializer.SerializeToElement(Item),
                ["scope"] = JsonSerializer.SerializeToElement("user"), ["offset_ms"] = JsonSerializer.SerializeToElement(10) },
            "profile", new("jellyfin", "connector", Item), AudioSyncAuthority: new("account"));
        Assert.NotEmpty(KaevoCloudConnectorService.AudioSyncPreferenceKey("connector", request));
        Assert.Throws<InvalidOperationException>(() => KaevoCloudConnectorService.AudioSyncPreferenceKey("other", request));
        Assert.Throws<InvalidOperationException>(() => KaevoCloudConnectorService.AudioSyncPreferenceKey("connector", request with { AudioSyncAuthority = null }));
        request.Parameters!["account_id"] = JsonSerializer.SerializeToElement("spoofed");
        Assert.Throws<InvalidOperationException>(() => KaevoCloudConnectorService.AudioSyncPreferenceKey("connector", request));
    }
}
