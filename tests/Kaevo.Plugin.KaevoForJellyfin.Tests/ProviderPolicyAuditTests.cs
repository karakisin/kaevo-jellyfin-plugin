using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class ProviderPolicyAuditTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "kaevo-provider-audit-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task AuditUsesPseudonymousDestinationAndNeverWritesUrlOrCredential()
    {
        var store = new KaevoProviderPolicyAuditStore(_directory);
        await store.RecordAsync("sonarr", "approved", "private", new Uri("https://provider.secret.test:8989/base?key=canary"), "approved", default);
        var text = await File.ReadAllTextAsync(Path.Combine(_directory, "provider-policy.jsonl"));
        Assert.Contains("pdr1_", text);
        Assert.DoesNotContain("provider.secret.test", text);
        Assert.DoesNotContain("canary", text);
        Assert.DoesNotContain("/base", text);
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Combine(_directory, "provider-policy.jsonl")));
        }
    }

    public void Dispose() { if (Directory.Exists(_directory)) Directory.Delete(_directory, true); }
}
