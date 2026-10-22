using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Xunit;

namespace Kaevo.Plugin.KaevoForJellyfin.Tests;

public sealed class AccountDeletionEligibilityTests
{
    private static string User(int n) => n.ToString("x32");
    private static KaevoAccountDeletionEligibility.Target Target(int n) => new("profile-" + n, User(n));
    private static JsonElement Users(params (int Id, bool Admin)[] rows) => JsonSerializer.SerializeToElement(
        rows.Select(r => new { Id = User(r.Id), Policy = new { IsAdministrator = r.Admin } }));
    private static string? Resolve(string pid) => User(int.Parse(pid.Split('-').Last()));
    private static string Check(JsonElement rows, params int[] targets) =>
        KaevoAccountDeletionEligibility.Check(rows, targets.Select(Target).ToArray(), Resolve);

    [Fact]
    public void LastUserIsRejectedBeforeAnyProviderDelete()
    {
        var error = Assert.Throws<InvalidOperationException>(() => Check(Users((1, true)), 1));
        Assert.Equal("accountLifecycleV2LastJellyfinUser", error.Message);
    }

    [Fact]
    public void LastAdministratorIsRejectedEvenWithOtherNonAdminUsers()
    {
        var error = Assert.Throws<InvalidOperationException>(() => Check(Users((1, true), (2, false)), 1));
        Assert.Equal("accountLifecycleV2LastJellyfinAdministrator", error.Message);
    }

    [Fact]
    public void BatchCannotDeleteAllAdministratorsOneAtATime()
    {
        var rows = Users((1, true), (2, true), (3, false));
        Assert.Equal(64, Check(rows, 1).Length);
        Assert.Equal(64, Check(rows, 2).Length);
        var error = Assert.Throws<InvalidOperationException>(() => Check(rows, 1, 2));
        Assert.Equal("accountLifecycleV2LastJellyfinAdministrator", error.Message);
    }

    [Fact]
    public void RemainingAdministratorPermitsTheExactBatch()
    {
        Assert.Equal(64, Check(Users((1, true), (2, true), (3, false)), 1, 3).Length);
    }

    [Fact]
    public void AlreadyAbsentTargetsDoNotNeedARecreatedLocalBinding()
    {
        var digest = KaevoAccountDeletionEligibility.Check(Users((3, true)), new[] { Target(1), Target(2) },
            _ => throw new Exception("No absent identity may be rebound"));
        Assert.Equal(64, digest.Length);
    }

    [Fact]
    public void ExistingTargetRequiresItsExactLocalBinding()
    {
        Assert.Throws<InvalidOperationException>(() => KaevoAccountDeletionEligibility.Check(
            Users((1, false), (2, true)), new[] { Target(1) }, _ => User(2)));
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("[{\"Id\":\"00000000000000000000000000000001\"}]")]
    [InlineData("[{\"Id\":\"00000000000000000000000000000001\",\"Policy\":{\"IsAdministrator\":\"false\"}}]")]
    [InlineData("[{\"Id\":\"00000000000000000000000000000001\",\"Policy\":{\"IsAdministrator\":true,\"IsAdministrator\":false}}]")]
    [InlineData("[{\"Id\":\"invalid\",\"Policy\":{\"IsAdministrator\":false}}]")]
    public void MissingMalformedOrAmbiguousPolicyCannotApproveDeletion(string json)
    {
        using var doc = JsonDocument.Parse(json);
        Assert.Throws<InvalidOperationException>(() => Check(doc.RootElement, 1));
    }

    [Fact]
    public void DuplicateProviderIdentityIsRejected()
    {
        Assert.Throws<InvalidOperationException>(() => Check(Users((1, true), (1, false), (2, true)), 1));
    }

    private static Dictionary<string, JsonElement> Parameters(params int[] values) => new()
    {
        ["planned_jellyfin_deletions"] = JsonSerializer.SerializeToElement(values.Select(n =>
            new { profile_id = "profile-" + n, jellyfin_user_id = User(n) }))
    };
    private static KaevoCloudConnectorService.AccountLifecycleV2CommandContext Context() =>
        new("ald2_0123456789abcdef0123456789abcdef", "binding-12345678", "profile-1", "connector-1", User(1), 17);

    [Theory]
    [InlineData(new int[] {})]
    [InlineData(new int[] { 1, 1 })]
    [InlineData(new int[] { 2 })]
    public void PlanMustBeCompleteUniqueAndContainCurrentExactTarget(int[] targets)
    {
        Assert.Throws<InvalidOperationException>(() => KaevoAccountDeletionEligibility.Targets(Parameters(targets), Context()));
    }

    [Fact]
    public void AbsentPlanCannotFallBackToOnlyTheCurrentUser()
    {
        Assert.Throws<InvalidOperationException>(() => KaevoAccountDeletionEligibility.Targets(new Dictionary<string, JsonElement>(), Context()));
    }

    [Fact]
    public void EligibilityCommandUsesExistingBindingAndCannotRecreateIt()
    {
        Assert.True(KaevoCloudConnectorService.IsAccountLifecycleV2Operation(KaevoCloudConnectorService.LifecycleV2JellyfinEligibility));
        Assert.Contains("account_lifecycle_deletion_eligibility_v1", KaevoCloudConnectorService.ConnectorCapabilities);
    }
}
