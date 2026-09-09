using Kaevo.Plugin.KaevoForJellyfin.Configuration;

namespace Kaevo.Plugin.KaevoForJellyfin.Services;

internal static class KaevoTwoWayProfileDeletionPolicy
{
    internal const string DisabledState = "two_way_profile_deletion_disabled";

    internal static bool Allows(PluginConfiguration? configuration) =>
        configuration?.TwoWayProfileDeletionEnabled == true;

    internal static void Require(PluginConfiguration? configuration)
    {
        if (!Allows(configuration))
        {
            throw new InvalidOperationException(DisabledState);
        }
    }
}
