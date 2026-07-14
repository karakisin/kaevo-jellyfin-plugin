using MediaBrowser.Model.Plugins;

namespace Kaevo.Plugin.KaevoForJellyfin.Configuration;

public sealed class PluginConfiguration : BasePluginConfiguration
{
    public bool CloudRelayEnabled { get; set; } = false;

    public int SnapshotItemLimit { get; set; } = 50;
}
