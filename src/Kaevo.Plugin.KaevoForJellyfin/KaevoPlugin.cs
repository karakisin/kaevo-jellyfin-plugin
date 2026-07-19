using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;
using Kaevo.Plugin.KaevoForJellyfin.Configuration;
using Kaevo.Plugin.KaevoForJellyfin.Services;

namespace Kaevo.Plugin.KaevoForJellyfin;

public sealed class KaevoPlugin : BasePlugin<PluginConfiguration>, IHasWebPages
{
    public static readonly Guid PluginId = Guid.Parse("80c77b84-7f2d-4b52-84c7-7dfe68cd95ae");

    public KaevoPlugin(IApplicationPaths applicationPaths, IXmlSerializer xmlSerializer)
        : base(applicationPaths, xmlSerializer)
    {
        PackageIntegrityValid = KaevoPackageIntegrity.IsValidVersion(
            typeof(KaevoPlugin).Assembly.GetName().Version, typeof(KaevoPlugin).Assembly.Location);
        Instance = this;
    }

    public static KaevoPlugin? Instance { get; private set; }

    public bool PackageIntegrityValid { get; }

    public override string Name => "Kaevo";

    public override Guid Id => PluginId;

    public IEnumerable<PluginPageInfo> GetPages()
    {
        yield return new PluginPageInfo
        {
            Name = Name,
            EmbeddedResourcePath = GetType().Namespace + ".Configuration.configPage.html"
        };
    }
}
