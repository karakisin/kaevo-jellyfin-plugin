using Kaevo.Plugin.KaevoForJellyfin.Services;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Plugins;
using Microsoft.Extensions.DependencyInjection;

namespace Kaevo.Plugin.KaevoForJellyfin;

public sealed class PluginServiceRegistrator : IPluginServiceRegistrator
{
    public void RegisterServices(IServiceCollection serviceCollection, IServerApplicationHost applicationHost)
    {
        serviceCollection.AddSingleton<KaevoCloudState>();
        serviceCollection.AddSingleton<KaevoSecretStore>();
        serviceCollection.AddSingleton<KaevoOptimizerCoordinator>();
        serviceCollection.AddHostedService<KaevoCloudConnectorService>();
    }
}
