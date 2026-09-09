using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Kaevo.Plugin.KaevoForJellyfin.Configuration;
using Kaevo.Plugin.KaevoForJellyfin.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
namespace Kaevo.Plugin.KaevoForJellyfin.Tests;
public class ProfileArtworkAccessTests
{
    [Theory]
    [InlineData(200, true, true)]
    [InlineData(404, true, false)]
    [InlineData(200, false, false)]
    public async Task ImageBytesRequireExactProfileItemAccess(int status, bool sameItem, bool allowed)
    {
        const string item = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", user = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        using var provider = new Provider(status, sameItem ? item : new string('c',32));
        using var http = new HttpClient(provider);
        var service = new KaevoCloudConnectorService(null!, null!, null!, null!, null!, null!, null!, null!,
            null!, null!, null!, null!, null!, NullLogger<KaevoCloudConnectorService>.Instance);
        const BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic;
        var field = typeof(KaevoCloudConnectorService).GetField("_jellyfin",flags)!;
        ((HttpClient)field.GetValue(service)!).Dispose(); field.SetValue(service,http);
        var config = new PluginConfiguration { LocalJellyfinBaseUrl="http://fixture.invalid", ProfileJellyfinBindingsJson=JsonSerializer.Serialize(new Dictionary<string,string>{{"profile",user}}) };
        var query = new Dictionary<string,JsonElement> { ["item_id"]=JsonSerializer.SerializeToElement(item),["image_type"]=JsonSerializer.SerializeToElement("Primary") };
        var task = (Task)typeof(KaevoCloudConnectorService).GetMethod("ReadArtworkAsync",flags)!.Invoke(service,[config,new KaevoConnectorSecrets("", "", "synthetic"),"profile",query,CancellationToken.None])!;
        if(allowed) await task; else await Assert.ThrowsAsync<InvalidOperationException>(async()=>await task);
        Assert.Equal($"/Users/{user}/Items/{item}",provider.Paths[0]);
        Assert.Equal(allowed ? 2 : 1,provider.Paths.Count);
    }
    private sealed class Provider(int status,string item) : HttpMessageHandler
    {
        public List<string> Paths {get;}=[];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancellationToken)
        {
            Paths.Add(request.RequestUri!.AbsolutePath);
            var reply=new HttpResponseMessage(Paths.Count==1?(HttpStatusCode)status:HttpStatusCode.OK);
            if(Paths.Count==1) reply.Content=new StringContent(JsonSerializer.Serialize(new {Id=item}),Encoding.UTF8,"application/json");
            else { reply.Content=new ByteArrayContent([137,80,78,71,13,10,26,10]);reply.Content.Headers.ContentType=new("image/png"); }
            return Task.FromResult(reply);
        }
    }
}
