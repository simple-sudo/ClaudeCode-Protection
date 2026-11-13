using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace ProtectionLifecycle;

internal sealed partial record ProxyRouteObservation
{
    internal static async Task<ProxyRouteObservation> Capture(ProxyChannelLease proxy,CancellationToken cancellation=default)
        => await CaptureCore(proxy, stableSelection: false, cancellation).ConfigureAwait(false);

    internal static async Task<ProxyRouteObservation> CaptureStableSelection(ProxyChannelLease proxy, CancellationToken cancellation)
        => await CaptureCore(proxy, stableSelection: true, cancellation).ConfigureAwait(false);

    private static async Task<ProxyRouteObservation> CaptureCore(ProxyChannelLease proxy, bool stableSelection, CancellationToken cancellation)
    {
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        deadline.CancelAfter(TimeSpan.FromSeconds(3));
        using var handler=new SocketsHttpHandler {UseProxy=false,AllowAutoRedirect=false,UseCookies=false,MaxResponseHeadersLength=8};
        handler.ConnectCallback=async (context,cancel)=>
        {
            if(context.DnsEndPoint.Host!="127.0.0.1" || context.DnsEndPoint.Port!=LocalManagementBoundary.ControllerPort)
                throw new InvalidDataException("UnexpectedProxyControllerEndpoint");
            var socket=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp);
            try
            {
                await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback,LocalManagementBoundary.ControllerPort),cancel).ConfigureAwait(false);
                proxy.AssertControllerPeer(socket);
                return new NetworkStream(socket,ownsSocket:true);
            }
            catch{socket.Dispose();throw;}
        };
        using var client=new HttpClient(handler){DefaultVersionPolicy=HttpVersionPolicy.RequestVersionExact,MaxResponseContentBufferSize=MaxProxyBytes};
        client.DefaultRequestHeaders.ConnectionClose=true;
        byte[]? config=null,inventory=null,inventoryReadback=null,configReadback=null;
        try
        {
            config=await client.GetByteArrayAsync("http://127.0.0.1:9090/configs",deadline.Token).ConfigureAwait(false);
            inventory=await client.GetByteArrayAsync("http://127.0.0.1:9090/proxies",deadline.Token).ConfigureAwait(false);
            if (stableSelection)
                inventoryReadback=await client.GetByteArrayAsync("http://127.0.0.1:9090/proxies",deadline.Token).ConfigureAwait(false);
            configReadback=await client.GetByteArrayAsync("http://127.0.0.1:9090/configs",deadline.Token).ConfigureAwait(false);
            proxy.AssertControllerListener();
            return stableSelection
                ? EvaluateStableSelection(config, inventory, inventoryReadback!, configReadback)
                : EvaluateWithConfigReadback(config,inventory,configReadback);
        }
        catch(Exception error) when(error is HttpRequestException or IOException or InvalidDataException or UnauthorizedAccessException or
            OperationCanceledException or System.ComponentModel.Win32Exception)
        {return Unavailable;}
        finally
        {
            if(config is not null)CryptographicOperations.ZeroMemory(config);
            if(inventory is not null)CryptographicOperations.ZeroMemory(inventory);
            if(inventoryReadback is not null)CryptographicOperations.ZeroMemory(inventoryReadback);
            if(configReadback is not null)CryptographicOperations.ZeroMemory(configReadback);
        }
    }
}
