using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;

namespace ProtectionLifecycle;

// Configuration can disqualify a route. A snapshot cannot prove where the
// proxy sends a later CONNECT, even if no direct policy is visible in it.
internal sealed record ProxyRouteObservation(string Status,bool ReachableDirect,bool DirectEmptyFallback,bool ManualDirectChoice,bool Complete,
    bool SelectableDirectRoute,bool SelectionGraphComplete)
{
    internal const int MaxConfigBytes=16384,MaxProxyBytes=524288;
    private const int MaxNodes=512,MaxHops=32;
    internal static ProxyRouteObservation Unavailable=>new("CONTROLLER_EVIDENCE_UNAVAILABLE",false,false,false,false,false,false);
    public bool AllowsRoutePrecheck=>Complete && SelectionGraphComplete && !ReachableDirect && !SelectableDirectRoute;
    internal void RequireAllowed(string stage)
    {
        if(!AllowsRoutePrecheck)throw WfpNative.Contract(stage);
    }

    internal static ProxyRouteObservation EvaluateWithConfigReadback(byte[] before,byte[] inventory,byte[] after)
    {
        if(before.Length is <2 or >MaxConfigBytes || after.Length is <2 or >MaxConfigBytes)return Unavailable;
        return before.AsSpan().SequenceEqual(after)?Evaluate(before,inventory):
            new("CONTROLLER_CONFIG_CHANGED_DURING_SNAPSHOT",false,false,false,false,false,false);
    }

    internal static ProxyRouteObservation Evaluate(byte[] config,byte[] inventory)
    {
        if(config.Length is <2 or >MaxConfigBytes || inventory.Length is <2 or >MaxProxyBytes)return Unavailable;
        try
        {
            var options=new JsonDocumentOptions{MaxDepth=24};
            using var settings=JsonDocument.Parse(config,options);
            var mode=Name(Fields(settings.RootElement),"mode");
            if(mode=="direct")return new("DIRECT_MODE",true,false,false,true,true,true);
            if(mode!="global")return new("GLOBAL_MODE_NOT_OBSERVED",false,false,false,false,false,false);

            using var document=JsonDocument.Parse(inventory,options);
            var nodes=Fields(Fields(document.RootElement).GetValueOrDefault("proxies"));
            if(!nodes.TryGetValue("GLOBAL",out var global) || Name(Fields(global),"type")!="Selector")return Unavailable;
            var current=Walk(nodes,includeUnselected:false);
            var selectable=Walk(nodes,includeUnselected:true);
            return new(current.Direct?"DIRECT_ROUTE_REACHABLE":current.Complete?"NO_DIRECT_ROUTE_IN_SNAPSHOT":"ROUTE_EVIDENCE_INCOMPLETE",
                current.Direct,current.EmptyFallback,current.ManualChoice,current.Complete,selectable.Direct,selectable.Complete);
        }
        catch(Exception error) when(error is JsonException or InvalidDataException){return Unavailable;}
    }

    private static (bool Direct,bool EmptyFallback,bool ManualChoice,bool Complete) Walk(Dictionary<string,JsonElement> nodes,bool includeUnselected)
    {
        var active=new HashSet<string>(StringComparer.Ordinal);
        var visited=new HashSet<string>(StringComparer.Ordinal);
        bool direct=false,emptyFallback=false,manualChoice=false,complete=true;
        Visit("GLOBAL",0);
        return(direct,emptyFallback,manualChoice,complete);

        void Visit(string name,int depth)
        {
            if(depth>MaxHops || active.Contains(name)){complete=false;return;}
            if(!visited.Add(name))return;
            if(IsDirect(name)){direct=true;return;}
            if(!nodes.TryGetValue(name,out var value)){complete=false;return;}
            var node=Fields(value);
            if(Name(node,"name")!=name){complete=false;return;}
            var type=Name(node,"type")?.ToUpperInvariant();
            if(!node.TryGetValue("dialer-proxy",out var dialer) ||
                dialer.ValueKind!=JsonValueKind.String || dialer.GetString()!="")complete=false;
            if(type is not ("SELECTOR" or "FALLBACK" or "URLTEST" or "LOADBALANCE"))
            {
                if(type is not ("REJECT" or "REJECTDROP" or "VLESS" or "VMESS" or "TROJAN" or "SHADOWSOCKS" or
                    "SHADOWSOCKSR" or "SOCKS5" or "HTTP" or "HYSTERIA" or "HYSTERIA2" or "TUIC" or "WIREGUARD" or "SSH"))
                    complete=false;
                return;
            }

            active.Add(name);
            if(Name(node,"emptyFallback") is { } fallback)
            {
                if(IsDirect(fallback))emptyFallback=true;
                Visit(fallback,depth+1);
            }
            else complete=false;
            var all=node.GetValueOrDefault("all");
            if(all.ValueKind!=JsonValueKind.Array || all.GetArrayLength()>MaxNodes)complete=false;
            else
            {
                var members=new HashSet<string>(StringComparer.Ordinal);
                foreach(var member in all.EnumerateArray())
                {
                    if(Text(member) is not { } memberName || !members.Add(memberName)){complete=false;continue;}
                    if(type=="SELECTOR")manualChoice|=IsDirect(memberName);
                    if(type!="SELECTOR" || includeUnselected)Visit(memberName,depth+1);
                }
                if(type=="SELECTOR" && members.Count>0)
                {
                    var selected=Name(node,"now");
                    if(selected is null || !members.Contains(selected))complete=false;
                    else if(!includeUnselected)Visit(selected,depth+1);
                }
            }
            active.Remove(name);
        }

        bool IsDirect(string name)
        {
            if(IsDirectPolicy(name))return true;
            return nodes.TryGetValue(name,out var value) && Name(Fields(value),"type") is { } type && IsDirectPolicy(type);
        }
    }

    private static bool IsDirectPolicy(string name)=>name.Equals("DIRECT",StringComparison.OrdinalIgnoreCase) ||
        name.Equals("COMPATIBLE",StringComparison.OrdinalIgnoreCase);

    private static Dictionary<string,JsonElement> Fields(JsonElement value)
    {
        if(value.ValueKind!=JsonValueKind.Object)throw new InvalidDataException("ProxyRouteObjectExpected");
        var fields=new Dictionary<string,JsonElement>(StringComparer.Ordinal);
        foreach(var field in value.EnumerateObject())
            if(fields.Count>=MaxNodes || !fields.TryAdd(field.Name,field.Value))throw new InvalidDataException("ProxyRouteObjectAmbiguous");
        return fields;
    }

    private static string? Name(Dictionary<string,JsonElement> fields,string name)=>Text(fields.GetValueOrDefault(name));
    private static string? Text(JsonElement value)=>value.ValueKind==JsonValueKind.String && value.GetString() is {Length:>0 and <=256} text &&
        !text.Any(char.IsControl)?text:null;

    internal static async Task<ProxyRouteObservation> Capture(ProxyChannelLease proxy,CancellationToken cancellation=default)
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
        byte[]? config=null,inventory=null,configReadback=null;
        try
        {
            config=await client.GetByteArrayAsync("http://127.0.0.1:9090/configs",deadline.Token).ConfigureAwait(false);
            inventory=await client.GetByteArrayAsync("http://127.0.0.1:9090/proxies",deadline.Token).ConfigureAwait(false);
            configReadback=await client.GetByteArrayAsync("http://127.0.0.1:9090/configs",deadline.Token).ConfigureAwait(false);
            proxy.AssertControllerListener();
            return EvaluateWithConfigReadback(config,inventory,configReadback);
        }
        catch(Exception error) when(error is HttpRequestException or IOException or InvalidDataException or UnauthorizedAccessException or
            OperationCanceledException or System.ComponentModel.Win32Exception)
        {return Unavailable;}
        finally
        {
            if(config is not null)CryptographicOperations.ZeroMemory(config);
            if(inventory is not null)CryptographicOperations.ZeroMemory(inventory);
            if(configReadback is not null)CryptographicOperations.ZeroMemory(configReadback);
        }
    }
}
