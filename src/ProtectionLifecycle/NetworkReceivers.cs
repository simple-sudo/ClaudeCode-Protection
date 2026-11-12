using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed class NetworkReceivers : IDisposable
{
    internal static readonly string[] Roles={"tcp4-other-port","tcp4-other-address","tcp6","udp4","udp6","raw-dns-udp53"};
    private readonly List<Socket> sockets=new();
    private readonly List<Task> collectors=new();
    private readonly ConcurrentBag<(string Role,byte[] Data)> receipts=new();
    private readonly CancellationTokenSource stop=new();
    private readonly int[] ports=new int[5];
    internal NetworkReceivers()
    {
        try
        {
            ports[0]=Tcp(IPAddress.Loopback,Roles[0]);ports[1]=Tcp(IPAddress.Parse("127.0.0.2"),Roles[1]);ports[2]=Tcp(IPAddress.IPv6Loopback,Roles[2]);
            ports[3]=Udp(IPAddress.Loopback,0,Roles[3]);ports[4]=Udp(IPAddress.IPv6Loopback,0,Roles[4]);_=Udp(IPAddress.Parse("127.0.0.2"),53,Roles[5]);
        }
        catch(Exception failure){try{Dispose();}catch(Exception cleanup){throw new AggregateException(failure,cleanup);}throw;}
    }
    internal NetworkProbePlan Plan(NetworkProbeKind kind)=>new(kind,ports[0],ports[1],ports[2],ports[3],ports[4],Guid.NewGuid().ToString("N"));
    private Socket Bound(IPAddress address,SocketType type,ProtocolType protocol,int port)
    {
        var socket=new Socket(address.AddressFamily,type,protocol){ExclusiveAddressUse=true};sockets.Add(socket);
        if(address.AddressFamily==AddressFamily.InterNetworkV6)socket.DualMode=false;
        socket.Bind(new IPEndPoint(address,port));return socket;
    }
    private int Tcp(IPAddress address,string role)
    {
        var socket=Bound(address,SocketType.Stream,ProtocolType.Tcp,0);socket.Listen(8);collectors.Add(CollectTcp(socket,role));return ((IPEndPoint)socket.LocalEndPoint!).Port;
    }
    private int Udp(IPAddress address,int port,string role)
    {
        var socket=Bound(address,SocketType.Dgram,ProtocolType.Udp,port);collectors.Add(CollectUdp(socket,role));return ((IPEndPoint)socket.LocalEndPoint!).Port;
    }
    private async Task CollectTcp(Socket listener,string role)
    {
        try
        {
            while(!stop.IsCancellationRequested)
            {
                using var client=await listener.AcceptAsync(stop.Token);var bytes=new byte[128];
                using var timeout=CancellationTokenSource.CreateLinkedTokenSource(stop.Token);timeout.CancelAfter(2000);
                try
                {
                    var total=0;
                    while(total<bytes.Length){var count=await client.ReceiveAsync(bytes.AsMemory(total),SocketFlags.None,timeout.Token);if(count==0)break;total+=count;}
                    if(total>0)receipts.Add((role,bytes[..total]));
                }
                catch(OperationCanceledException) when(!stop.IsCancellationRequested){}
            }
        }
        catch(OperationCanceledException) when(stop.IsCancellationRequested){}
        catch(ObjectDisposedException) when(stop.IsCancellationRequested){}
        catch(SocketException) when(stop.IsCancellationRequested){}
    }
    private async Task CollectUdp(Socket socket,string role)
    {
        try
        {
            var bytes=new byte[512];
            while(!stop.IsCancellationRequested)
            {var count=await socket.ReceiveAsync(bytes,SocketFlags.None,stop.Token);if(count>0)receipts.Add((role,bytes[..count]));}
        }
        catch(OperationCanceledException) when(stop.IsCancellationRequested){}
        catch(ObjectDisposedException) when(stop.IsCancellationRequested){}
        catch(SocketException) when(stop.IsCancellationRequested){}
    }
    internal int[] ReceiptCounts(NetworkProbePlan plan)=>Roles.Select(role=>receipts.Count(r=>r.Role==role &&
        r.Data.AsSpan().SequenceEqual(role==Roles[5]?plan.DnsQuery:plan.Payload))).ToArray();
    internal void AssertCollecting()
    {
        if(stop.IsCancellationRequested || collectors.Count!=Roles.Length || collectors.Any(t=>t.IsCompleted))
            throw WfpNative.Contract("NetworkReceiverCollectorNotHealthy");
    }
    public void Dispose()
    {
        stop.Cancel();foreach(var socket in sockets)socket.Dispose();
        try{Task.WhenAll(collectors).GetAwaiter().GetResult();}finally{stop.Dispose();}
    }
}
