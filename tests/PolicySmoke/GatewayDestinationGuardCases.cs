using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using ProtectionLifecycle;

internal static class GatewayDestinationGuardCases
{
    internal static void Run()
    {
        var checks=0;
        void Require(bool value,string reason){if(!value)throw new InvalidDataException(reason);checks++;}
        void Refuse(Action action,string reason)
        {try{action();}catch(InvalidDataException){checks++;return;}throw new InvalidDataException("Guard accepted "+reason);}
        IPAddress Ip(string value)=>IPAddress.Parse(value);
        long now=100;
        var ownPublic=Ip("8.8.8.8");var otherPublic=Ip("1.1.1.1");var ownV6=Ip("2606:4700:4700::1111");
        var supplied=new[]{IPAddress.Loopback,Ip("192.168.1.5"),ownPublic,ownV6};var reads=0;
        IPAddress[] Read(){reads++;return supplied;}
        var guard=new GatewayDestinationGuard(Read,()=>now);
        Refuse(()=>guard.RequireRemotePublicAddress(ownPublic),"own public IPv4 service");
        Refuse(()=>guard.RequireRemotePublicAddress(ownV6),"own public IPv6 service");
        foreach(var value in new[]{"127.0.0.1","10.1.2.3","192.168.1.5","169.254.169.254","::1","fc00::1","::ffff:8.8.8.8"})
            Refuse(()=>guard.RequireRemotePublicAddress(Ip(value)),"local/special/mapped target");
        guard.RequireRemotePublicAddress(otherPublic);checks++;
        var at=reads;guard.AssertCurrent();Require(reads==at,"per-write health uses bounded one-second snapshot interval");
        now+=999;guard.AssertCurrent();Require(reads==at,"snapshot not refreshed early");
        now++;guard.AssertCurrent();Require(reads==at+1,"snapshot refreshed at one second");
        at=reads;guard.RequireRemotePublicAddress(otherPublic);Require(reads==at+1,"new tunnel always forces a current capture");
        supplied=new[]{ownV6,ownPublic,ownPublic,Ip("192.168.1.5"),IPAddress.Loopback};guard.AssertCurrent(true);checks++;
        supplied=supplied.Append(otherPublic).ToArray();Refuse(()=>guard.AssertCurrent(true),"newly local public address revokes existing tunnels");
        supplied=new[]{IPAddress.Loopback,Ip("192.168.1.5"),ownPublic,ownV6};Refuse(()=>guard.AssertCurrent(true),"restoring old snapshot cannot revive revoked owner");
        Refuse(()=>guard.RequireRemotePublicAddress(Ip("9.9.9.9")),"revoked owner cannot start another public tunnel");
        var alias=new GatewayDestinationGuard(()=>new[]{Ip("::ffff:8.8.8.8")},()=>100);
        Refuse(()=>alias.RequireRemotePublicAddress(ownPublic),"mapped local alias cannot disguise local IPv4");
        var scoped=Ip("2606:4700:4700::1111");scoped.ScopeId=9;
        var scopes=new GatewayDestinationGuard(()=>new[]{scoped},()=>100);
        Refuse(()=>scopes.RequireRemotePublicAddress(ownV6),"scope ID cannot disguise identical local address bytes");
        foreach(var data in new IPAddress[][]{Array.Empty<IPAddress>(),null!,new IPAddress[]{null!},Enumerable.Repeat(IPAddress.Loopback,4097).ToArray()})
            Refuse(()=>new GatewayDestinationGuard(()=>data,()=>100),"missing/null/oversized inventory");
        foreach(var failure in new Exception[]{new NetworkInformationException(5),new SocketException(10013),new InvalidOperationException("OWN_NONSECRET_DETAIL"),new PlatformNotSupportedException(),new System.Security.SecurityException("OWN_NONSECRET_DETAIL")})
        {
            var captured=false;
            try{_=new GatewayDestinationGuard(()=>throw failure,()=>100);}
            catch(InvalidDataException error){captured=error.Message=="GatewayAddressInventoryUnconfirmed" && error.InnerException is null;}
            Require(captured,"native provider failure returns a fixed error without details");
        }
        IPAddress[]? current=new[]{IPAddress.Loopback};var uncertain=new GatewayDestinationGuard(()=>current!,()=>100);
        current=null;Refuse(()=>uncertain.AssertCurrent(true),"failed refresh never keeps a formerly valid snapshot");
        current=new[]{IPAddress.Loopback};Refuse(()=>uncertain.AssertCurrent(true),"failed snapshot cannot recover implicitly");
        long tick=100;var clock=new GatewayDestinationGuard(()=>new[]{IPAddress.Loopback},()=>tick);tick=99;
        Refuse(()=>clock.AssertCurrent(),"backward monotonic clock");tick=100;Refuse(()=>clock.AssertCurrent(),"clock failure is irreversible");
        Refuse(()=>new GatewayDestinationGuard(()=>new[]{IPAddress.Loopback},()=>-1),"unknown initial clock");
        var exposed=new[]{IPAddress.Loopback,ownPublic};var immutable=new GatewayDestinationGuard(()=>exposed,()=>100);
        exposed[1]=otherPublic;Refuse(()=>immutable.RequireRemotePublicAddress(ownPublic),"caller array mutation is drift rather than changing captured identity");
        var noExport=typeof(GatewayDestinationGuard).GetProperties(System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.Public|System.Reflection.BindingFlags.NonPublic);
        Require(noExport.Length==0,"guard exposes no address snapshot or adapter fields");
        Console.WriteLine($"PASS gateway host-destination guard: {checks} checks; own public IPv4/IPv6 refused, other public control allowed, aliases/scope/null/oversize/errors/drift/clock refused and revocation irreversible. Injected nonsecret fixture addresses only; no OS adapter enumeration, sockets, DNS, proxy, UAC, WFP, Job or product execution.");
    }
}
