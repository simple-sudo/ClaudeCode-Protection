using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace ProtectionLifecycle;

internal enum NetworkProbeKind { Control,Quarantine,Proxy,ProxyDenied,ProxySession }
internal sealed record NetworkProbePlan(NetworkProbeKind Kind,int TcpPort,int OtherAddressPort,int Tcp6Port,int UdpPort,int Udp6Port,string Nonce)
{
    internal bool RequiresProxy=>Kind is NetworkProbeKind.Proxy or NetworkProbeKind.ProxySession;
    internal void Validate()
    {
        if(!Enum.IsDefined(Kind) || new[]{TcpPort,OtherAddressPort,Tcp6Port,UdpPort,Udp6Port}.Any(p=>p is <1024 or >65535 || p==CompiledFencePolicy.ProxyPort))
            throw WfpNative.Contract("BoundedOwnedLoopbackEndpointsRequired");
        _=Identifiers.Hex32(Nonce);
    }
    internal byte[] Payload=>Encoding.ASCII.GetBytes("CPC-NET:"+Nonce);
    internal byte[] DnsQuery
    {
        get
        {
            var data=new List<byte>{0x43,0x50,1,0,0,1,0,0,0,0,0,0};
            foreach(var part in ("cpc-"+Nonce+".invalid").Split('.')){data.Add(checked((byte)part.Length));data.AddRange(Encoding.ASCII.GetBytes(part));}
            data.AddRange(new byte[]{0,0,1,0,1});return data.ToArray();
        }
    }
}
internal sealed record SocketProbe(string Role,bool SocketCallSucceeded,int? SocketError,string? FailureType);
internal sealed record NetworkTransportFailure(string Type,int Code,string? HttpError,int? SocketError,string? InnerType,int? InnerCode)
{
    internal static NetworkTransportFailure From(Exception error)
    {
        SocketException? socket=null;for(Exception? e=error;e is not null;e=e.InnerException)if(e is SocketException s){socket=s;break;}
        return new(error.GetType().Name,error.HResult,(error as HttpRequestException)?.HttpRequestError.ToString(),
            socket is null?null:(int)socket.SocketErrorCode,error.InnerException?.GetType().Name,error.InnerException?.HResult);
    }
}
internal sealed record NetworkChildReport(int SchemaVersion,int Pid,NetworkProbeKind Kind,string Nonce,SocketProbe[] Cases,int? ProxyHttpStatus,
    SocketProbe? ProxySocket,NetworkTransportFailure? ProxyFailure,TlsValidationObservation? TlsValidation,TlsCertificateObservation[]? CertificateChain,RevocationSupply? RevocationSupply,int FailureMask,bool SystemResolverQualified);
internal sealed record NetworkPhaseReport(NetworkProbeKind Kind,string JobId,NetworkChildReport? Child,int[]? IndependentReceiverCounts,
    int ReceiptObservationMs,bool Matched,WfpErrorEvidence[] Failures,bool ProfileDeleteAbsenceQualified);

// Receiver-side nonce receipts are independent of child Send return values.
// All listeners are freshly bound, exclusive, and loopback-only. Port 53 is
// used only on 127.0.0.2; an existing binding fails instead of being replaced.
