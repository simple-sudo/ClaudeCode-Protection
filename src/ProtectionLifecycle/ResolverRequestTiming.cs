using System.Diagnostics;
using System.Net;
using System.Net.Security;

namespace ProtectionLifecycle;

// A resolver cannot have produced the answer before the authenticated stream
// is ready for this HTTP request. Count all time from here through the target
// tunnel gates, while excluding the earlier proxy and TLS setup.
internal sealed class ResolverRequestTiming(HttpRequestMessage request)
{
    private long startedAt=-1;

    internal long StartedAt
    {
        get
        {
            var stamp=Volatile.Read(ref startedAt);
            return stamp>=0?stamp:throw WfpNative.Contract("ResolverRequestStartMissing");
        }
    }

    internal ValueTask<Stream> OnAuthenticatedStream(SocketsHttpPlaintextStreamFilterContext context,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if(!ReferenceEquals(context.InitialRequestMessage,request) || context.NegotiatedHttpVersion!=HttpVersion.Version11 ||
            context.PlaintextStream is not SslStream {IsAuthenticated:true,IsEncrypted:true,IsServer:false} ||
            Interlocked.CompareExchange(ref startedAt,Stopwatch.GetTimestamp(),-1)!=-1)
            throw WfpNative.Contract("ResolverRequestStartBindingDiffers");
        return ValueTask.FromResult(context.PlaintextStream);
    }
}
