namespace ClaudeCodeProtection.Security;

// The session gateway's actual duplex copier. It owns neither streams nor
// sockets; its caller retains the deadline, revocation and endpoint lifetime.
internal static class SessionTunnel
{
    internal static async Task CopyAsync(Stream client,Stream upstream,Action clientFinishSending,Action upstreamFinishSending,
        Action<int> accountBytes,long directionLimit,Action assertAuthorized,CancellationToken token)
    {
        if(directionLimit is <1 or >8*1024*1024)throw new ArgumentOutOfRangeException(nameof(directionLimit));
        using var canceled=CancellationTokenSource.CreateLinkedTokenSource(token);
        async Task Pump(Stream input,Stream output,Action finishSending)
        {
            var buffer=new byte[16384];long total=0;
            while(true)
            {
                canceled.Token.ThrowIfCancellationRequested();
                assertAuthorized();
                var count=await input.ReadAsync(buffer,canceled.Token);
                if(count==0)
                {
                    canceled.Token.ThrowIfCancellationRequested();
                    assertAuthorized();
                    finishSending();return;
                }
                total+=count;
                if(total>directionLimit)throw new InvalidDataException("SessionTunnelByteBudgetExceeded");
                accountBytes(count); // Reserve the session budget BEFORE forwarding.
                assertAuthorized(); // A blocked read must not outlive permission.
                await output.WriteAsync(buffer.AsMemory(0,count),canceled.Token);
            }
        }
        var upload=Pump(client,upstream,upstreamFinishSending);
        var download=Pump(upstream,client,clientFinishSending);
        var all=Task.WhenAll(upload,download);
        try
        {
            // A normal EOF only sends FIN on that direction; the other pump
            // must still deliver its remaining bytes. A fault cancels its peer.
            await await Task.WhenAny(upload,download);
            await all;
        }
        finally
        {
            try{canceled.Cancel();}
            finally
            {
                // Observe both tasks before the caller disposes either endpoint.
                // Preserve the primary error rather than replacing it with the
                // companion pump's cancellation/close failure.
                try{await all;}catch{}
            }
        }
    }
}

// In-memory health freshness, never a report/file/launch credential. Only the
// owning Admission renews it after the existing runtime's full health checks.
internal sealed class SessionForwardingLease
{
    internal const int MaximumGapMs=2000;
    private readonly Func<long> clock;
    private long until=-1;
    private int revoked;
    internal SessionForwardingLease(Func<long> monotonicClock){clock=monotonicClock;}
    internal void Renew(long runtimeRemainingMs)
    {
        var now=clock();var previous=Interlocked.Read(ref until);
        if(Volatile.Read(ref revoked)!=0 || now<0 || runtimeRemainingMs<=0 || previous>=0 && now>=previous)
        {Revoke();throw new InvalidOperationException("SessionForwardingHealthExpiredOrRevoked");}
        Interlocked.Exchange(ref until,checked(now+Math.Min(MaximumGapMs,runtimeRemainingMs)));
        if(Volatile.Read(ref revoked)!=0)throw new InvalidOperationException("SessionForwardingHealthRevoked");
    }
    internal void AssertCurrent()
    {
        var now=clock();var expires=Interlocked.Read(ref until);
        if(Volatile.Read(ref revoked)!=0 || now<0 || expires<0 || now>=expires)
        {
            if(expires>=0 && now>=expires)Revoke();
            throw new InvalidOperationException("SessionForwardingHealthMissingExpiredOrRevoked");
        }
    }
    internal void Revoke()=>Interlocked.Exchange(ref revoked,1);
}
