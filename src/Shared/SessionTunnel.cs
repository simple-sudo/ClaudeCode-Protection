namespace ClaudeCodeProtection.Security;

// The session gateway's actual duplex copier. It owns neither streams nor
// sockets; its caller retains the deadline, revocation and endpoint lifetime.
internal static class SessionTunnel
{
    // Read only the bounded initial ClientHello. Return a duplex replay view
    // so the existing copier accounts/forwards every validated byte exactly once.
    // No upstream socket is created by this method.
    internal static async Task<Stream> RequireTlsClientHelloAsync(Stream client,string host,Action assertAuthorized,CancellationToken token)
    {
        using var wire=new MemoryStream();using var handshake=new MemoryStream();var expected=-1;
        for(var record=0;record<8;record++)
        {
            assertAuthorized();var header=new byte[5];await client.ReadExactlyAsync(header,token);
            assertAuthorized();var size=(header[3]<<8)|header[4];
            if(header[0]!=22 || header[1]!=3 || header[2] is <1 or >3 || size is <1 or >16384 || wire.Length+5+size>32768)
                throw new InvalidDataException("InitialTlsRecordRefused");
            var payload=new byte[size];await client.ReadExactlyAsync(payload,token);assertAuthorized();
            wire.Write(header);wire.Write(payload);handshake.Write(payload);
            var bytes=handshake.GetBuffer();
            if(handshake.Length>=4 && expected<0)
            {
                expected=4+((bytes[1]<<16)|(bytes[2]<<8)|bytes[3]);
                if(bytes[0]!=1 || expected is <4 or >32768)throw new InvalidDataException("InitialTlsHandshakeRefused");
            }
            if(expected>=0 && handshake.Length>=expected)
            {
                if(handshake.Length!=expected)throw new InvalidDataException("ExtraInitialTlsHandshakeBytes");
                ProxyDestinationPolicy.ValidateTlsClientHello(host,bytes.AsSpan(0,expected));assertAuthorized();
                return new PrefixDuplexStream(client,wire.ToArray());
            }
        }
        throw new InvalidDataException("TlsInitialRecordCapacity");
    }
    private sealed class PrefixDuplexStream(Stream inner,byte[] prefix):Stream
    {
        private int position;
        public override bool CanRead=>inner.CanRead;
        public override bool CanWrite=>inner.CanWrite;
        public override bool CanSeek=>false;
        public override long Length=>throw new NotSupportedException();
        public override long Position{get=>throw new NotSupportedException();set=>throw new NotSupportedException();}
        public override ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken token=default)
        {
            token.ThrowIfCancellationRequested();
            if(position==prefix.Length)return inner.ReadAsync(buffer,token);
            var count=Math.Min(buffer.Length,prefix.Length-position);prefix.AsMemory(position,count).CopyTo(buffer);position+=count;return ValueTask.FromResult(count);
        }
        public override int Read(byte[] buffer,int offset,int count)
        {
            if(position==prefix.Length)return inner.Read(buffer,offset,count);
            var size=Math.Min(count,prefix.Length-position);prefix.AsSpan(position,size).CopyTo(buffer.AsSpan(offset,size));position+=size;return size;
        }
        public override void Flush()=>inner.Flush();
        public override void Write(byte[] buffer,int offset,int count)=>inner.Write(buffer,offset,count);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer,CancellationToken token=default)=>inner.WriteAsync(buffer,token);
        public override long Seek(long offset,SeekOrigin origin)=>throw new NotSupportedException();
        public override void SetLength(long value)=>throw new NotSupportedException();
        // The caller owns the endpoint; this view cannot close it prematurely.
    }
    internal static async Task CopyAsync(Stream client,Stream upstream,Action clientFinishSending,Action upstreamFinishSending,
        Action<int> accountBytes,long directionLimit,Action assertAuthorized,CancellationToken token,
        Action<bool>? observeCompletedWrite=null)
    {
        if(directionLimit is <1 or >8*1024*1024)throw new ArgumentOutOfRangeException(nameof(directionLimit));
        using var canceled=CancellationTokenSource.CreateLinkedTokenSource(token);
        async Task Pump(Stream input,Stream output,Action finishSending,bool towardUpstream)
        {
            var buffer=new byte[16384];long total=0;
            while(true)
            {
                canceled.Token.ThrowIfCancellationRequested();
                assertAuthorized();
                var count=await input.ReadAsync(buffer,canceled.Token);
                // A read can complete concurrently with cancellation.
                canceled.Token.ThrowIfCancellationRequested();
                if(count==0)
                {
                    assertAuthorized();
                    finishSending();return;
                }
                total+=count;
                if(total>directionLimit)throw new InvalidDataException("SessionTunnelByteBudgetExceeded");
                accountBytes(count); // Reserve the session budget BEFORE forwarding.
                assertAuthorized(); // A blocked read must not outlive permission.
                await output.WriteAsync(buffer.AsMemory(0,count),canceled.Token);
                if(observeCompletedWrite is not null)
                {
                    // An in-flight write may finish after cancellation or loss
                    // of permission. It cannot qualify the fixed exchange.
                    canceled.Token.ThrowIfCancellationRequested();
                    assertAuthorized();
                    observeCompletedWrite(towardUpstream);
                }
            }
        }
        var upload=Pump(client,upstream,upstreamFinishSending,true);
        var download=Pump(upstream,client,clientFinishSending,false);
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
