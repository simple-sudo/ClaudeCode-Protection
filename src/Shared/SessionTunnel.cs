namespace ClaudeCodeProtection.Security;

// The session gateway's actual duplex copier. It owns neither streams nor
// sockets; its caller retains the deadline, revocation and endpoint lifetime.
internal static class SessionTunnel
{
    internal static async Task CopyAsync(Stream client,Stream upstream,Action clientFinishSending,Action upstreamFinishSending,
        Action<int> accountBytes,long directionLimit,CancellationToken token)
    {
        if(directionLimit is <1 or >8*1024*1024)throw new ArgumentOutOfRangeException(nameof(directionLimit));
        using var canceled=CancellationTokenSource.CreateLinkedTokenSource(token);
        async Task Pump(Stream input,Stream output,Action finishSending)
        {
            var buffer=new byte[16384];long total=0;
            while(true)
            {
                canceled.Token.ThrowIfCancellationRequested();
                var count=await input.ReadAsync(buffer,canceled.Token);
                if(count==0)
                {
                    canceled.Token.ThrowIfCancellationRequested();
                    finishSending();return;
                }
                total+=count;
                if(total>directionLimit)throw new InvalidDataException("SessionTunnelByteBudgetExceeded");
                accountBytes(count); // Reserve the session budget BEFORE forwarding.
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
