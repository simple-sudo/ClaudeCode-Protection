using System.Text;
using ClaudeCodeProtection.Security;

internal static class SessionTunnelCases
{
    internal static async Task RunAsync()
    {
        var request=Encoding.ASCII.GetBytes("owned request");
        var response=Enumerable.Range(0,32769).Select(i=>(byte)(i%251)).ToArray();
        // The peer withholds its entire response until the request direction
        // is half-closed. Both orientations must preserve the delayed tail.
        foreach(var reverse in new[]{false,true})
        {
            using var first=new Endpoint(reverse?response:request,!reverse);
            using var second=new Endpoint(reverse?request:response,reverse);
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(2));long accounted=0;
            await SessionTunnel.CopyAsync(first,second,
                ()=>{first.FinishSending();if(reverse)first.OpenRead();},
                ()=>{second.FinishSending();if(!reverse)second.OpenRead();},
                count=>Interlocked.Add(ref accounted,count),65536,()=>{},deadline.Token);
            Check(first.Written.SequenceEqual(reverse?request:response) && second.Written.SequenceEqual(reverse?response:request),
                "normal EOF must drain the delayed opposite direction completely");
            Check(first.Finishes==1 && second.Finishes==1 && accounted==request.Length+response.Length,"half-close and byte accounting");
            Check(first.ActiveReads==0 && second.ActiveReads==0,"normal completion drains both readers");
        }
        // A fault AFTER the first normal EOF must not be swallowed as cleanup.
        using(var first=new Endpoint(request,true))
        using(var second=new Endpoint(response,false){ReadFailure=new IOException("owned late failure")})
        using(var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(2)))
        {
            await Reject<IOException>(()=>SessionTunnel.CopyAsync(first,second,first.FinishSending,
                ()=>{second.FinishSending();second.OpenRead();},_=>{},65536,()=>{},deadline.Token));
            Check(second.ActiveReads==0,"late failing reader drained");
        }
        // The other reader remains blocked: errors must cancel and observe it.
        foreach(var quota in new[]{false,true})
        {
            using var first=new Endpoint(request,true);
            using var second=new Endpoint(Array.Empty<byte>(),false){FailWrites=!quota};
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(2));
            if(quota)
                await Reject<InvalidDataException>(()=>SessionTunnel.CopyAsync(first,second,first.FinishSending,second.FinishSending,_=>{},1,()=>{},deadline.Token));
            else
                await Reject<IOException>(()=>SessionTunnel.CopyAsync(first,second,first.FinishSending,second.FinishSending,_=>{},65536,()=>{},deadline.Token));
            Check(second.Canceled && first.ActiveReads==0 && second.ActiveReads==0,"failure cancels and drains companion reader");
            Check(second.Written.Length==0,"rejected bytes never forwarded");
        }
        using(var first=new Endpoint(request,true))
        using(var second=new Endpoint(Array.Empty<byte>(),false))
        using(var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(2)))
        {
            await Reject<InvalidDataException>(()=>SessionTunnel.CopyAsync(first,second,first.FinishSending,second.FinishSending,
                _=>throw new InvalidDataException("owned session budget exhausted"),65536,()=>{},deadline.Token));
            Check(second.Written.Length==0 && second.Canceled,"session byte reservation fails before write and drains peer");
        }
        using(var first=new Endpoint(Array.Empty<byte>(),false))
        using(var second=new Endpoint(Array.Empty<byte>(),false))
        using(var deadline=new CancellationTokenSource(TimeSpan.FromMilliseconds(100)))
        {
            await Reject<OperationCanceledException>(()=>SessionTunnel.CopyAsync(first,second,first.FinishSending,second.FinishSending,_=>{},65536,()=>{},deadline.Token));
            Check(first.Canceled && second.Canceled && first.ActiveReads==0 && second.ActiveReads==0,"deadline cancels and drains both directions");
            Check(first.Finishes==0 && second.Finishes==0,"cancellation is not clean EOF");
        }
        foreach(var expire in new[]{false,true})
        {
            long clock=0;var permission=new SessionForwardingLease(()=>Interlocked.Read(ref clock));permission.Renew(10000);
            using var first=new Endpoint(request,false);using var second=new Endpoint(Array.Empty<byte>(),false);
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(2));
            var copy=SessionTunnel.CopyAsync(first,second,first.FinishSending,second.FinishSending,_=>{},65536,permission.AssertCurrent,deadline.Token);
            Check(first.ActiveReads==1 && second.ActiveReads==1,"both directions wait under current permission");
            if(expire)Interlocked.Exchange(ref clock,SessionForwardingLease.MaximumGapMs);else permission.Revoke();
            first.OpenRead();
            await Reject<InvalidOperationException>(()=>copy);
            Check(second.Written.Length==0 && second.Canceled && first.ActiveReads==0 && second.ActiveReads==0,
                "revocation/expiry during a blocked read prevents forwarding and drains both readers");
            Refuse(()=>permission.Renew(10000)); // No resurrection by a late heartbeat.
        }
        long now=0;var health=new SessionForwardingLease(()=>now);
        Refuse(health.AssertCurrent);health.Renew(10000);
        now=1000;health.Renew(9000);now=2999;health.AssertCurrent();now=3000;Refuse(health.AssertCurrent);Refuse(()=>health.Renew(7000));
        now=0;var remaining=new SessionForwardingLease(()=>now);remaining.Renew(50);now=49;remaining.AssertCurrent();now=50;Refuse(remaining.AssertCurrent);
        now=0;var revoked=new SessionForwardingLease(()=>now);revoked.Revoke();Refuse(()=>revoked.Renew(10000));
        var zero=new SessionForwardingLease(()=>0);Refuse(()=>zero.Renew(0));Refuse(zero.AssertCurrent);
    }
    private static void Check(bool value,string message)
    {if(!value)throw new InvalidOperationException("SessionTunnel: "+message);}
    private static void Refuse(Action action)
    {
        try{action();}catch(InvalidOperationException){return;}
        throw new InvalidOperationException("SessionTunnel: expected forwarding permission refusal");
    }
    private static async Task Reject<T>(Func<Task> action) where T:Exception
    {
        try{await action().WaitAsync(TimeSpan.FromSeconds(3));}
        catch(T){return;}
        throw new InvalidOperationException("SessionTunnel: expected "+typeof(T).Name);
    }
    // Entirely memory-backed duplex endpoint; it cannot open a socket, file,
    // native API, product entry point or another process.
    internal sealed class Endpoint:Stream
    {
        private readonly byte[] input;
        private readonly TaskCompletionSource ready=new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly MemoryStream written=new();
        private int position,active;
        internal bool FailWrites {get;init;}
        internal int MaximumRead {get;init;}=int.MaxValue;
        internal Exception? ReadFailure {get;init;}
        internal bool Canceled {get;private set;}
        internal int ActiveReads=>Volatile.Read(ref active);
        internal int Finishes {get;private set;}
        internal byte[] Written=>written.ToArray();
        internal Endpoint(byte[] input,bool open){this.input=input;if(open)OpenRead();}
        internal void OpenRead()=>ready.TrySetResult();
        internal void FinishSending()=>Finishes++;
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken token=default)
        {
            Interlocked.Increment(ref active);
            try
            {
                await ready.Task.WaitAsync(token);token.ThrowIfCancellationRequested();
                if(ReadFailure is not null)throw ReadFailure;
                var count=Math.Min(MaximumRead,Math.Min(buffer.Length,input.Length-position));input.AsMemory(position,count).CopyTo(buffer);position+=count;return count;
            }
            catch(OperationCanceledException){Canceled=true;throw;}
            finally{Interlocked.Decrement(ref active);}
        }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer,CancellationToken token=default)
        {token.ThrowIfCancellationRequested();if(FailWrites)throw new IOException("owned write failure");written.Write(buffer.Span);return ValueTask.CompletedTask;}
        public override bool CanRead=>true;
        public override bool CanWrite=>true;
        public override bool CanSeek=>false;
        public override long Length=>throw new NotSupportedException();
        public override long Position {get=>position;set=>throw new NotSupportedException();}
        public override void Flush(){}
        public override int Read(byte[] buffer,int offset,int count)=>throw new NotSupportedException();
        public override void Write(byte[] buffer,int offset,int count)=>throw new NotSupportedException();
        public override long Seek(long offset,SeekOrigin origin)=>throw new NotSupportedException();
        public override void SetLength(long value)=>throw new NotSupportedException();
        protected override void Dispose(bool disposing){if(disposing)written.Dispose();base.Dispose(disposing);}
    }
}
