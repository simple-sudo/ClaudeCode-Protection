using System.Text.Json;
using System.Threading.Channels;
using ClaudeCodeProtection.Security;

namespace ProtectionLifecycle;

// Fixed self-developed offline comparison. The ephemeral CA is never added to
// a store. Its SNI is a string in memory, with no DNS, socket or external peer.
internal sealed record OpenSslOfflineWitness(int SchemaVersion,string SessionId,int Pid,long StartedFileTime,long EndedFileTime,
    bool ExchangeVerified,int? WrongNameError,int? UnknownRootError,bool EofDenied,string? FailureStage,int? ErrorCode)
{
    private static readonly string[] Stages={"MODULES","FIXTURE","EXCHANGE","WRONG_NAME","UNKNOWN_ROOT","EARLY_EOF","MODULE_RELEASE"};
    internal bool Complete=>ExchangeVerified && WrongNameError==62 && UnknownRootError==20 && EofDenied &&
        FailureStage is null && ErrorCode is null;

    internal static OpenSslOfflineWitness Observe(string session,bool ordinaryFixture=false,string? release=null)
    {
        var start=DateTime.UtcNow.ToFileTimeUtc();var stage="MODULES";
        var exchanged=false;var eof=false;int? wrongName=null,wrongRoot=null;
        try
        {
            using var modules=ordinaryFixture?OpenSslModuleLease.OpenForOrdinaryFixture():OpenSslModuleLease.OpenForInstalledWorker(release??"");
            stage="FIXTURE";
            using var identity=new OpenSslOfflineIdentity(modules);
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(7));
            var wire=new Fixture(modules,identity);
            stage="EXCHANGE";wire.Exchange(SessionProxy.Target,identity.TrustedRoot,null,deadline.Token).GetAwaiter().GetResult();exchanged=true;
            stage="WRONG_NAME";wrongName=wire.Exchange("deliberate-mismatch.invalid",identity.TrustedRoot,62,deadline.Token).GetAwaiter().GetResult();
            stage="UNKNOWN_ROOT";wrongRoot=wire.Exchange(SessionProxy.Target,identity.UntrustedRoot,20,deadline.Token).GetAwaiter().GetResult();
            stage="EARLY_EOF";wire.CheckEarlyEof(identity.TrustedRoot,deadline.Token).GetAwaiter().GetResult();eof=true;
            stage="MODULE_RELEASE";
        }
        catch(OpenSslModuleException error)when(stage=="MODULES")
        {
            return Result(error.Stage,error.ErrorCode);
        }
        catch(OpenSslFixtureException error)when(stage=="FIXTURE")
        {
            return Result(error.Stage,error.ErrorCode);
        }
        catch(Exception error)
        {
            return Result(stage,error is System.ComponentModel.Win32Exception native?native.NativeErrorCode:error.HResult);
        }
        return Result(null,null);

        OpenSslOfflineWitness Result(string? failure,int? error)=>new(3,Identifiers.Hex32(session),Environment.ProcessId,start,
            DateTime.UtcNow.ToFileTimeUtc(),exchanged,wrongName,wrongRoot,eof,failure,error);
    }

    internal static OpenSslOfflineWitness Parse(string raw,string session,uint pid,long createdFileTime,uint exit)
    {
        if(raw.Length is <1 or >4096)throw new InvalidDataException("Offline TLS evidence bounds refused");
        using var json=JsonDocument.Parse(raw,new JsonDocumentOptions{MaxDepth=2});
        StrictJson.Fields(json.RootElement,"SchemaVersion","SessionId","Pid","StartedFileTime","EndedFileTime","ExchangeVerified",
            "WrongNameError","UnknownRootError","EofDenied","FailureStage","ErrorCode");
        var report=json.RootElement.Deserialize<OpenSslOfflineWitness>()??throw new InvalidDataException("Offline TLS report absent");
        if(report.SchemaVersion is not (1 or 2 or 3) || report.SessionId!=Identifiers.Hex32(session) || report.Pid<=0 || (uint)report.Pid!=pid ||
            createdFileTime<=0 || report.StartedFileTime<createdFileTime || report.EndedFileTime<report.StartedFileTime ||
            report.EndedFileTime-createdFileTime>TimeSpan.FromSeconds(30).Ticks)
            throw new InvalidDataException("Offline TLS report actor differs");
        if(report.Complete)
        {
            if(exit!=0)throw new InvalidDataException("Offline TLS completion exit differs");
            return report;
        }
        var stage=report.SchemaVersion>=2 && OpenSslModuleLease.IsReportedStage(report.FailureStage)?0:
            report.SchemaVersion==3 && OpenSslFixtureException.IsReportedStage(report.FailureStage)?1:Array.IndexOf(Stages,report.FailureStage);
        if(exit!=3 || stage<0 || report.ErrorCode is null || report.ExchangeVerified!=(stage>2) ||
            report.WrongNameError!=(stage>3?62:(int?)null) || report.UnknownRootError!=(stage>4?20:(int?)null) ||
            report.EofDenied!=(stage>5))
            throw new InvalidDataException("Offline TLS report progression differs");
        return report;
    }

    internal static async Task<int> VerifyRevocationOrdinary()
    {
        using var modules=OpenSslModuleLease.OpenForOrdinaryFixture();
        using var identity=new OpenSslOfflineIdentity(modules,revocationFixture:true);
        var lists=identity.RevocationFixture!.Value;
        byte[][] reviewed=[lists.Current,lists.RootCurrent];
        int cases=0;
        await Head(reviewed,"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"u8.ToArray(),204);
        await Head(reviewed,"HTTP/1.1 103 Early Hints\r\nLink: </ignored>\r\n\r\nHTTP/1.1 301 Moved\r\nContent-Length: 100\r\n\r\n"u8.ToArray(),301);
        await Head(reviewed,"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 403 Refusé\r\nX-Note: opaque é\r\n\r\n"u8.ToArray(),403,replyFragmentBytes:11);
        await Head([lists.Current],[],expectedVerifyError:3);
        await Head([lists.Expired,lists.RootCurrent],[],expectedVerifyError:12);
        await Head([lists.Revoked,lists.RootCurrent],[],expectedVerifyError:23);
        await Head([lists.WrongSigner,lists.RootCurrent],[],expectedVerifyError:8);
        await Head([lists.Current.Concat(new byte[]{0}).ToArray()],[],policyFailure:true);
        await Head([],[],policyFailure:true);
        await Head(reviewed,"HTTP/1.1 200 OK\r\n\r\nunexpected"u8.ToArray(),responseError:FixedHeadResponseError.BytesAfterFinalHeader,
            expectedTail:new(200,10,FixedHeadTailKind.Other));
        await Head(reviewed,"HTTP/1.1 301 Moved\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"u8.ToArray(),
            responseError:FixedHeadResponseError.BytesAfterFinalHeader,expectedTail:new(301,5,FixedHeadTailKind.EmptyChunk));
        await Head(reviewed,"HTTP/1.1 204 No Content\r\n\r\n\r\n"u8.ToArray(),
            responseError:FixedHeadResponseError.BytesAfterFinalHeader,expectedTail:new(204,2,FixedHeadTailKind.EmptyLine));
        await Head(reviewed,"HTTP/1.1 404 Missing\r\n\r\nHTTP/1.1 200 OK\r\n\r\n"u8.ToArray(),
            responseError:FixedHeadResponseError.BytesAfterFinalHeader,expectedTail:new(404,19,FixedHeadTailKind.HttpPrefix));
        await Head(reviewed,"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"u8.ToArray(),responseError:FixedHeadResponseError.ProtocolSwitch);
        await Head(reviewed,"HTTP/1.1 200 OK\r\n Folded: text\r\n\r\n"u8.ToArray(),responseError:FixedHeadResponseError.InvalidFieldName);
        await Head(reviewed,"HTTP/1.1 200 OK\r\nX: a\0b\r\n\r\n"u8.ToArray(),responseError:FixedHeadResponseError.MalformedOctet);
        await Head(reviewed,"HTTP/2 200 OK\r\n\r\n"u8.ToArray(),responseError:FixedHeadResponseError.InvalidStatusLine);
        await Head(reviewed,System.Text.Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("HTTP/1.1 103 Early Hints\r\n\r\n",5))),
            responseError:FixedHeadResponseError.InformationalCapacity);
        await Head(reviewed,System.Text.Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nX: "+new string('a',8192)+"\r\n\r\n"),
            responseError:FixedHeadResponseError.HeaderCapacity);
        return cases;

        async Task Head(byte[][] crls,byte[] reply,int? status=null,int? expectedVerifyError=null,
            bool policyFailure=false,FixedHeadResponseError? responseError=null,int replyFragmentBytes=4096,
            FixedHeadTrailingObservation? expectedTail=null)
        {
            var outgoing=Channel.CreateUnbounded<byte[]>();
            var incoming=Channel.CreateUnbounded<byte[]>();
            using var clientWire=new MemoryWire(incoming.Reader,outgoing.Writer);
            using var serverWire=new MemoryWire(outgoing.Reader,incoming.Writer);
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(4));
            var applicationRead=0;
            var server=Serve();
            try
            {
                try
                {
                    var observed=await FixedOpenSslHead.SendAsync(modules,clientWire,identity.TrustedRoot,crls,deadline.Token);
                    if(observed!=status)throw new InvalidOperationException("Unexpected fixed HEAD status");
                }
                catch(OpenSslFailure error)when(expectedVerifyError is not null && error.VerificationError==expectedVerifyError){}
                catch(OpenSslFailure error)when(policyFailure && error.NativeError is null && error.VerificationError is null){}
                catch(InvalidDataException)when(policyFailure){}
                catch(FixedHeadResponseException error)when(error.Reason==responseError && error.Trailing==expectedTail){}
                if(status is not null || responseError is not null)await server;
            }
            finally
            {
                deadline.Cancel();
                try{await server;}
                catch(OperationCanceledException)when(deadline.IsCancellationRequested){}
                catch(OpenSslFailure)when(status is null && responseError is null){}
            }
            if(applicationRead!=(status is not null || responseError is not null?1:0))
                throw new InvalidDataException("Fixed HEAD was released before certificate verification");
            cases++;

            async Task Serve()
            {
                using var peer=OpenSslMemoryConnection.CreateOfflineFixturePeer(modules.SslHandle,modules.CryptoHandle,serverWire,identity);
                await peer.AuthenticateAsync(deadline.Token);
                var request=new byte[1024];
                var count=await peer.ReadAsync(request,deadline.Token);
                applicationRead++;
                if(!request.AsSpan(0,count).SequenceEqual(
                    "HEAD /robots.txt HTTP/1.1\r\nHost: www.microsoft.com\r\nUser-Agent: ClaudeCode-Protection/1.0\r\nConnection: close\r\n\r\n"u8))
                    throw new InvalidDataException("Fixed HEAD request bytes differ");
                for(var offset=0;offset<reply.Length;offset+=replyFragmentBytes)
                    await peer.WriteAsync(reply.AsSpan(offset,Math.Min(replyFragmentBytes,reply.Length-offset)).ToArray(),deadline.Token);
            }
        }
    }

    private sealed class Fixture(OpenSslModuleLease modules,OpenSslOfflineIdentity identity)
    {
        private static readonly byte[] Request={19,43,71},Reply={89,53,11};
        private OpenSslMemoryConnection Client(Stream wire,string host,byte[] anchor)
            =>new(modules.SslHandle,modules.CryptoHandle,wire,host,anchor);

        internal async Task<int?> Exchange(string host,byte[] anchor,int? expectedError,CancellationToken cancel)
        {
            var outgoing=Channel.CreateUnbounded<byte[]>();var incoming=Channel.CreateUnbounded<byte[]>();
            using var clientWire=new MemoryWire(incoming.Reader,outgoing.Writer);
            using var serverWire=new MemoryWire(outgoing.Reader,incoming.Writer);
            using var exchange=CancellationTokenSource.CreateLinkedTokenSource(cancel);
            using var client=Client(clientWire,host,anchor);
            var server=Serve();
            try
            {
                await client.AuthenticateAsync(exchange.Token);
                if(expectedError is not null)throw new InvalidDataException("Bad TLS identity was accepted");
                await client.WriteAsync(Request,exchange.Token);
                var response=new byte[Reply.Length];
                if(await client.ReadAsync(response,exchange.Token)!=Reply.Length || !response.AsSpan().SequenceEqual(Reply))
                    throw new InvalidDataException("Encrypted application reply differs");
                await server;
                return null;
            }
            catch(OpenSslFailure error) when(expectedError is not null && error.NativeError==1 && error.VerificationError==expectedError)
            {
                return error.VerificationError;
            }
            finally
            {
                exchange.Cancel();
                try{await server;}
                catch(OperationCanceledException)when(exchange.IsCancellationRequested){}
            }
            async Task Serve()
            {
                try
                {
                    using var replay=expectedError is null?
                        await SessionTunnel.RequireTlsClientHelloAsync(serverWire,host,()=>exchange.Token.ThrowIfCancellationRequested(),exchange.Token):null;
                    using var peer=OpenSslMemoryConnection.CreateOfflineFixturePeer(modules.SslHandle,modules.CryptoHandle,
                        replay??serverWire,identity);
                    await peer.AuthenticateAsync(exchange.Token);
                    var request=new byte[Request.Length];
                    if(await peer.ReadAsync(request,exchange.Token)!=Request.Length || !request.AsSpan().SequenceEqual(Request))
                        throw new InvalidDataException("Encrypted application request differs");
                    await peer.WriteAsync(Reply,exchange.Token);
                }
                catch(Exception failure){incoming.Writer.TryComplete(failure);throw;}
            }
        }

        internal async Task CheckEarlyEof(byte[] anchor,CancellationToken cancel)
        {
            var outgoing=Channel.CreateUnbounded<byte[]>();var incoming=Channel.CreateUnbounded<byte[]>();
            incoming.Writer.Complete();
            using var wire=new MemoryWire(incoming.Reader,outgoing.Writer);
            using var client=Client(wire,SessionProxy.Target,anchor);
            try
            {
                await client.AuthenticateAsync(cancel);
                throw new InvalidDataException("Truncated TLS stream authenticated");
            }
            catch(EndOfStreamException){}
            try{await client.WriteAsync(Request,cancel);}
            catch(InvalidOperationException){return;}
            throw new InvalidDataException("Application data was accepted after failed authentication");
        }
    }

    private sealed class MemoryWire(ChannelReader<byte[]> reader,ChannelWriter<byte[]> writer) : Stream
    {
        private ReadOnlyMemory<byte> pending;
        public override bool CanRead=>true;
        public override bool CanSeek=>false;
        public override bool CanWrite=>true;
        public override long Length=>throw new NotSupportedException();
        public override long Position {get=>throw new NotSupportedException();set=>throw new NotSupportedException();}
        public override void Flush(){}
        public override long Seek(long offset,SeekOrigin origin)=>throw new NotSupportedException();
        public override void SetLength(long value)=>throw new NotSupportedException();
        public override int Read(byte[] b,int o,int n)=>throw new NotSupportedException();
        public override void Write(byte[] b,int o,int n)=>throw new NotSupportedException();
        public override async ValueTask<int> ReadAsync(Memory<byte> data,CancellationToken cancel=default)
        {
            if(pending.IsEmpty)
            {
                if(!await reader.WaitToReadAsync(cancel))return 0;
                pending=await reader.ReadAsync(cancel);
            }
            var count=Math.Min(data.Length,pending.Length);
            pending[..count].CopyTo(data);pending=pending[count..];
            return count;
        }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> data,CancellationToken cancel=default)
            =>writer.WriteAsync(data.ToArray(),cancel);
    }
}
