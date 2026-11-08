using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ProtectionLifecycle;

// Caller holds the exact native modules for this entire lease. The client
// consumes only a supplied byte stream and an explicit offline trust anchor.
// The local comparison peer takes an ephemeral fixture key. Neither role
// opens sockets, loads trust paths or owns forwarding authority.
internal sealed class OpenSslMemoryConnection : IDisposable
{
    private const int MaxWireBytes=128*1024, BufferBytes=4096, WantRead=2;
    internal const ulong NoLoadConfig=0x80;
    private readonly Native api;
    private readonly Stream wire;
    private readonly byte[] buffer=new byte[BufferBytes];
    private IntPtr context,ssl,input,output;
    private int readBytes,writtenBytes;
    private int useState; // 0 idle, 1 operation in progress, 2 disposed.
    private readonly bool client;
    private bool authenticated,faulted;

    internal OpenSslMemoryConnection(IntPtr sslModule,IntPtr cryptoModule,Stream wire,string host,byte[] trustAnchor)
        :this(sslModule,cryptoModule,wire,host,trustAnchor,null,null){}

    internal static OpenSslMemoryConnection CreateRevocationCheckedClient(IntPtr sslModule,IntPtr cryptoModule,Stream wire,
        string host,byte[] trustAnchor,IReadOnlyList<byte[]> certificateRevocationLists)
    {
        ArgumentNullException.ThrowIfNull(certificateRevocationLists);
        return new(sslModule,cryptoModule,wire,host,trustAnchor,null,certificateRevocationLists);
    }

    internal static OpenSslMemoryConnection CreateOfflineFixturePeer(IntPtr sslModule,IntPtr cryptoModule,Stream wire,
        OpenSslOfflineIdentity identity)
        =>new(sslModule,cryptoModule,wire,null,null,identity,null);

    private OpenSslMemoryConnection(IntPtr sslModule,IntPtr cryptoModule,Stream wire,string? host,byte[]? anchor,
        OpenSslOfflineIdentity? identity,IReadOnlyList<byte[]>? certificateRevocationLists)
    {
        if(!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture!=Architecture.X64)
            throw new PlatformNotSupportedException("Fixed OpenSSL Windows x64 ABI required");
        if(host is null?identity is null:
            anchor is not {Length:>=1 and <=16384} || host.Length is <1 or >253 || Uri.CheckHostName(host)!=UriHostNameType.Dns ||
            !host.All(c=>char.IsAsciiLetterOrDigit(c) || c is '-' or '.'))
            throw new InvalidDataException("Fixed TLS name or trust anchor refused");
        api=new(sslModule,cryptoModule);
        this.wire=wire;
        client=host is not null;
        try
        {
            // OPENSSL_INIT_NO_LOAD_CONFIG. No default trust file, CA path,
            // provider search override or verification callback is installed.
            Check(api.Init(NoLoadConfig,IntPtr.Zero)==1,"INIT");
            context=api.ContextNew(client?api.ClientMethod():api.ServerMethod());
            Check(context!=IntPtr.Zero,"CONTEXT");
            Check(api.ContextControl(context,123,0x0303,IntPtr.Zero)==1 &&
                api.ContextControl(context,124,0x0304,IntPtr.Zero)==1,"VERSION");
            const ulong noRenegotiation=1UL<<30;
            Check((api.SetContextOptions(context,noRenegotiation)&noRenegotiation)!=0,"NO_RENEGOTIATION");
            if(client)
            {
                api.ContextVerify(context,1,IntPtr.Zero); // SSL_VERIFY_PEER
                var store=api.CertStore(context);
                Check(store!=IntPtr.Zero,"TRUST_STORE");
                AddTrustObject(store,anchor!,api.DecodeCertificate,api.AddCertificate,api.FreeCertificate,"TRUST_ANCHOR");
                if(certificateRevocationLists is not null)InstallRevocationPolicy(store,certificateRevocationLists);
            }
            else
            {
                Check(api.UseCertificate(context,identity!.Certificate)==1,"FIXTURE_CERTIFICATE");
                Check(api.UsePrivateKey(context,identity.Key)==1 && api.CheckPrivateKey(context)==1,"FIXTURE_KEY_BINDING");
                if(identity.IntermediateCertificate!=IntPtr.Zero)
                    Check(api.ContextControl(context,89,1,identity.IntermediateCertificate)==1,"FIXTURE_INTERMEDIATE");
            }
            ssl=api.SslNew(context);
            Check(ssl!=IntPtr.Zero,"SESSION");
            if(host is not null)ConfigureClient(host);
            else api.AcceptState(ssl);
            using var read=new PendingBio(api);
            using var write=new PendingBio(api);
            input=read.Handle;output=write.Handle;
            api.SetBio(ssl,input,output);
            read.Transfer();write.Transfer();
        }
        catch{Dispose();throw;}
    }

    private void ConfigureClient(string host)
    {
        var name=Marshal.StringToCoTaskMemUTF8(host);
        try
        {
            var parameters=api.VerifyParameters(ssl);
            Check(parameters!=IntPtr.Zero,"VERIFY_PARAMETERS");
            api.SetHostFlags(parameters,OpenSslDer.ExactDnsName);
            Check(api.SetHost(ssl,name)==1 && api.SslControl(ssl,55,0,name)==1,"SERVER_NAME");
        }
        finally{Marshal.FreeCoTaskMem(name);}
        api.ConnectState(ssl);
    }

    internal Task AuthenticateAsync(CancellationToken cancel)
        =>OperateAsync(()=>api.Handshake(ssl),"HANDSHAKE",cancel,authenticate:true);

    internal async Task WriteAsync(byte[] bytes,CancellationToken cancel)
    {
        if(bytes.Length is <1 or >BufferBytes)throw new InvalidDataException("TLS write bound refused");
        await OperateAsync(()=>api.Write(ssl,bytes,bytes.Length),"WRITE",cancel,requiredLength:bytes.Length).ConfigureAwait(false);
    }

    internal async Task<int> ReadAsync(byte[] bytes,CancellationToken cancel)
    {
        if(bytes.Length is <1 or >BufferBytes)throw new InvalidDataException("TLS read bound refused");
        return await OperateAsync(()=>api.Read(ssl,bytes,bytes.Length),"READ",cancel).ConfigureAwait(false);
    }

    private void InstallRevocationPolicy(IntPtr store,IReadOnlyList<byte[]> lists)
    {
        const int maxLists=4,maxCrlBytes=1024*1024;
        if(lists.Count is <1 or >maxLists)throw new InvalidDataException("Fixed offline CRL count refused");
        foreach(var der in lists)
        {
            if(der is not {Length:>=1 and <=maxCrlBytes})throw new InvalidDataException("Fixed offline CRL size refused");
            AddTrustObject(store,der,api.DecodeCrl,api.AddCrl,api.FreeCrl,"TRUST_CRL");
        }
        // CRL_CHECK | CRL_CHECK_ALL. A missing or expired CRL fails
        // validation. No lookup methods, network retrieval, or callback.
        Check(api.SetStoreFlags(store,OpenSslDer.CheckWholeChainRevocation)==1,"TRUST_REVOCATION");
    }

    private static void AddTrustObject(IntPtr store,byte[] der,OpenSslDer.Decode decode,Native.Pair add,OpenSslDer.Free free,string stage)
    {
        var item=OpenSslDer.Read(der,decode,free);
        try{Check(item!=IntPtr.Zero && add(store,item)==1,stage);}
        finally{if(item!=IntPtr.Zero)free(item);}
    }

    private async Task<int> OperateAsync(Func<int> step,string stage,CancellationToken cancel,bool authenticate=false,int? requiredLength=null)
    {
        var previous=Interlocked.CompareExchange(ref useState,1,0);
        ObjectDisposedException.ThrowIf(previous==2,this);
        if(previous!=0)throw new InvalidOperationException("Concurrent TLS operation refused");
        try
        {
            if(faulted || (authenticate?authenticated:!authenticated))
                throw new InvalidOperationException("TLS operation unavailable in the current state");
            var result=await AdvanceAsync(step,stage,cancel).ConfigureAwait(false);
            if(authenticate)
            {
                if(client)Check(api.VerifyResult(ssl)==0,"VERIFY");
                authenticated=true;
            }
            if(requiredLength is int exact)Check(result==exact,"PARTIAL_WRITE");
            return result;
        }
        catch{faulted=true;throw;}
        finally{Volatile.Write(ref useState,0);}
    }

    private async Task<int> AdvanceAsync(Func<int> step,string stage,CancellationToken cancel)
    {
        // Bounded retries plus a whole-connection wire budget. Keep SSL_get_error
        // adjacent to the native operation on the same OS thread.
        for(int attempt=0;attempt<96;attempt++)
        {
            cancel.ThrowIfCancellationRequested();
            api.ClearErrors();
            var result=step();
            var error=result>0?0:api.GetError(ssl,result);
            if(result<=0 && error!=WantRead)
                throw new OpenSslFailure(stage,error,client && !authenticated?api.VerifyResult(ssl):null);
            await FlushAsync(cancel).ConfigureAwait(false);
            if(result>0)return result;
            var count=await wire.ReadAsync(buffer,cancel).ConfigureAwait(false);
            if(count==0)throw new EndOfStreamException("TLS peer closed before the fixed exchange");
            readBytes+=count;
            Check(readBytes<=MaxWireBytes && api.BioWrite(input,buffer,count)==count,"INPUT_BOUND");
        }
        throw new InvalidDataException("TLS progress bound exceeded");
    }

    private async Task FlushAsync(CancellationToken cancel)
    {
        while(api.BioPending(output) is >0)
        {
            var count=api.BioRead(output,buffer,buffer.Length);
            Check(count>0 && count<=buffer.Length,"OUTPUT_READ");
            writtenBytes+=count;
            Check(writtenBytes<=MaxWireBytes,"OUTPUT_BOUND");
            await wire.WriteAsync(buffer.AsMemory(0,count),cancel).ConfigureAwait(false);
        }
    }

    private static void Check(bool ok,string stage){if(!ok)throw new OpenSslFailure(stage,null);}

    public void Dispose()
    {
        var previous=Interlocked.CompareExchange(ref useState,2,0);
        if(previous==2)return;
        if(previous!=0)throw new InvalidOperationException("Wait for the original TLS operation before disposal");
        if(ssl!=IntPtr.Zero)api.SslFree(ssl); // releases the two owned BIOs
        if(context!=IntPtr.Zero)api.ContextFree(context);
        CryptographicOperations.ZeroMemory(buffer);
    }

    private sealed class PendingBio : IDisposable
    {
        private readonly Native api;
        private bool transferred;
        internal IntPtr Handle {get;}
        internal PendingBio(Native api)
        {
            this.api=api;
            Handle=api.BioNew(api.BioMemory());
            Check(Handle!=IntPtr.Zero,"BIO");
        }
        internal void Transfer()=>transferred=true;
        public void Dispose(){if(!transferred)_=api.BioFree(Handle);}
    }

    private sealed class Native
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int InitCall(ulong options,IntPtr settings);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate IntPtr PointerCall();
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate IntPtr PointerOn(IntPtr value);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int IntOn(IntPtr value);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate void VoidOn(IntPtr value);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate void VoidCall();
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int Control(IntPtr value,int command,int argument,IntPtr pointer);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate void Verify(IntPtr context,int mode,IntPtr callback);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate ulong Options(IntPtr ssl,ulong options);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int Pair(IntPtr first,IntPtr second);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate void SetFlags(IntPtr parameters,uint flags);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int StoreFlags(IntPtr store,uint flags);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate void Triple(IntPtr first,IntPtr second,IntPtr third);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int Error(IntPtr ssl,int result);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int Io(IntPtr owner,[In,Out] byte[] bytes,int count);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate nuint SizeOn(IntPtr owner);

        internal readonly InitCall Init;
        internal readonly PointerCall ClientMethod,ServerMethod,BioMemory;
        internal readonly PointerOn ContextNew,SslNew,CertStore,VerifyParameters,BioNew;
        internal readonly VoidOn ContextFree,SslFree,ConnectState,AcceptState;
        internal readonly OpenSslDer.Free FreeCertificate,FreeCrl;
        internal readonly Control ContextControl,SslControl;
        internal readonly Verify ContextVerify;
        internal readonly Options SetContextOptions;
        internal readonly Pair SetHost,AddCertificate,AddCrl,UseCertificate,UsePrivateKey;
        internal readonly SetFlags SetHostFlags;
        internal readonly StoreFlags SetStoreFlags;
        internal readonly Triple SetBio;
        internal readonly IntOn Handshake,VerifyResult,BioFree,CheckPrivateKey;
        internal readonly Error GetError;
        internal readonly OpenSslDer.Decode DecodeCertificate,DecodeCrl;
        internal readonly Io BioRead,BioWrite,Read,Write;
        internal readonly SizeOn BioPending;
        internal readonly VoidCall ClearErrors;

        internal Native(IntPtr ssl,IntPtr crypto)
        {
            Init=Bind<InitCall>(ssl,"OPENSSL_init_ssl");
            ClientMethod=Bind<PointerCall>(ssl,"TLS_client_method");
            ServerMethod=Bind<PointerCall>(ssl,"TLS_server_method");
            ContextNew=Bind<PointerOn>(ssl,"SSL_CTX_new");
            ContextFree=Bind<VoidOn>(ssl,"SSL_CTX_free");
            ContextControl=Bind<Control>(ssl,"SSL_CTX_ctrl");
            ContextVerify=Bind<Verify>(ssl,"SSL_CTX_set_verify");
            SetContextOptions=Bind<Options>(ssl,"SSL_CTX_set_options");
            CertStore=Bind<PointerOn>(ssl,"SSL_CTX_get_cert_store");
            SslNew=Bind<PointerOn>(ssl,"SSL_new");
            SslFree=Bind<VoidOn>(ssl,"SSL_free");
            SetHost=Bind<Pair>(ssl,"SSL_set1_host");
            VerifyParameters=Bind<PointerOn>(ssl,"SSL_get0_param");
            SslControl=Bind<Control>(ssl,"SSL_ctrl");
            ConnectState=Bind<VoidOn>(ssl,"SSL_set_connect_state");
            AcceptState=Bind<VoidOn>(ssl,"SSL_set_accept_state");
            UseCertificate=Bind<Pair>(ssl,"SSL_CTX_use_certificate");
            UsePrivateKey=Bind<Pair>(ssl,"SSL_CTX_use_PrivateKey");
            CheckPrivateKey=Bind<IntOn>(ssl,"SSL_CTX_check_private_key");
            SetBio=Bind<Triple>(ssl,"SSL_set_bio");
            Handshake=Bind<IntOn>(ssl,"SSL_do_handshake");
            GetError=Bind<Error>(ssl,"SSL_get_error");
            VerifyResult=Bind<IntOn>(ssl,"SSL_get_verify_result");
            Read=Bind<Io>(ssl,"SSL_read");
            Write=Bind<Io>(ssl,"SSL_write");
            SetHostFlags=Bind<SetFlags>(crypto,"X509_VERIFY_PARAM_set_hostflags");
            DecodeCertificate=Bind<OpenSslDer.Decode>(crypto,"d2i_X509");
            AddCertificate=Bind<Pair>(crypto,"X509_STORE_add_cert");
            FreeCertificate=Bind<OpenSslDer.Free>(crypto,"X509_free");
            DecodeCrl=Bind<OpenSslDer.Decode>(crypto,"d2i_X509_CRL");
            AddCrl=Bind<Pair>(crypto,"X509_STORE_add_crl");
            FreeCrl=Bind<OpenSslDer.Free>(crypto,"X509_CRL_free");
            SetStoreFlags=Bind<StoreFlags>(crypto,"X509_STORE_set_flags");
            BioMemory=Bind<PointerCall>(crypto,"BIO_s_mem");
            BioNew=Bind<PointerOn>(crypto,"BIO_new");
            BioFree=Bind<IntOn>(crypto,"BIO_free");
            BioPending=Bind<SizeOn>(crypto,"BIO_ctrl_pending");
            BioRead=Bind<Io>(crypto,"BIO_read");
            BioWrite=Bind<Io>(crypto,"BIO_write");
            ClearErrors=Bind<VoidCall>(crypto,"ERR_clear_error");
        }
        private static T Bind<T>(IntPtr module,string name) where T:Delegate
            =>Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(module,name));
    }
}

internal sealed class OpenSslFailure : IOException
{
    internal int? NativeError {get;}
    internal int? VerificationError {get;}
    internal OpenSslFailure(string stage,int? nativeError,int? verificationError=null):base("Fixed OpenSSL TLS: "+stage)
    {NativeError=nativeError;VerificationError=verificationError;}
}
