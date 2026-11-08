using System.Runtime.InteropServices;

namespace ProtectionLifecycle;

// Uses a fresh in-memory store. No system trust, fetch callbacks, verification
// overrides or OpenSSL configuration files participate.
internal static class OpenSslOfflineChain
{
    internal static bool Verify(OpenSslModuleLease modules,string host,byte[] root,byte[] leaf,
        byte[] issuer,IReadOnlyList<byte[]> crls)
    {
        var api=new Native(modules.CryptoHandle);
        if(api.Initialize(OpenSslMemoryConnection.NoLoadConfig,IntPtr.Zero)!=1)return false;
        api.ClearErrors();
        var store=IntPtr.Zero;
        var context=IntPtr.Zero;
        var intermediate=IntPtr.Zero;
        var peer=IntPtr.Zero;
        var untrusted=IntPtr.Zero;
        try
        {
            store=api.NewStore();
            context=api.NewContext();
            intermediate=OpenSslDer.Read(issuer,api.DecodeCertificate,api.FreeCertificate);
            peer=OpenSslDer.Read(leaf,api.DecodeCertificate,api.FreeCertificate);
            untrusted=api.NewStack();
            if(store==IntPtr.Zero || context==IntPtr.Zero || untrusted==IntPtr.Zero ||
                intermediate==IntPtr.Zero || peer==IntPtr.Zero || api.Push(untrusted,intermediate)!=1 ||
                !Add(root,api.DecodeCertificate,api.AddCertificate,api.FreeCertificate))
                return false;
            foreach(var list in crls)
                if(!Add(list,api.DecodeCrl,api.AddCrl,api.FreeCrl))return false;
            if(api.SetFlags(store,OpenSslDer.CheckWholeChainRevocation)!=1 ||
                api.InitializeContext(context,store,peer,untrusted)!=1 ||
                api.SetPurpose(context,2)!=1) // X509_PURPOSE_SSL_SERVER
                return false;
            var parameters=api.Parameters(context);
            if(parameters==IntPtr.Zero)return false;
            api.SetHostFlags(parameters,OpenSslDer.ExactDnsName);
            return api.SetHost(parameters,host,0)==1 && api.Verify(context)==1;
        }
        finally
        {
            if(context!=IntPtr.Zero)api.FreeContext(context);
            if(untrusted!=IntPtr.Zero)api.FreeStack(untrusted);
            if(peer!=IntPtr.Zero)api.FreeCertificate(peer);
            if(intermediate!=IntPtr.Zero)api.FreeCertificate(intermediate);
            if(store!=IntPtr.Zero)api.FreeStore(store);
            api.ClearErrors();
        }

        bool Add(byte[] bytes,OpenSslDer.Decode decoder,Native.Pair add,OpenSslDer.Free free)
        {
            var item=OpenSslDer.Read(bytes,decoder,free);
            if(item==IntPtr.Zero)return false;
            try{return add(store,item)==1;}
            finally{free(item);}
        }
    }

    private sealed class Native(IntPtr crypto)
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate IntPtr New();
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate IntPtr PointerOn(IntPtr owner);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate void Free(IntPtr owner);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate void Clear();
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int Pair(IntPtr owner,IntPtr value);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int Init(ulong options,IntPtr settings);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int InitContext(IntPtr context,IntPtr store,IntPtr leaf,IntPtr untrusted);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int IntOn(IntPtr owner);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int Purpose(IntPtr owner,int value);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int StoreFlags(IntPtr owner,uint flags);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate void HostFlags(IntPtr owner,uint flags);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int Host(IntPtr owner,[MarshalAs(UnmanagedType.LPUTF8Str)] string name,nuint length);

        internal readonly Init Initialize=Bind<Init>(crypto,"OPENSSL_init_crypto");
        internal readonly New NewStore=Bind<New>(crypto,"X509_STORE_new"),NewContext=Bind<New>(crypto,"X509_STORE_CTX_new"),
            NewStack=Bind<New>(crypto,"OPENSSL_sk_new_null");
        internal readonly Free FreeStore=Bind<Free>(crypto,"X509_STORE_free"),FreeContext=Bind<Free>(crypto,"X509_STORE_CTX_free"),
            FreeStack=Bind<Free>(crypto,"OPENSSL_sk_free");
        internal readonly OpenSslDer.Free FreeCertificate=Bind<OpenSslDer.Free>(crypto,"X509_free"),FreeCrl=Bind<OpenSslDer.Free>(crypto,"X509_CRL_free");
        internal readonly Pair Push=Bind<Pair>(crypto,"OPENSSL_sk_push"),AddCertificate=Bind<Pair>(crypto,"X509_STORE_add_cert"),
            AddCrl=Bind<Pair>(crypto,"X509_STORE_add_crl");
        internal readonly OpenSslDer.Decode DecodeCertificate=Bind<OpenSslDer.Decode>(crypto,"d2i_X509"),DecodeCrl=Bind<OpenSslDer.Decode>(crypto,"d2i_X509_CRL");
        internal readonly StoreFlags SetFlags=Bind<StoreFlags>(crypto,"X509_STORE_set_flags");
        internal readonly InitContext InitializeContext=Bind<InitContext>(crypto,"X509_STORE_CTX_init");
        internal readonly Purpose SetPurpose=Bind<Purpose>(crypto,"X509_STORE_CTX_set_purpose");
        internal readonly PointerOn Parameters=Bind<PointerOn>(crypto,"X509_STORE_CTX_get0_param");
        internal readonly HostFlags SetHostFlags=Bind<HostFlags>(crypto,"X509_VERIFY_PARAM_set_hostflags");
        internal readonly Host SetHost=Bind<Host>(crypto,"X509_VERIFY_PARAM_set1_host");
        internal readonly IntOn Verify=Bind<IntOn>(crypto,"X509_verify_cert");
        internal readonly Clear ClearErrors=Bind<Clear>(crypto,"ERR_clear_error");

        private static T Bind<T>(IntPtr module,string name) where T:Delegate
            =>Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(module,name));
    }
}
