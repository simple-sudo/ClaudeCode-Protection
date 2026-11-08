using System.Runtime.InteropServices;

namespace ProtectionLifecycle;

// The fixture uses the same locked OpenSSL modules as the TLS transport.
// Certificates and private keys live only in this process.
internal sealed class OpenSslOfflineIdentity : IDisposable
{
    private readonly Native api;
    private IntPtr leaf,leafKey;
    internal byte[] TrustedRoot { get; }
    internal byte[] UntrustedRoot { get; }
    internal IntPtr Certificate=>leaf!=IntPtr.Zero?leaf:throw new ObjectDisposedException(nameof(OpenSslOfflineIdentity));
    internal IntPtr Key=>leafKey!=IntPtr.Zero?leafKey:throw new ObjectDisposedException(nameof(OpenSslOfflineIdentity));

    internal OpenSslOfflineIdentity(OpenSslModuleLease modules)
    {
        api=new Native(modules.CryptoHandle);
        Require(api.Initialize(OpenSslMemoryConnection.NoLoadConfig,IntPtr.Zero)==1,"FIXTURE_INIT");
        using var rootKey=CreateKey();
        using var wrongKey=CreateKey();
        using var root=CreateCertificate(rootKey.Value,IntPtr.Zero,rootKey.Value,"Fixed local TLS test root",1);
        using var wrong=CreateCertificate(wrongKey.Value,IntPtr.Zero,wrongKey.Value,"Independent local TLS test root",2);
        TrustedRoot=Encode(root.Value);
        UntrustedRoot=Encode(wrong.Value);
        using var key=CreateKey();
        using var certificate=CreateCertificate(key.Value,root.Value,rootKey.Value,"deliberate-mismatch.invalid",3);
        leafKey=key.Take();
        leaf=certificate.Take();
    }

    private Owned CreateKey()
    {
        using var context=Hold(api.NewKeyContext(IntPtr.Zero,"ED25519",IntPtr.Zero),api.FreeKeyContext,"FIXTURE_KEY_CONTEXT");
        Require(api.InitKey(context.Value)==1,"FIXTURE_KEY_INIT");
        var generated=api.GenerateKey(context.Value,out var key);
        if(generated==1 && key!=IntPtr.Zero)return new(key,api.FreeKey);
        var failure=Failure("FIXTURE_KEY");
        if(key!=IntPtr.Zero)api.FreeKey(key);
        throw failure;
    }

    private Owned CreateCertificate(IntPtr key,IntPtr issuer,IntPtr issuerKey,string subject,int serial)
    {
        using var cert=Hold(api.NewCertificate(),api.FreeCertificate,"FIXTURE_CERTIFICATE");
        var c=cert.Value;
        var name=api.Subject(c);
        Require(name!=IntPtr.Zero && api.SetVersion(c,2)==1 && api.SetNumber(api.Serial(c),serial)==1 &&
            api.AddName(name,"CN",0x1001,subject,-1,-1,0)==1 &&
            api.SetIssuer(c,issuer==IntPtr.Zero?name:api.Subject(issuer))==1 && api.SetPublicKey(c,key)==1 &&
            api.AdjustTime(api.NotBefore(c),-300)!=IntPtr.Zero && api.AdjustTime(api.NotAfter(c),3600)!=IntPtr.Zero,
            "FIXTURE_CERTIFICATE");
        if(issuer==IntPtr.Zero)
        {
            Extension(c,"basicConstraints","critical,CA:TRUE");
            Extension(c,"keyUsage","critical,keyCertSign");
        }
        else
        {
            Extension(c,"basicConstraints","critical,CA:FALSE");
            Extension(c,"keyUsage","critical,digitalSignature");
            Extension(c,"subjectAltName","DNS:"+SessionProxy.Target);
        }
        // Ed25519 chooses its own digest. X509_sign signs the in-memory object.
        Require(api.Sign(c,issuerKey,IntPtr.Zero)>0,"FIXTURE_SIGN");
        return new(cert.Take(),api.FreeCertificate);
    }

    private void Extension(IntPtr certificate,string name,string fixedValue)
    {
        // This fixed extension grammar cannot dereference a config section.
        using var extension=Hold(api.NewExtension(IntPtr.Zero,IntPtr.Zero,name,fixedValue),
            api.FreeExtension,"FIXTURE_EXTENSION");
        Require(api.AddExtension(certificate,extension.Value,-1)==1,"FIXTURE_EXTENSION");
    }

    private byte[] Encode(IntPtr cert)
    {
        var size=api.EncodedSize(cert,IntPtr.Zero);
        Require(size is >0 and <=4096,"FIXTURE_ENCODING");
        var memory=Marshal.AllocHGlobal(size);
        try
        {
            var cursor=memory;
            Require(api.Encode(cert,ref cursor)==size && cursor==memory+size,"FIXTURE_ENCODING");
            var result=new byte[size];
            Marshal.Copy(memory,result,0,size);
            return result;
        }
        finally{Marshal.FreeHGlobal(memory);}
    }

    public void Dispose()
    {
        if(leaf!=IntPtr.Zero){api.FreeCertificate(leaf);leaf=IntPtr.Zero;}
        if(leafKey!=IntPtr.Zero){api.FreeKey(leafKey);leafKey=IntPtr.Zero;}
    }

    private Owned Hold(IntPtr value,Native.Free release,string stage)
    {
        Require(value!=IntPtr.Zero,stage);
        return new(value,release);
    }
    private void Require(bool valid,string stage)
    {
        if(!valid)throw Failure(stage);
    }
    private OpenSslFixtureException Failure(string stage)=>new(stage,api.LastError());

    private sealed class Owned : IDisposable
    {
        private readonly Native.Free release;
        internal IntPtr Value {get;private set;}
        internal Owned(IntPtr value,Native.Free release)
        {
            Value=value;this.release=release;
        }
        internal IntPtr Take(){var value=Value;Value=IntPtr.Zero;return value;}
        public void Dispose(){if(Value!=IntPtr.Zero)release(Take());}
    }

    private sealed class Native(IntPtr module)
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int Init(ulong options,IntPtr settings);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate void Free(IntPtr item);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate IntPtr KeyContext(IntPtr library,[MarshalAs(UnmanagedType.LPStr)] string algorithm,IntPtr properties);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int IntOn(IntPtr item);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int Generate(IntPtr context,out IntPtr key);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate IntPtr New();
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate IntPtr PointerOn(IntPtr item);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int Number(IntPtr item,int value);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate IntPtr Time(IntPtr item,int offset);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int Pair(IntPtr first,IntPtr second);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int NameEntry(IntPtr name,[MarshalAs(UnmanagedType.LPStr)] string field,
            int type,[MarshalAs(UnmanagedType.LPStr)] string value,int length,int position,int set);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate IntPtr NewExt(IntPtr config,IntPtr context,
            [MarshalAs(UnmanagedType.LPStr)] string name,[MarshalAs(UnmanagedType.LPStr)] string value);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int AddExt(IntPtr cert,IntPtr extension,int location);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int SignCert(IntPtr cert,IntPtr key,IntPtr digest);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate int EncodeCert(IntPtr cert,ref IntPtr cursor);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] internal delegate uint Error();

        internal readonly Init Initialize=Bind<Init>(module,"OPENSSL_init_crypto");
        internal readonly KeyContext NewKeyContext=Bind<KeyContext>(module,"EVP_PKEY_CTX_new_from_name");
        internal readonly Free FreeKeyContext=Bind<Free>(module,"EVP_PKEY_CTX_free");
        internal readonly Free FreeKey=Bind<Free>(module,"EVP_PKEY_free");
        internal readonly IntOn InitKey=Bind<IntOn>(module,"EVP_PKEY_keygen_init");
        internal readonly Generate GenerateKey=Bind<Generate>(module,"EVP_PKEY_generate");
        internal readonly New NewCertificate=Bind<New>(module,"X509_new");
        internal readonly Free FreeCertificate=Bind<Free>(module,"X509_free");
        internal readonly PointerOn Subject=Bind<PointerOn>(module,"X509_get_subject_name");
        internal readonly PointerOn Serial=Bind<PointerOn>(module,"X509_get_serialNumber");
        internal readonly Number SetVersion=Bind<Number>(module,"X509_set_version");
        internal readonly Number SetNumber=Bind<Number>(module,"ASN1_INTEGER_set");
        internal readonly NameEntry AddName=Bind<NameEntry>(module,"X509_NAME_add_entry_by_txt");
        internal readonly Pair SetIssuer=Bind<Pair>(module,"X509_set_issuer_name");
        internal readonly Pair SetPublicKey=Bind<Pair>(module,"X509_set_pubkey");
        internal readonly PointerOn NotBefore=Bind<PointerOn>(module,"X509_getm_notBefore");
        internal readonly PointerOn NotAfter=Bind<PointerOn>(module,"X509_getm_notAfter");
        internal readonly Time AdjustTime=Bind<Time>(module,"X509_gmtime_adj");
        internal readonly NewExt NewExtension=Bind<NewExt>(module,"X509V3_EXT_nconf");
        internal readonly Free FreeExtension=Bind<Free>(module,"X509_EXTENSION_free");
        internal readonly AddExt AddExtension=Bind<AddExt>(module,"X509_add_ext");
        internal readonly SignCert Sign=Bind<SignCert>(module,"X509_sign");
        internal readonly Pair EncodedSize=Bind<Pair>(module,"i2d_X509");
        internal readonly EncodeCert Encode=Bind<EncodeCert>(module,"i2d_X509");
        internal readonly Error LastError=Bind<Error>(module,"ERR_peek_last_error");
        private static T Bind<T>(IntPtr module,string name) where T:Delegate
            =>Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(module,name));
    }
}

internal sealed class OpenSslFixtureException(string stage,uint nativeError) : IOException("Fixed in-memory OpenSSL certificate preparation failed")
{
    internal string Stage {get;}=stage;
    internal int ErrorCode=>nativeError==0?HResult:unchecked((int)nativeError);
    internal static bool IsReportedStage(string? value)=>value is "FIXTURE_INIT" or "FIXTURE_KEY_CONTEXT" or
        "FIXTURE_KEY_INIT" or "FIXTURE_KEY" or "FIXTURE_CERTIFICATE" or "FIXTURE_EXTENSION" or "FIXTURE_SIGN" or "FIXTURE_ENCODING";
}
