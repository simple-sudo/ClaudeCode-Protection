using System.Runtime.InteropServices;

namespace ProtectionLifecycle;

// Only the ordinary memory fixture calls this class. The production verifier
// consumes issuer-signed CRL bytes and does not create a revocation list.
internal sealed class OpenSslOfflineCrlFixture(IntPtr crypto)
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate IntPtr New();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate IntPtr Time(IntPtr value,int seconds);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void Free(IntPtr value);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int SetNumber(IntPtr value,int number);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int Pair(IntPtr first,IntPtr second);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int Sign(IntPtr crl,IntPtr key,IntPtr digest);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int Encode(IntPtr crl,ref IntPtr cursor);

    private readonly New newCrl=Bind<New>(crypto,"X509_CRL_new");
    private readonly Free freeCrl=Bind<Free>(crypto,"X509_CRL_free");
    private readonly Free freeTime=Bind<Free>(crypto,"ASN1_TIME_free");
    private readonly Time adjust=Bind<Time>(crypto,"X509_gmtime_adj");
    private readonly SetNumber version=Bind<SetNumber>(crypto,"X509_CRL_set_version");
    private readonly Pair issuer=Bind<Pair>(crypto,"X509_CRL_set_issuer_name");
    private readonly Pair last=Bind<Pair>(crypto,"X509_CRL_set1_lastUpdate");
    private readonly Pair next=Bind<Pair>(crypto,"X509_CRL_set1_nextUpdate");
    private readonly New newRevoked=Bind<New>(crypto,"X509_REVOKED_new");
    private readonly Free freeRevoked=Bind<Free>(crypto,"X509_REVOKED_free");
    private readonly Pair setSerial=Bind<Pair>(crypto,"X509_REVOKED_set_serialNumber");
    private readonly Pair setDate=Bind<Pair>(crypto,"X509_REVOKED_set_revocationDate");
    private readonly Pair addRevoked=Bind<Pair>(crypto,"X509_CRL_add0_revoked");
    private readonly Sign sign=Bind<Sign>(crypto,"X509_CRL_sign");
    private readonly Pair size=Bind<Pair>(crypto,"i2d_X509_CRL");
    private readonly Encode encode=Bind<Encode>(crypto,"i2d_X509_CRL");

    internal (byte[] RootCurrent,byte[] Current,byte[] Expired,byte[] Revoked,byte[] WrongSigner) Create(
        IntPtr rootSubject,IntPtr rootKey,IntPtr subject,IntPtr key,IntPtr otherKey,IntPtr serial)
        =>(Make(rootSubject,rootKey,-300,3600),Make(subject,key,-300,3600),Make(subject,key,-3600,-300),
            Make(subject,key,-300,3600,serial),Make(subject,otherKey,-300,3600));

    private byte[] Make(IntPtr subject,IntPtr key,int from,int until,IntPtr revokedSerial=default)
    {
        var crl=newCrl();
        var before=IntPtr.Zero;
        var after=IntPtr.Zero;
        var revoked=IntPtr.Zero;
        try
        {
            Require(crl!=IntPtr.Zero && subject!=IntPtr.Zero && version(crl,1)==1 && issuer(crl,subject)==1);
            before=adjust(IntPtr.Zero,from);
            after=adjust(IntPtr.Zero,until);
            Require(before!=IntPtr.Zero && after!=IntPtr.Zero && last(crl,before)==1 && next(crl,after)==1);
            if(revokedSerial!=IntPtr.Zero)
            {
                revoked=newRevoked();
                Require(revoked!=IntPtr.Zero && setSerial(revoked,revokedSerial)==1 && setDate(revoked,before)==1);
                Require(addRevoked(crl,revoked)==1);
                revoked=IntPtr.Zero; // CRL now owns it.
            }
            Require(sign(crl,key,IntPtr.Zero)>0);
            var bytes=size(crl,IntPtr.Zero);
            Require(bytes is >0 and <=4096);
            var output=new byte[bytes];
            var pinned=GCHandle.Alloc(output,GCHandleType.Pinned);
            try
            {
                var start=pinned.AddrOfPinnedObject();
                var cursor=start;
                Require(encode(crl,ref cursor)==bytes && cursor==start+bytes);
            }
            finally{pinned.Free();}
            return output;
        }
        finally
        {
            if(revoked!=IntPtr.Zero)freeRevoked(revoked);
            if(after!=IntPtr.Zero)freeTime(after);
            if(before!=IntPtr.Zero)freeTime(before);
            if(crl!=IntPtr.Zero)freeCrl(crl);
        }
    }

    private static T Bind<T>(IntPtr module,string name) where T:Delegate
        =>Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(module,name));
    private static void Require(bool result)
    {
        if(!result)throw new InvalidDataException("Ordinary OpenSSL CRL fixture construction failed");
    }
}
