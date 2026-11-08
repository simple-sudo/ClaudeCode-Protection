using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace ProtectionLifecycle;

internal sealed class OpenSslModuleException(string stage,Exception cause) : IOException("Fixed native module qualification failed",cause)
{
    internal string Stage {get;}=stage;
    internal int ErrorCode=>InnerException is Win32Exception native?native.NativeErrorCode:InnerException!.HResult;
}

// The parent already holds the immutable installed version, including both
// modules and the containing directories. The restricted child separately
// pins the bytes it loads and allows only System32 dependency resolution.
internal sealed class OpenSslModuleLease : IDisposable
{
    private const int Schema=PackageAssetCatalog.OpenSslWindowsEntropySchema;
    private static readonly AssetSpec Crypto=PackageAssetCatalog.ForSchema(Schema).Single(a=>a.Id==PackageAssetCatalog.OpenSslWindowsCryptoId);
    private static readonly AssetSpec Ssl=PackageAssetCatalog.ForSchema(Schema).Single(a=>a.Id==PackageAssetCatalog.OpenSslWindowsLibraryId);
    private readonly Module crypto,ssl;
    internal IntPtr CryptoHandle=>crypto.Handle;
    internal IntPtr SslHandle=>ssl.Handle;
    private OpenSslModuleLease(string directory)
    {
        crypto=new(directory,Crypto,"CRYPTO");
        try{ssl=new(directory,Ssl,"SSL");}catch{crypto.Dispose();throw;}
    }
    internal static void AssertOwnedPackage(ReviewedPackage package)
    {
        if(package.SchemaVersion!=Schema || !Has(Crypto) || !Has(Ssl))
            throw WfpNative.Contract("OpenSslRequiresExactWindowsEntropyAssets");

        bool Has(AssetSpec spec)=>package.Files.Any(file=>file.Asset==spec && spec.Matches(file.Length,file.SHA256));
    }
    internal const string ReleaseVariable="CPC_OPENSSL_RELEASE";
    internal static bool IsReportedStage(string? stage)=>stage is "MODULE_IMAGE" ||
        (stage is not null && stage.Split('_') is ["MODULE","CRYPTO" or "SSL","PRELOADED" or "READ" or "DIGEST" or "LOAD" or "MAPPED" or "CLEANUP"]);
    internal static OpenSslModuleLease OpenForInstalledWorker(string release)
        =>new(InstalledDirectory(release,AppContext.BaseDirectory,Environment.ProcessPath,typeof(OpenSslModuleLease).Assembly.Location));

    // The owner derives and locks the path from FixedLayout and checks the
    // suspended image through its kernel handle before resume. The child needs
    // only the release binding and its own image location, no Shell lookup or
    // environment-provided directory. It can only load the exact reviewed bytes.
    internal static string InstalledDirectory(string release,string baseDirectory,string? image,string assembly)
    {
        try
        {
            var directory=Path.TrimEndingDirectorySeparator(baseDirectory);
            var suffix="\\ClaudeCodeProtection\\versions\\"+Identifiers.Hex32(release)+"\\bin\\admin";
            if(directory.Length is <4 or >200 || !char.IsAsciiLetter(directory[0]) || directory[1]!=':' || directory[2]!='\\' ||
                directory.Contains('/') || directory.AsSpan(2).Contains(':') || directory.Contains('\0') ||
                !directory.EndsWith(suffix,StringComparison.OrdinalIgnoreCase) || directory.Length<=2+suffix.Length ||
                directory[3..].Split('\\').Any(part=>part.Length==0 || part.EndsWith('.') || part.EndsWith(' ')) ||
                !Same(directory,Path.GetFullPath(directory)) ||
                !Same(Path.Combine(directory,"ProtectionBroker.exe"),image) ||
                !Same(Path.Combine(directory,"ProtectionLifecycle.dll"),assembly))
                throw new InvalidDataException("OpenSSL requires the fixed installed Broker image");
            return directory;
        }
        catch(Exception error){throw new OpenSslModuleException("MODULE_IMAGE",error);}
    }
    internal static OpenSslModuleLease OpenForOrdinaryFixture()
        =>new(Path.Combine(AppContext.BaseDirectory,"native"));

    public void Dispose(){try{ssl.Dispose();}finally{crypto.Dispose();}}

    private static bool Same(string a,string? b)=>string.Equals(a,b,StringComparison.OrdinalIgnoreCase);
    private sealed class Module : IDisposable
    {
        private FileStream? file;
        internal IntPtr Handle {get;private set;}
        internal Module(string directory,AssetSpec asset,string role)
        {
            var leaf=Path.GetFileName(asset.Path);var path=Path.Combine(directory,leaf);
            var stage="PRELOADED";
            try
            {
                if(GetModuleHandle(leaf)!=IntPtr.Zero)throw new InvalidDataException("Unreviewed existing OpenSSL module refused");
                stage="READ";
                file=File.Open(path,FileMode.Open,FileAccess.Read,FileShare.Read);
                stage="DIGEST";
                if(!asset.Matches(file.Length,Convert.ToHexString(SHA256.HashData(file))))
                    throw new InvalidDataException("Fixed OpenSSL asset changed");
                stage="LOAD";
                Handle=LoadLibrary(path,IntPtr.Zero,0x800); // LOAD_LIBRARY_SEARCH_SYSTEM32. Crypto is already loaded.
                if(Handle==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
                stage="MAPPED";
                var actual=new StringBuilder(512);
                var count=GetModuleFileName(Handle,actual,(uint)actual.Capacity);
                if(count==0 || count>=actual.Capacity || !Same(path,actual.ToString()))
                    throw new InvalidDataException("Loaded OpenSSL image path differs");
            }
            catch(Exception error)
            {
                try{Dispose();}
                catch(Exception cleanup){throw new OpenSslModuleException("MODULE_"+role+"_CLEANUP",cleanup);}
                throw new OpenSslModuleException("MODULE_"+role+"_"+stage,error);
            }
        }
        public void Dispose()
        {
            try{if(Handle!=IntPtr.Zero){NativeLibrary.Free(Handle);Handle=IntPtr.Zero;}}
            finally{file?.Dispose();}
        }
    }
    [DllImport("kernel32.dll",EntryPoint="LoadLibraryExW",ExactSpelling=true,SetLastError=true,CharSet=CharSet.Unicode)]
    private static extern IntPtr LoadLibrary(string path,IntPtr reserved,uint flags);
    [DllImport("kernel32.dll",EntryPoint="GetModuleHandleW",ExactSpelling=true,CharSet=CharSet.Unicode)]
    private static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32.dll",EntryPoint="GetModuleFileNameW",ExactSpelling=true,CharSet=CharSet.Unicode)]
    private static extern uint GetModuleFileName(IntPtr module,StringBuilder path,uint size);
}
