using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace ProtectionLifecycle;

// The parent already holds the immutable installed version, including both
// modules and the containing directories. The restricted child separately
// pins the bytes it loads and allows only System32 dependency resolution.
internal sealed class OpenSslModuleLease : IDisposable
{
    private static readonly AssetSpec Crypto=PackageAssetCatalog.ForSchema(2).Single(a=>a.Id==PackageAssetCatalog.OpenSslCryptoId);
    private static readonly AssetSpec Ssl=PackageAssetCatalog.ForSchema(2).Single(a=>a.Id==PackageAssetCatalog.OpenSslLibraryId);
    private readonly Module crypto,ssl;
    internal IntPtr CryptoHandle=>crypto.Handle;
    internal IntPtr SslHandle=>ssl.Handle;
    private OpenSslModuleLease(string directory)
    {
        crypto=new(directory,Crypto);
        try{ssl=new(directory,Ssl);}catch{crypto.Dispose();throw;}
    }
    internal static void AssertOwnedPackage(ReviewedPackage package)
    {
        if(package.SchemaVersion!=2 || !Has(Crypto) || !Has(Ssl))
            throw WfpNative.Contract("OpenSslRequiresExactInstalledV2Assets");

        bool Has(AssetSpec spec)=>package.Files.Any(file=>file.Asset==spec && spec.Matches(file.Length,file.SHA256));
    }
    internal static OpenSslModuleLease OpenForInstalledWorker()
    {
        var directory=Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory);
        var version=Directory.GetParent(directory)?.Parent;
        var release=Identifiers.Hex32(version?.Name??"");
        var expected=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "ClaudeCodeProtection","versions",release,"bin","admin");
        if(!Same(expected,directory) || !Same(Path.Combine(expected,"ProtectionBroker.exe"),Environment.ProcessPath) ||
            !Same(Path.Combine(expected,"ProtectionLifecycle.dll"),typeof(OpenSslModuleLease).Assembly.Location))
            throw new InvalidDataException("OpenSSL requires the fixed installed Broker image");
        return new(expected);
    }
    internal static OpenSslModuleLease OpenForOrdinaryFixture()
        =>new(Path.Combine(AppContext.BaseDirectory,"native"));

    public void Dispose(){try{ssl.Dispose();}finally{crypto.Dispose();}}

    private static bool Same(string a,string? b)=>string.Equals(a,b,StringComparison.OrdinalIgnoreCase);
    private sealed class Module : IDisposable
    {
        private readonly FileStream file;
        internal IntPtr Handle {get;private set;}
        internal Module(string directory,AssetSpec asset)
        {
            var leaf=Path.GetFileName(asset.Path);var path=Path.Combine(directory,leaf);
            if(GetModuleHandle(leaf)!=IntPtr.Zero)throw new InvalidDataException("Unreviewed existing OpenSSL module refused");
            file=File.Open(path,FileMode.Open,FileAccess.Read,FileShare.Read);
            try
            {
                if(!asset.Matches(file.Length,Convert.ToHexString(SHA256.HashData(file))))
                    throw new InvalidDataException("Fixed OpenSSL asset changed");
                Handle=LoadLibrary(path,IntPtr.Zero,0x800); // LOAD_LIBRARY_SEARCH_SYSTEM32. Crypto is already loaded.
                if(Handle==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
                var actual=new StringBuilder(512);
                var count=GetModuleFileName(Handle,actual,(uint)actual.Capacity);
                if(count==0 || count>=actual.Capacity || !Same(path,actual.ToString()))
                    throw new InvalidDataException("Loaded OpenSSL image path differs");
            }
            catch{Dispose();throw;}
        }
        public void Dispose()
        {
            if(Handle!=IntPtr.Zero){NativeLibrary.Free(Handle);Handle=IntPtr.Zero;}
            file.Dispose();
        }
    }
    [DllImport("kernel32.dll",EntryPoint="LoadLibraryExW",ExactSpelling=true,SetLastError=true,CharSet=CharSet.Unicode)]
    private static extern IntPtr LoadLibrary(string path,IntPtr reserved,uint flags);
    [DllImport("kernel32.dll",EntryPoint="GetModuleHandleW",ExactSpelling=true,CharSet=CharSet.Unicode)]
    private static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32.dll",EntryPoint="GetModuleFileNameW",ExactSpelling=true,CharSet=CharSet.Unicode)]
    private static extern uint GetModuleFileName(IntPtr module,StringBuilder path,uint size);
}
