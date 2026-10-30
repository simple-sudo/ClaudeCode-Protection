using System.Security.Cryptography;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed record PowerShellAsset(string Path,long Length,string SHA256);
internal sealed record PowerShellAssets(int SchemaVersion,string Version,string ArchiveSHA256,PowerShellAsset[] Files);

// A fixed Microsoft framework-dependent distribution; the existing trusted
// .NET 8 installation supplies its runtime. No host/user profiles or modules
// are copied. Provisioning is a separate, reviewed installation operation.
internal sealed class SessionPowerShellToolchain : IDisposable
{
    internal const string Version="7.4.22";
    internal const string Folder="ClaudeCodeProtection-PowerShell-7.4.22";
    internal const string ArchiveSHA256="40F7ED3365CE3BA6792DEB321B9AC7D68182D749C1AD72A49A2C84C3E4C364FA";
    internal const string AssetSetSHA256="61D9FDB42EB99E0370E93D9E1A0D1E94F8E800458CB321C2455E542968E81322";
    internal const string ExecutableSHA256="C3CB38D4A6CA4FE192B7F2CFD1C38CAB85E4C369AB9692EBE9FABC52929D807B";
    internal static string DirectoryFor(string programFiles)=>WindowsPathSeal.Child(programFiles,Folder);
    internal static string ToolFor(string programFiles)=>WindowsPathSeal.Child(DirectoryFor(programFiles),"pwsh.exe");
    private readonly List<PathLease> directories=new();
    private readonly List<FileStream> files=new();
    internal static PowerShellAssets ReadAssets()
    {
        using var resource=typeof(SessionPowerShellToolchain).Assembly.GetManifestResourceStream("ProtectionLifecycle.PowerShellToolchain.json")
            ??throw WfpNative.Contract("PowerShellAssetPolicyMissing");
        if(resource.Length is <1 or >131072)throw WfpNative.Contract("PowerShellAssetPolicyBounds");
        var bytes=new byte[checked((int)resource.Length)];resource.ReadExactly(bytes);
        if(Convert.ToHexString(SHA256.HashData(bytes))!=AssetSetSHA256)throw WfpNative.Contract("PowerShellAssetPolicyChanged");
        using var doc=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=4});
        StrictJson.Fields(doc.RootElement,"SchemaVersion","Version","ArchiveSHA256","Files");
        foreach(var row in doc.RootElement.GetProperty("Files").EnumerateArray())StrictJson.Fields(row,"Path","Length","SHA256");
        var value=JsonSerializer.Deserialize<PowerShellAssets>(bytes)??throw WfpNative.Contract("PowerShellAssetPolicyMissing");
        if(value.SchemaVersion!=1 || value.Version!=Version || value.ArchiveSHA256!=ArchiveSHA256 || value.Files.Length!=552)
            throw WfpNative.Contract("PowerShellAssetPolicyDiffers");
        var paths=new HashSet<string>(StringComparer.OrdinalIgnoreCase);long total=0;
        foreach(var asset in value.Files)
        {
            if(asset.Path.Length is <1 or >200 || asset.Path.Split('/').Length>10 || asset.Path.Split('/').Any(part=>
                part.Length==0 || part is "." or ".." || part.Any(c=>!char.IsAsciiLetterOrDigit(c) && c is not ('.' or '_' or '-'))) ||
                !paths.Add(asset.Path) || asset.Length is <0 or >16*1024*1024)throw WfpNative.Contract("PowerShellAssetPathOrLengthRefused");
            _=Identifiers.Hash(asset.SHA256);total=checked(total+asset.Length);
        }
        if(total>128*1024*1024 || value.Files.Single(a=>a.Path=="pwsh.exe").SHA256!=ExecutableSHA256)
            throw WfpNative.Contract("PowerShellAssetSetRefused");
        return value;
    }
    internal static SessionPowerShellToolchain Open()
    {
        var result=new SessionPowerShellToolchain();
        try
        {
            var root=DirectoryFor(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            var assets=ReadAssets();var parents=new HashSet<string>(StringComparer.OrdinalIgnoreCase){root};
            foreach(var asset in assets.Files)
            {
                var parent=Path.GetDirectoryName(WindowsPathSeal.Child(root,asset.Path));
                while(parent is not null && !string.Equals(parent,root,StringComparison.OrdinalIgnoreCase))
                {parents.Add(parent);parent=Path.GetDirectoryName(parent);}
            }
            foreach(var directory in parents.OrderBy(p=>p.Length))result.directories.Add(WindowsPathSeal.LockDirectory(directory,PathPolicy.CreationParent));
            foreach(var asset in assets.Files)
            {
                var stream=new FileStream(WindowsPathSeal.Open(WindowsPathSeal.Child(root,asset.Path),false,true),FileAccess.Read,1,false);
                result.files.Add(stream);
                if(stream.Length!=asset.Length || Convert.ToHexString(SHA256.HashData(stream))!=asset.SHA256)
                    throw WfpNative.Contract("FixedPowerShellAssetChanged");
                stream.Position=0;
            }
            result.AssertHeld();return result;
        }
        catch{result.Dispose();throw;}
    }
    internal void AssertHeld()
    {
        if(files.Count!=552 || directories.Count==0)throw WfpNative.Contract("PowerShellAssetLeaseIncomplete");
        foreach(var directory in directories)directory.AssertHeld();
        foreach(var stream in files)
        {if(stream.SafeFileHandle.IsClosed)throw WfpNative.Contract("PowerShellAssetLeaseLost");WindowsPathSeal.AssertAcl(stream.SafeFileHandle,false,true);}
    }
    public void Dispose()
    {foreach(var stream in files)stream.Dispose();for(var i=directories.Count-1;i>=0;i--)directories[i].Dispose();}
}
