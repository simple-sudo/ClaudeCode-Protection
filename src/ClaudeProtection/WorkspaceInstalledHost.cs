using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using ClaudeCodeProtection.Workspaces;

namespace ClaudeProtection;

// Authenticate and hold the existing sibling before asking Windows to elevate
// it. No download, executable selection, ACL repair or package installation.
internal sealed class WorkspaceInstalledHost : IDisposable
{
    private readonly WorkspaceFiles.HeldPaths paths=new();
    private static readonly string[] Trusted={"S-1-5-18","S-1-5-32-544",
        ((SecurityIdentifier)new NTAccount("NT SERVICE","TrustedInstaller").Translate(typeof(SecurityIdentifier))).Value};
    private static readonly (string Asset,string Relative)[] Required={
        ("daily-exe","bin/current/ClaudeProtection.exe"),("daily-dll","bin/current/ClaudeProtection.dll"),
        ("daily-deps","bin/current/ClaudeProtection.deps.json"),("daily-runtime","bin/current/ClaudeProtection.runtimeconfig.json"),
        ("broker-exe","bin/admin/ProtectionBroker.exe"),("broker-dll","bin/admin/ProtectionBroker.dll"),
        ("broker-deps","bin/admin/ProtectionBroker.deps.json"),("broker-runtime","bin/admin/ProtectionBroker.runtimeconfig.json"),
        ("broker-lifecycle","bin/admin/ProtectionLifecycle.dll")};
    internal WorkspaceInstalledHost(string root)
    {
        try
        {
            foreach(var relative in new[]{"","bin/current","bin/admin"})
            {
                var folder=relative.Length==0?root:Path.Combine(root,relative.Replace('/','\\'));
                paths.DirectoryChain(folder);
                for(var directory=new DirectoryInfo(folder);directory is not null;directory=directory.Parent)
                    Check(directory.GetAccessControl(),directory.FullName.Equals(folder,StringComparison.OrdinalIgnoreCase));
            }
            var manifest=paths.ReadFile(Path.Combine(root,"package.json"));Check(manifest.GetAccessControl(),true);
            if(manifest.Length is <1 or >65536)throw new InvalidDataException("Installed manifest size refused");
            var bytes=new byte[(int)manifest.Length];manifest.ReadExactly(bytes);
            using var doc=JsonDocument.Parse(bytes);var r=doc.RootElement;
            if(r.GetProperty("SchemaVersion").GetInt32()!=1 || r.GetProperty("Scope").GetString()!="UNACTIVATED_PRODUCT" ||
                r.GetProperty("Release").GetString()!=Path.GetFileName(root))throw new InvalidDataException("Installed manifest location differs");
            var files=r.GetProperty("Files").EnumerateArray().ToArray();
            if(files.Length!=14 || files.Select(f=>f.GetProperty("Asset").GetString()).Distinct(StringComparer.Ordinal).Count()!=14)
                throw new InvalidDataException("Ambiguous installed asset catalog");
            foreach(var asset in Required)
            {
                var matches=files.Where(f=>f.GetProperty("Asset").GetString()==asset.Asset).ToArray();
                if(matches.Length!=1)throw new InvalidDataException("Installed executable asset missing");
                var file=paths.ReadFile(Path.Combine(root,asset.Relative.Replace('/','\\')));Check(file.GetAccessControl(),true);
                if(file.Length is <1 or >128*1024*1024 || file.Length!=matches[0].GetProperty("Length").GetInt64() ||
                    Convert.ToHexString(SHA256.HashData(file))!=matches[0].GetProperty("SHA256").GetString())
                    throw new InvalidDataException("Installed executable bytes differ");
            }
        }
        catch{paths.Dispose();throw;}
    }
    private static void Check(FileSystemSecurity security,bool leaf)
    {
        var owner=security.GetOwner(typeof(SecurityIdentifier))?.Value;
        if(owner is null || !Trusted.Contains(owner,StringComparer.Ordinal))
            throw new InvalidDataException("Untrusted installed owner");
        var danger=leaf?0x500d0156L:0x500d0040L;
        foreach(FileSystemAccessRule rule in security.GetAccessRules(true,true,typeof(SecurityIdentifier)))
        {
            if((rule.PropagationFlags&PropagationFlags.InheritOnly)!=0)continue;
            if(rule.AccessControlType==AccessControlType.Allow && ((long)rule.FileSystemRights&danger)!=0 &&
                !Trusted.Contains(rule.IdentityReference.Value,StringComparer.Ordinal))throw new InvalidDataException("Untrusted installed write grant");
        }
    }
    public void Dispose()=>paths.Dispose();
}
