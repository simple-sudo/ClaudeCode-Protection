using System.Security.Principal;

namespace ProtectionLifecycle;

// This view is entirely under the task tree. The existing profile lease
// still owns the kernel package registration and all closed-Job cleanup.
internal sealed class OfflineConsoleStorage : IDisposable
{
    internal sealed record Paths(string Base,string Packages,string Package,string LocalData,string Temp);
    private readonly PathLease workspace;
    private readonly PathLease[] directories;
    internal Paths View {get;}

    private OfflineConsoleStorage(PathLease workspace,Paths view,PathLease[] directories)
    {this.workspace=workspace;View=view;this.directories=directories;}

    internal static Paths Resolve(string workspace,string package)
    {
        const string prefix="ClaudeCodeProtection.";
        if(!package.StartsWith(prefix,StringComparison.Ordinal))
            throw WfpNative.Contract("OfflineConsolePackageNameDiffers");
        _=Identifiers.Hex32(package[prefix.Length..]);
        var root=WindowsPathSeal.Child(workspace,"local");
        var packages=WindowsPathSeal.Child(root,"Packages");
        var directory=WindowsPathSeal.Child(packages,package);
        var localData=WindowsPathSeal.Child(directory,"AC");
        return new(root,packages,directory,localData,WindowsPathSeal.Child(localData,"Temp"));
    }

    internal static OfflineConsoleStorage Create(ProtectedState state,PathLease workspace,string? exactCreatorAudience=null)
    {
        state.AssertHeld();workspace.AssertHeld();
        using var identity=WindowsIdentity.GetCurrent();
        using var package=new InstallationPackageSid(state);
        var owner=exactCreatorAudience??identity.User?.Value??throw WfpNative.Contract("WorkspaceHumanOwnerMissing");
        var view=Resolve(workspace.Path,package.Name);
        var directories=new List<PathLease>();
        try
        {
            foreach(var path in new[]{view.Base,view.Packages,view.Package,view.LocalData,view.Temp})
                directories.Add(SessionWorkspaceDirectory.CreateWorkspace(path,owner,package.Value,true));
            return new(workspace,view,directories.ToArray());
        }
        catch
        {
            for(var i=directories.Count-1;i>=0;i--)directories[i].Dispose();
            throw;
        }
    }

    internal void AssertHeld(PathLease expectedWorkspace)
    {
        if(!ReferenceEquals(workspace,expectedWorkspace))throw WfpNative.Contract("OfflineConsoleStorageOwnerDiffers");
        workspace.AssertHeld();
        foreach(var directory in directories)directory.AssertHeld();
    }

    public void Dispose()
    {
        for(var i=directories.Length-1;i>=0;i--)directories[i].Dispose();
    }
}
