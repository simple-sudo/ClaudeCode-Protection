using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

internal sealed record ResourceProbePlan(int SchemaVersion,string Nonce,string InstallationId,string Release,int BrokerPid,string ToolSHA256,string? GitAssetSetSHA256,string? WorkspaceInputSHA256,string ProgramFilesRoot)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault)]
    public bool DevelopProject {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? HostPrivacySHA256 {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? CallerProjectKind {get;init;}
    internal static ResourceProbePlan Parse(string raw)
    {
        if(raw.Length>1024)throw WfpNative.Contract("ResourcePlanBoundsRefused");
        using var json=JsonDocument.Parse(raw);var fields=new[]{"SchemaVersion","Nonce","InstallationId","Release","BrokerPid","ToolSHA256","GitAssetSetSHA256","WorkspaceInputSHA256","ProgramFilesRoot"};
        var schema=json.RootElement.GetProperty("SchemaVersion").GetInt32();
        StrictJson.Fields(json.RootElement,schema==6?fields.Concat(new[]{"DevelopProject","HostPrivacySHA256","CallerProjectKind"}).ToArray():schema==5?fields.Concat(new[]{"DevelopProject","HostPrivacySHA256"}).ToArray():fields);
        var plan=JsonSerializer.Deserialize<ResourceProbePlan>(raw)??throw WfpNative.Contract("ResourcePlanMissing");plan.Validate();return plan;
    }
    internal void Validate()
    {
        if(SchemaVersion!=(DevelopProject?(CallerProjectKind is null?5:6):3) || BrokerPid<=0 || WindowsPathSeal.Canonical(ProgramFilesRoot)!=ProgramFilesRoot ||
            CallerProjectKind is not null && (!DevelopProject || !CSharpProjectTask.IsKind(CallerProjectKind)) ||
            (DevelopProject?!WorkspaceBundle.IsHash(HostPrivacySHA256):HostPrivacySHA256 is not null))throw WfpNative.Contract("ResourceQualificationPlanRefused");
        _=Identifiers.Hex32(Nonce);_=Identifiers.Hex32(InstallationId);_=Identifiers.Hex32(Release);_=Identifiers.Hash(ToolSHA256);
        if(GitAssetSetSHA256 is not null && GitAssetSetSHA256!=SessionGitToolchain.AssetSetSHA256)throw WfpNative.Contract("GitAssetSetNotReviewed");
        if(WorkspaceInputSHA256 is not null && (GitAssetSetSHA256 is null || !WorkspaceBundle.IsHash(WorkspaceInputSHA256)))throw WfpNative.Contract("WorkspaceDataPlanRefused");
        if(DevelopProject && (GitAssetSetSHA256!=SessionGitToolchain.AssetSetSHA256 ||
            (CallerProjectKind is null?WorkspaceInputSHA256!=BundledProjectDevelopment.BaselineHash:!WorkspaceBundle.IsHash(WorkspaceInputSHA256))))throw WfpNative.Contract(CallerProjectKind is null?"FixedDevelopmentProjectPlanRequired":"ExplicitCallerProjectPlanRequired");
    }
    // Paths are resolved by the trusted owner outside LPAC. These are internal
    // runtime facts, never a privileged host-path operation or CLI parameter.
    internal string ExpectedChildImage=>WindowsPathSeal.Child(ProgramFilesRoot,"ClaudeCodeProtection/versions/"+Release+"/bin/admin/ProtectionBroker.exe");
    internal string Fixture=>WindowsPathSeal.Child(ProgramFilesRoot,"ClaudeCodeProtection-State/resource-fixture-"+Nonce+".json");
    internal string GitDirectory=>WindowsPathSeal.Child(ProgramFilesRoot,"Git/mingw64/bin");
    internal string PowerShellDirectory=>SessionPowerShellToolchain.DirectoryFor(ProgramFilesRoot);
    internal string PowerShellToolPath=>SessionPowerShellToolchain.ToolFor(ProgramFilesRoot);
    internal string PowerShellLaunchImage=>ExpectedChildImage;
    // Explicit workspace bytes authorize fixed Git data processing only.
    // General tool qualification must still prove PowerShell and compilation.
    internal static (bool PowerShell,bool Compiler) ToolRequirements(bool developProject,bool hasWorkspaceInput)
    {
        var powerShell=!developProject && !hasWorkspaceInput;
        return (powerShell,powerShell || developProject);
    }
    internal bool RequiresPowerShell=>ToolRequirements(DevelopProject,WorkspaceInputSHA256 is not null).PowerShell;
    internal bool RequiresCompilerTool=>ToolRequirements(DevelopProject,WorkspaceInputSHA256 is not null).Compiler;
    internal string Workspace(string sid)=>GitAssetSetSHA256 is null?WindowsPathSeal.Child(SessionResources.ProfileFolder(sid),"workspace-"+Nonce):WindowsPathSeal.Child(ProgramFilesRoot,"ClaudeCodeProtection-Task-"+Nonce);
    internal byte[] Input=>Encoding.UTF8.GetBytes("CPC-RESOURCE:"+Nonce);
    // Same data transfer contract as daily workspace-pack, without importing
    // a caller-selected workload into this fixed qualification entry point.
    internal byte[] FixedProjectBundle=>WorkspaceBundle.Create(new[]{("payload.txt",Input),
        ("src/message.txt",Encoding.UTF8.GetBytes("Project input "+Nonce+"\n")),
        ("README.md",Encoding.UTF8.GetBytes("Offline workspace transfer\n"))}).Serialize();
    internal byte[] ProjectBundle
    {
        get
        {
            if(WorkspaceInputSHA256 is null)return FixedProjectBundle;
            using var file=File.OpenRead(WindowsPathSeal.Child(Workspace(""),"project-input.json"));
            if(file.Length is <1 or >WorkspaceBundle.MaxBundleBytes)throw WfpNative.Contract("WorkspaceDataLengthRefused");
            var bytes=new byte[checked((int)file.Length)];file.ReadExactly(bytes);
            if(WorkspaceBundle.Hash(bytes)!=WorkspaceInputSHA256)throw WfpNative.Contract("WorkspaceDataDigestChanged");
            _=WorkspaceBundle.Parse(bytes);return bytes;
        }
    }
}
