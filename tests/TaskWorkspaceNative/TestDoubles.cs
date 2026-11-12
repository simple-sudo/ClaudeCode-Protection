using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace ProtectionLifecycle;

internal sealed record BoundBytes(byte[] Bytes,string SHA256)
{
    internal static BoundBytes From(byte[] bytes)=>new(bytes,Convert.ToHexString(SHA256.HashData(bytes)));
}
internal sealed class ProtectedState
{
    private readonly Dictionary<string,BoundBytes> files=new(StringComparer.Ordinal);
    internal string InstallationId {get;}
    internal string PackageSid {get;}
    internal ProtectedState(string packageSid)
    {
        InstallationId=Guid.NewGuid().ToString("N");
        PackageSid=packageSid;
    }
    internal void AssertHeld(){}
    internal BoundBytes Read(string leaf,int maximum=8192)
    {
        if(!files.TryGetValue(leaf,out var value))throw WfpNative.Contract("NativeTestStateLeafMissing");
        if(value.Bytes.Length>maximum)throw WfpNative.Contract("NativeTestStateLeafTooLarge");
        return value;
    }
    internal BoundBytes? ReadOptional(string leaf)=>files.GetValueOrDefault(leaf);
    internal void WriteNew(string leaf,byte[] bytes)
    {
        if(files.ContainsKey(leaf))throw WfpNative.Contract("NativeTestStateLeafAlreadyExists");
        files.Add(leaf,BoundBytes.From(bytes));
    }
    internal string[] ListLeaves(string prefix)=>files.Keys.Where(k=>k.StartsWith(prefix,StringComparison.Ordinal)).OrderBy(k=>k,StringComparer.Ordinal).ToArray();
}
internal sealed record ProfileStorageReceipt(int SchemaVersion,string InstallationId,string ProfileId,bool Control,string OwnerSid,
    string Name,string Sid,string StorageRoot,string StorageIdentity,string ParentIdentity,string Status);
internal sealed class InstallationPackageSid : IDisposable
{
    internal string Value {get;}
    internal InstallationPackageSid(ProtectedState state)=>Value=state.PackageSid;
    public void Dispose(){}
}
internal static class SessionProfileRecovery
{
    internal static string ValidateCleanupIntent(ProtectedState state,ProfileStorageReceipt profile)
    {
        state.AssertHeld();
        var created=state.Read("profile-created-"+profile.ProfileId+".json",8192);
        var raw=state.Read("profile-delete-intent-"+profile.ProfileId+".json",8192);
        using var doc=JsonDocument.Parse(raw.Bytes,new JsonDocumentOptions{MaxDepth=3});
        var root=doc.RootElement;
        StrictJson.Fields(root,"SchemaVersion","InstallationId","ProfileId","CreatedSHA256","JobId","BindingSHA256","CompletionSHA256","Scope","NewProcessAdmissionAllowed");
        if(root.GetProperty("SchemaVersion").GetInt32()!=2 ||
            StrictJson.Text(root,"InstallationId")!=state.InstallationId ||
            StrictJson.Text(root,"ProfileId")!=profile.ProfileId ||
            StrictJson.Text(root,"CreatedSHA256")!=created.SHA256 ||
            LifecycleJournal.NullableText(root,"JobId") is not null ||
            LifecycleJournal.NullableText(root,"BindingSHA256") is not null ||
            LifecycleJournal.NullableText(root,"CompletionSHA256") is not null ||
            StrictJson.Text(root,"Scope")!="EXACT_CREATED_CURRENT_USER_PROFILE_ONLY" ||
            root.GetProperty("NewProcessAdmissionAllowed").GetBoolean())
            throw WfpNative.Contract("ProfileCleanupIntentMismatch");
        return raw.SHA256;
    }
}
internal static class SessionResources
{
    internal static void AssertFreshWorkspaceForRecovery(Microsoft.Win32.SafeHandles.SafeFileHandle handle,string humanSid,string packageSid)
    {
        using var descriptor=new WorkspaceDescriptor(humanSid,packageSid,true);
        descriptor.AssertApplied(handle,allowMissingLowLabel:true);
    }
    internal static void AssertMutableWorkspace(Microsoft.Win32.SafeHandles.SafeFileHandle handle,string humanSid,string packageSid)
    {
        using var descriptor=new WorkspaceDescriptor(humanSid,packageSid,true);
        descriptor.AssertApplied(handle);
    }
}
internal static class WfpNative
{
    internal static InvalidDataException Contract(string reason)=>new(reason);
    internal static string Describe(Exception error)=>error.GetType().Name+": "+error.Message;
}
internal sealed class WfpFailure : IOException
{
    internal WfpFailure(string stage,uint status):base(stage+" (0x"+status.ToString("X8")+")"){}
}
internal static class Identifiers
{
    internal static string Hex32(string value)
        =>value.Length==32 && value.All(c=>char.IsAsciiHexDigit(c))?value.ToLowerInvariant():throw WfpNative.Contract("IdentifierHex32Invalid");
    internal static string ObjectIdentity(string value)
        =>System.Text.RegularExpressions.Regex.IsMatch(value,@"^[0-9A-Fa-f]{8}:[0-9A-Fa-f]{8}:[0-9A-Fa-f]{8}$")
            ?value.ToUpperInvariant():throw WfpNative.Contract("ObjectIdentityInvalid");
}
internal static class StrictJson
{
    internal static void Fields(JsonElement root,params string[] expected)
    {
        var names=root.EnumerateObject().Select(p=>p.Name).ToArray();
        if(names.Length!=expected.Length || names.Distinct(StringComparer.Ordinal).Count()!=names.Length ||
            names.Except(expected,StringComparer.Ordinal).Any())throw WfpNative.Contract("StrictJsonFieldsMismatch");
    }
    internal static string Text(JsonElement root,string name)=>root.GetProperty(name).GetString()??throw WfpNative.Contract("StrictJsonTextMissing");
}
internal static class LifecycleJournal
{
    internal static string? NullableText(JsonElement root,string name)
        =>root.GetProperty(name).ValueKind==JsonValueKind.Null?null:StrictJson.Text(root,name);
}
internal static class KernelJobSeal
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct SecurityAttributes
    {
        internal int Length;
        internal IntPtr Descriptor;
        internal int Inherit;
    }
}
internal enum CreationRole { OfficialClaudeDirectory, OfficialClaudeExe }
internal sealed class CreationTag
{
    internal CreationRole Role {get;}
    internal string Sid {get;}
    internal CreationTag(CreationRole role,string sid){Role=role;Sid=sid;}
    internal static CreationTag? TryParse(string sid)=>null;
}
