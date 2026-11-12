using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

internal sealed record OwnedJobIntent(int SchemaVersion,string InstallationId,string JobId,string Release,string ManifestSHA256,string Binding,string Scope,
    [property:JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)] string? CreatorServiceSid=null)
{
    private const string AtomicBinding="ATOMIC_JOB_LIST_REQUIRED",PrivateScope="JOB_MEMBERS_ONLY",CreatorScope="SESSION_ZERO_CREATOR_JOB_MEMBERS_ONLY";
    internal static string Leaf(string id)=>"job-intent-"+Identifiers.Hex32(id)+".json";
    internal string Alias=>"CPCJob."+Identifiers.Hex32(InstallationId)+"."+Identifiers.Hex32(JobId);
    internal string Name=>CreatorServiceSid is null?Alias+"\\Session":CreatorJobName(InstallationId,JobId);
    internal static string CreatorJobName(string installationId,string jobId)=>@"Global\CPCSessionJob."+Identifiers.Hex32(installationId)+"."+Identifiers.Hex32(jobId);
    internal CreationTag Tag=>CreationTag.For(CreationRole.OwnedJob,JobId);
    internal static OwnedJobIntent ForNewJob(string installationId,string release,string manifest,string? creatorServiceSid)
    {
        if(creatorServiceSid is not null)AssertCreatorSid(creatorServiceSid);
        return new(creatorServiceSid is null?2:3,installationId,Guid.NewGuid().ToString("N"),release,manifest,AtomicBinding,
            creatorServiceSid is null?PrivateScope:CreatorScope,creatorServiceSid);
    }
    internal static OwnedJobIntent Read(ProtectedState state,string id)
    {
        state.AssertHeld();id=Identifiers.Hex32(id);using var doc=JsonDocument.Parse(state.Read(Leaf(id),8192).Bytes,new JsonDocumentOptions{MaxDepth=4});
        return Parse(doc.RootElement,state.InstallationId,id);
    }
    internal static OwnedJobIntent Parse(JsonElement r,string installationId,string id)
    {
        var schema=r.GetProperty("SchemaVersion").GetInt32();
        string[] fields=["SchemaVersion","InstallationId","JobId","Release","ManifestSHA256","Binding","Scope"];
        if(schema is not (2 or 3))throw new InvalidDataException("Unsupported job intent schema");
        StrictJson.Fields(r,schema==3?[..fields,"CreatorServiceSid"]:fields);
        var scope=schema==3?CreatorScope:PrivateScope;
        if(StrictJson.Text(r,"InstallationId")!=installationId || StrictJson.Text(r,"JobId")!=id ||
            StrictJson.Text(r,"Binding")!=AtomicBinding || StrictJson.Text(r,"Scope")!=scope)throw new InvalidDataException("Foreign job intent or unsupported binding");
        var creator=schema==3?StrictJson.Text(r,"CreatorServiceSid"):null;
        if(creator is not null)AssertCreatorSid(creator);
        return new(schema,installationId,id,Identifiers.Hex32(StrictJson.Text(r,"Release")),Identifiers.Hash(StrictJson.Text(r,"ManifestSHA256")),AtomicBinding,scope,creator);
    }
    internal static void AssertCreatorSid(string sid)
    {
        // Service-specific SID only. Reject the shared LocalService and the
        // all-services group, as well as our own synthetic creation tag space.
        var segments=sid.Split('-');
        if(!sid.StartsWith("S-1-5-80-",StringComparison.Ordinal) || segments.Length!=9 ||
            !segments.Skip(4).All(s=>uint.TryParse(s,System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out var value) &&
                s==value.ToString(System.Globalization.CultureInfo.InvariantCulture)) || CreationTag.TryParse(sid) is not null)
            throw new InvalidDataException("Exact creator service SID required");
    }
    internal static IReadOnlyList<OwnedJobIntent> ReadAll(ProtectedState state)
    {
        var leaves=state.ListLeaves("job-intent-");if(leaves.Length>1024)throw new InvalidDataException("Job inventory capacity exceeded; no subset adopted");
        var result=new List<OwnedJobIntent>();
        foreach(var leaf in leaves)
        {
            if(leaf.Length!=48)throw new InvalidDataException("Unexpected job intent name");
            var id=Identifiers.Hex32(leaf.Substring(11,32));if(leaf!=Leaf(id))throw new InvalidDataException("Job intent name differs");
            result.Add(Read(state,id));
        }
        return result.AsReadOnly();
    }
}

internal sealed class SafeJobHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeJobHandle():base(true){}
    internal SafeJobHandle DuplicateAssignment()
    {
        // The creation attribute needs assignment. Query, terminate and
        // policy changes stay on the original Job owner's handle.
        var current=new IntPtr(-1);
        if(DuplicateHandle(current,this,current,out var assignment,0x0001,false,0))return assignment;
        var error=new Win32Exception(Marshal.GetLastWin32Error());
        assignment?.Dispose();error.Data["Stage"]="DuplicateJobAssignmentOnly";throw error;
    }
    protected override bool ReleaseHandle()=>CloseHandle(handle);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(IntPtr sourceProcess,SafeJobHandle source,IntPtr targetProcess,out SafeJobHandle target,
        uint access,[MarshalAs(UnmanagedType.Bool)]bool inherit,uint options);
}

internal sealed record JobSnapshot(string JobId,uint LimitFlags,uint ActiveBefore,uint ActiveAfter,uint[] ProcessIds,string AtUtc)
{
    internal bool ExpectedLimits=>LimitFlags==OwnedKernelJob.RequiredLimits;
    internal bool ObservedZero=>ActiveBefore==0 && ActiveAfter==0 && ProcessIds.Length==0;
}

internal sealed record UnadmittedJobRetirement(int SchemaVersion,string IntentSHA256,string Status,uint TotalProcesses,JobSnapshot Snapshot)
{
    internal const string Disposition="NEVER_ADMITTED_ORIGINAL_JOB_ZERO_OBSERVED";
    internal static string Leaf(string id)=>"job-unadmitted-retired-"+Identifiers.Hex32(id)+".json";

    internal static void AssertNoAdmissionEvidence(ProtectedState state,OwnedJobIntent intent)
    {
        if(state.ReadOptional("job-admission-"+intent.JobId+".json") is not null ||
            state.ReadOptional("job-completed-"+intent.JobId+".json") is not null)
            throw WfpNative.Contract("UnadmittedJobConflictingAdmissionEvidence");
    }

    internal static bool Read(ProtectedState state,OwnedJobIntent intent)
    {
        state.AssertHeld();
        var raw=state.ReadOptional(Leaf(intent.JobId));
        if(raw is null)return false;
        if(OwnedJobIntent.Read(state,intent.JobId)!=intent)throw WfpNative.Contract("UnadmittedJobIntentMismatch");
        AssertNoAdmissionEvidence(state,intent);
        Parse(raw.Bytes,intent,state.Read(OwnedJobIntent.Leaf(intent.JobId),8192).SHA256);
        return true;
    }

    internal static void Parse(byte[] bytes,OwnedJobIntent intent,string intentHash)
    {
        using var doc=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=5});
        var record=doc.RootElement;
        StrictJson.Fields(record,"SchemaVersion","IntentSHA256","Status","TotalProcesses","Snapshot");
        StrictJson.Fields(record.GetProperty("Snapshot"),"JobId","LimitFlags","ActiveBefore","ActiveAfter","ProcessIds","AtUtc");
        var result=record.Deserialize<UnadmittedJobRetirement>();
        if(intent.SchemaVersion!=2 || intent.CreatorServiceSid is not null || result is null || result.SchemaVersion!=1 ||
            result.IntentSHA256!=intentHash || result.Status!=Disposition || result.TotalProcesses!=0 ||
            result.Snapshot is not {ProcessIds:not null} snapshot ||
            snapshot.JobId!=intent.JobId || !snapshot.ExpectedLimits || !snapshot.ObservedZero)
            throw WfpNative.Contract("UnadmittedJobRetirementProofMismatch");
    }
}
