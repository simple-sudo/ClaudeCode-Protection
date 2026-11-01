using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

internal sealed record ToolLaunchRequest(int SchemaVersion,string Scope,string Nonce,int RootPid,int Sequence,string Kind,string[] Arguments,string StartSHA256);
internal sealed record ToolLaunchReply(int SchemaVersion,string Nonce,int RootPid,int Sequence,long Process,long Input,long Output,long Error,int? FailureCode,string? FailureStage);

// A continuation of the ORIGINAL anonymous report pipe, not a service or an
// elevated shell. Only that created worker owns its write end; descendant
// stdio handle lists do not inherit it. Replies transfer only pipe endpoints
// and SYNCHRONIZE/QUERY_LIMITED_INFORMATION on the confined tool process.
internal sealed class OwnedToolLaunch
{
    private readonly ConcurrentQueue<ToolLaunchRequest> requests=new();
    private int next=1;
    private static int workerSequence;
    internal async Task<string> ReadMessages(StreamReader reader)
    {
        for(var count=0;count<=64;count++)
        {
            var line=new StringBuilder();var one=new char[1];
            while(true)
            {
                if(await reader.ReadAsync(one.AsMemory())==0)throw WfpNative.Contract("OwnedToolPipeClosedWithoutTerminalReport");
                if(one[0]=='\n')break;
                if(line.Length>=16384)throw WfpNative.Contract("OwnedToolMessageBounds");line.Append(one[0]);
            }
            var text=line.ToString().TrimEnd('\r');
            using var doc=JsonDocument.Parse(text,new JsonDocumentOptions{MaxDepth=5});
            if(!doc.RootElement.TryGetProperty("Scope",out var scope) || scope.GetString()!="OWNED_TOOL_START_REQUEST")return text;
            StrictJson.Fields(doc.RootElement,"SchemaVersion","Scope","Nonce","RootPid","Sequence","Kind","Arguments","StartSHA256");
            var request=JsonSerializer.Deserialize<ToolLaunchRequest>(text)??throw WfpNative.Contract("OwnedToolRequestMissing");
            if(requests.Count!=0)throw WfpNative.Contract("OnlyOneOwnedToolRequestAtATime");requests.Enqueue(request);
        }
        throw WfpNative.Contract("OwnedToolRequestCountExceeded");
    }
    internal void ProcessPending(SessionResources resources,AtomicChild root,OwnedKernelJob job,ProtectedSession.ResourceQualification permit)
    {
        if(!requests.TryDequeue(out var request))return;
        if(request.SchemaVersion!=1 || request.Scope!="OWNED_TOOL_START_REQUEST" || request.Nonce!=resources.Plan.Nonce ||
            request.RootPid!=root.Pid || request.Sequence!=next || next>64)throw WfpNative.Contract("OwnedToolRequestBindingRefused");
        var start=ValidateStart(resources.Plan,resources.Workspace,request.Kind,request.Arguments,request.StartSHA256);next++;
        resources.AssertHeld();permit.AuthorizeToolCreation(root,job);resources.BeforeOwnedToolCreation(request.Kind);
        ToolLaunchReply reply;
        try
        {
            using var tool=root.StartOwnedTool(job,permit,start);
            reply=root.TransferToolHandles(tool,request.Sequence,resources.Plan.Nonce);
        }
        catch(System.ComponentModel.Win32Exception error)
        {
            var stage=error.Data["Stage"] as string;
            if(stage is null || stage.Length>80 || stage.Any(c=>!char.IsAsciiLetterOrDigit(c)))stage="OwnedToolNativeSetup";
            reply=new(1,resources.Plan.Nonce,checked((int)root.Pid),request.Sequence,0,0,0,0,error.NativeErrorCode,stage);
        }
        var path=ReplyPath(resources.Workspace,request.Sequence);
        var bytes=JsonSerializer.SerializeToUtf8Bytes(reply);
        using(var output=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None)){output.Write(bytes);output.Flush(true);}
        using var signal=new FileStream(path+".signal",FileMode.CreateNew,FileAccess.Write,FileShare.None);signal.Flush(true);
    }
    internal static ProcessStartInfo ValidateStart(ResourceProbePlan plan,string workspace,string kind,string[] arguments,string digest)
    {
        plan.Validate();_=Identifiers.Hash(digest);
        if(arguments is null || arguments.Length>64 || arguments.Any(a=>a is null || a.Length>8192 || a.Contains('\0')))
            throw WfpNative.Contract("OwnedToolArgumentsRefused");
        ProcessStartInfo start;
        if(kind=="powershell")
        {
            start=SessionResources.PowerShellStart(plan,workspace);
            if(!start.ArgumentList.SequenceEqual(arguments))throw WfpNative.Contract("OwnedPowerShellCompiledProgramRequired");
        }
        else if(kind=="project")
        {
            start=BundledProjectDevelopment.Start(plan,workspace);
            if(!start.ArgumentList.SequenceEqual(arguments))throw WfpNative.Contract("OwnedProjectCompiledProgramRequired");
        }
        else if(kind=="git" && plan.GitAssetSetSHA256==SessionGitToolchain.AssetSetSHA256)
        {
            var prefix=SessionGitToolchain.Start(workspace,plan.GitDirectory).ArgumentList.ToArray();
            if(arguments.Length<prefix.Length || !arguments.Take(prefix.Length).SequenceEqual(prefix))throw WfpNative.Contract("OwnedGitConfigurationRequired");
            var tail=arguments.Skip(prefix.Length).ToArray();var repo=WindowsPathSeal.Child(workspace,"git-project");
            var allowed=new[]{new[]{"hash-object","--stdin"},
                new[]{"init","--quiet","--initial-branch=qualification","--template="+WindowsPathSeal.Child(workspace,"empty-git-template"),repo},
                new[]{"--literal-pathspecs","-C",repo,"add","--force","--pathspec-from-file="+WindowsPathSeal.Child(workspace,"git-selected-paths.bin"),"--pathspec-file-nul"},
                new[]{"-C",repo,"commit","--quiet","--no-gpg-sign","-m","Controlled offline qualification"},
                new[]{"-C",repo,"rev-parse","--verify","HEAD"},new[]{"hash-object","--",plan.Fixture},
                new[]{"hash-object","--",WindowsPathSeal.Child(workspace,"all-packages-only.json")}};
            if(!allowed.Any(a=>a.SequenceEqual(tail)))throw WfpNative.Contract("OwnedGitCompiledOperationRequired");
            start=SessionGitToolchain.Start(workspace,plan.GitDirectory,tail);
        }
        else throw WfpNative.Contract("OwnedToolKindRefused");
        if(StartHash(start)!=digest)throw WfpNative.Contract("OwnedToolEnvironmentOrStartMismatch");return start;
    }
    internal static string StartHash(ProcessStartInfo start)=>Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {
        start.FileName,start.WorkingDirectory,Arguments=start.ArgumentList.ToArray(),Environment=start.Environment.OrderBy(e=>e.Key,StringComparer.OrdinalIgnoreCase).ToArray()})));
    private static string ReplyPath(string workspace,int sequence)
    {if(sequence is <1 or >64)throw WfpNative.Contract("OwnedToolSequenceBounds");return WindowsPathSeal.Child(workspace,"tool-launch-"+sequence.ToString("D2",System.Globalization.CultureInfo.InvariantCulture)+".json");}
    internal static AtomicChild.InheritedTool Request(ProcessStartInfo start,string packageSid,ToolCreationEvidence evidence)
    {
        var raw=Environment.GetEnvironmentVariable("CPC_RESOURCE_PLAN")??throw WfpNative.Contract("OwnedToolResourcePlanRequired");
        var plan=ResourceProbePlan.Parse(raw);
        var workspace=plan.Workspace(packageSid);
        if(start.WorkingDirectory!=workspace)throw WfpNative.Contract("OwnedToolWorkspaceRefused");
        var kind=start.FileName==plan.PowerShellLaunchImage?(start.ArgumentList.FirstOrDefault()=="resource-project"?"project":"powershell"):start.FileName==WindowsPathSeal.Child(plan.GitDirectory,"git.exe")?"git":throw WfpNative.Contract("OwnedToolFixedImageRequired");
        var sequence=Interlocked.Increment(ref workerSequence);var path=ReplyPath(workspace,sequence);
        var request=new ToolLaunchRequest(1,"OWNED_TOOL_START_REQUEST",plan.Nonce,Environment.ProcessId,sequence,kind,start.ArgumentList.ToArray(),StartHash(start));
        // Validate locally too, but only the trusted owner grants creation.
        _=ValidateStart(plan,workspace,kind,request.Arguments,request.StartSHA256);
        Console.WriteLine(JsonSerializer.Serialize(request));Console.Out.Flush();
        var clock=Stopwatch.StartNew();
        while(!File.Exists(path+".signal")){if(clock.ElapsedMilliseconds>=8000)throw WfpNative.Contract("OwnedToolReplyDeadline");Thread.Sleep(20);}
        using var input=File.OpenRead(path);if(input.Length is <1 or >4096)throw WfpNative.Contract("OwnedToolReplyBounds");
        var bytes=new byte[checked((int)input.Length)];input.ReadExactly(bytes);
        using var doc=JsonDocument.Parse(bytes);StrictJson.Fields(doc.RootElement,"SchemaVersion","Nonce","RootPid","Sequence","Process","Input","Output","Error","FailureCode","FailureStage");
        var reply=JsonSerializer.Deserialize<ToolLaunchReply>(bytes)??throw WfpNative.Contract("OwnedToolReplyMissing");
        if(reply.SchemaVersion!=1 || reply.Nonce!=plan.Nonce || reply.RootPid!=Environment.ProcessId || reply.Sequence!=sequence)throw WfpNative.Contract("OwnedToolReplyBindingRefused");
        if(reply.FailureCode is int code)
        {
            if(reply.FailureStage is null || reply.FailureStage.Length is <1 or >80 || reply.FailureStage.Any(c=>!char.IsAsciiLetterOrDigit(c)))throw WfpNative.Contract("OwnedToolFailureMetadataRefused");
            var error=new System.ComponentModel.Win32Exception(code);error.Data["Stage"]=reply.FailureStage;throw error;
        }
        if(reply.FailureStage is not null)throw WfpNative.Contract("OwnedToolUnexpectedFailureMetadata");
        if(new[]{reply.Process,reply.Input,reply.Output,reply.Error}.Any(h=>h<=0 || h>=long.MaxValue) ||
            new[]{reply.Process,reply.Input,reply.Output,reply.Error}.Distinct().Count()!=4)throw WfpNative.Contract("OwnedToolTransferredHandleShapeRefused");
        return new(new SafeProcessHandle((IntPtr)reply.Process,true),new SafeFileHandle((IntPtr)reply.Input,true),
            new SafeFileHandle((IntPtr)reply.Output,true),new SafeFileHandle((IntPtr)reply.Error,true),evidence);
    }
}
