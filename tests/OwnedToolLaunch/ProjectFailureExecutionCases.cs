using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

internal static class ProjectFailureExecutionCases
{
    internal static void Run(Assembly library,string mode)
    {
        const BindingFlags flags=BindingFlags.NonPublic|BindingFlags.Static;
        object? Call(Type type,string method,params object?[] values)
        {
            try{return type.GetMethod(method,flags)!.Invoke(null,values);}
            catch(TargetInvocationException error)when(error.InnerException is not null){ExceptionDispatchInfo.Capture(error.InnerException).Throw();throw;}
        }
        if(mode=="caller-failure-owner")
        {
            var contract=library.GetType("ProtectionLifecycle.WfpNative",true)!;
            var error=(Exception)Call(contract,"Contract","ProjectDevelopmentNotConfirmed")!;
            var childType=library.GetType("ProtectionLifecycle.ResourceChildReport",true)!;
            var child=JsonSerializer.SerializeToElement(new {SchemaVersion=1,Pid=1,Nonce=new string('a',32),WorkspaceWriteReadMatched=true,
                ToolExit=125,Cases=Array.Empty<object>(),FailureType=error.GetType().Name,FailureCode=error.HResult,
                FailureStage="WAIT_PROJECT_COMPILER/"+error.Data["Stage"],ToolDiagnostic=(string?)null,Git=(object?)null,
                CreationEvidence=(object?)null,OwnedCompilationObserved=false,
                ProjectFailure=new {Stage="Compile",Diagnostics=new[]{new {Code="CS0103",SourceIndex=0,Line=9,Column=52}}}});
            var observed=JsonSerializer.Deserialize(child.GetRawText(),childType)!;
            var report=JsonSerializer.SerializeToElement(new {Child=observed});var value=report.GetProperty("Child");
            var owner=library.GetType("ProtectionLifecycle.InstalledBroker",true)!;
            if(Call(owner,"ProjectFailureStageMatches",value.GetProperty("FailureStage").GetString()) is not true ||
                value.GetProperty("ToolExit").GetInt32()!=125 || value.GetProperty("ProjectFailure").GetProperty("Stage").GetString()!="Compile")
                throw new InvalidDataException("Original child contract stage/serialization did not reach owner");
            foreach(var wrong in new string?[]{null,"WAIT_PROJECT_COMPILER","WAIT_PROJECT_COMPILER/Other","WAIT_PROJECT_COMPILER/ProjectDevelopmentNotConfirmed/Other","START_PROJECT_COMPILER/ProjectDevelopmentNotConfirmed"})
                if(Call(owner,"ProjectFailureStageMatches",wrong) is not false)throw new InvalidDataException("Unrelated failure stage accepted");
            var stopType=library.GetType("ProtectionLifecycle.RuntimeStop",true)!;
            var confirms=stopType.GetMethod("ConfirmsClosedResources",BindingFlags.Instance|BindingFlags.NonPublic)!;
            var sessionId=new string('a',32);var jobId=new string('b',32);
            var stop=JsonSerializer.SerializeToNode(new {SessionId=sessionId,Reason="OFFLINE_RESOURCE_QUALIFICATION_TERMINAL",
                AdmissionClosed=true,QuarantineObservedBeforeStop=true,QuarantineAtMs=10,JobStopAtMs=11,
                FinalJob=new{JobId=jobId,LimitFlags=8192,ActiveBefore=0,ActiveAfter=0,ProcessIds=Array.Empty<int>(),AtUtc="synthetic"},
                Failures=Array.Empty<object>()})!.AsObject();
            bool Closed(JsonObject value)=>confirms.Invoke(JsonSerializer.Deserialize(value.ToJsonString(),stopType),new object[]{sessionId,jobId}) is true;
            if(!Closed(stop))throw new InvalidDataException("Exact closed resource fixture refused");
            foreach(var mutate in new Action<JsonObject>[] {j=>j["SessionId"]=jobId,j=>j["Reason"]="SESSION_FAILURE",j=>j["AdmissionClosed"]=false,
                j=>j["QuarantineObservedBeforeStop"]=false,j=>j["JobStopAtMs"]=9,j=>j["FinalJob"]!["JobId"]=sessionId,
                j=>j["FinalJob"]!["ActiveAfter"]=1,j=>j["FinalJob"]!["LimitFlags"]=0,j=>j["FinalJob"]=null})
            {
                var invalid=stop.DeepClone().AsObject();mutate(invalid);
                if(Closed(invalid))throw new InvalidDataException("Incomplete or foreign stop allowed workspace output reads");
            }
            var matches=stopType.GetMethod("MatchesResourceExport",BindingFlags.Instance|BindingFlags.NonPublic)!;
            var snapshotType=library.GetType("ProtectionLifecycle.JobSnapshot",true)!;
            object Decode(JsonNode value,Type type)=>JsonSerializer.Deserialize(value.ToJsonString(),type)!;
            var persisted=Decode(stop,stopType);var zero=Decode(stop["FinalJob"]!,snapshotType);
            bool ExportMatches(object report,object terminal,object completion)=>matches.Invoke(persisted,new[]{report,terminal,completion,sessionId,jobId}) is true;
            if(!ExportMatches(persisted,zero,zero))throw new InvalidDataException("Matching workspace export records refused");
            var later=stop.DeepClone().AsObject();later["FinalJob"]!["AtUtc"]="other observation";
            var foreignZero=Decode(later["FinalJob"]!,snapshotType);
            if(ExportMatches(Decode(later,stopType),zero,zero) || ExportMatches(persisted,foreignZero,zero) || ExportMatches(persisted,zero,foreignZero))
                throw new InvalidDataException("Unrelated zero observation allowed workspace export");
            later=stop.DeepClone().AsObject();later["QuarantineAtMs"]=9;
            if(ExportMatches(Decode(later,stopType),zero,zero))throw new InvalidDataException("Different stop sequence allowed workspace export");
            var confirmsGpu=stopType.GetMethod("ConfirmsClosedGpu",BindingFlags.Instance|BindingFlags.NonPublic)!;
            bool ClosedGpu(JsonObject value)=>confirmsGpu.Invoke(Decode(value,stopType),new object[]{sessionId,jobId}) is true;
            var gpuStop=stop.DeepClone().AsObject();gpuStop["Reason"]="FIXED_GPU_QUALIFICATION_TERMINAL";
            if(!ClosedGpu(gpuStop) || ClosedGpu(stop) || Closed(gpuStop))throw new InvalidDataException("GPU and workspace stop scopes mixed");
            gpuStop["QuarantineObservedBeforeStop"]=false;
            if(ClosedGpu(gpuStop))throw new InvalidDataException("GPU stop accepted without prior quarantine");
            Console.WriteLine("PASS owner failure stage, closed resources, workspace re-export and fixed GPU stop scope checks; pure fixture, no LPAC/UAC/private state");return;
        }
        var names=new[]{"cpc-project.json","src/Entry.cs","tests/Checks.cs","data/values.json","README.md"};
        var selected=names.Select(name=>
        {
            using var resource=Assembly.GetExecutingAssembly().GetManifestResourceStream("DataFixture."+name)??throw new InvalidDataException("Missing failure fixture");
            using var bytes=new MemoryStream();resource.CopyTo(bytes);return(Name:name,Bytes:bytes.ToArray());
        }).ToArray();
        var manifest=JsonNode.Parse(selected.Single(f=>f.Name=="cpc-project.json").Bytes)!.AsObject();
        var phase=mode switch {"caller-compile-failure"=>"Compile","caller-run-failure"=>"Run","caller-output-failure"=>"Output",_=>"Tests"};
        if(phase=="Compile")manifest["Edits"]![0]!["After"]="return MissingValue;";
        else if(phase=="Run")manifest["Edits"]![0]!["After"]="throw new System.InvalidOperationException(\"OWN_PRIVATE_EXCEPTION_MESSAGE\");";
        else if(phase=="Output")manifest["Edits"]!.AsArray().Add(new JsonObject{["Path"]="src/Entry.cs",["Before"]="return 0;",
            ["After"]="try { System.Console.Error.Write(new string('x', 4097)); } catch (IOException) { } return 0;"});
        else manifest["Edits"]!.AsArray().Add(new JsonObject{["Path"]="tests/Checks.cs",["Before"]="return 3;",["After"]="throw new Exception(\"OWN_PRIVATE_EXCEPTION_MESSAGE\");"});
        var files=selected.Select(f=>(f.Name,f.Name=="cpc-project.json"?JsonSerializer.SerializeToUtf8Bytes(manifest):
            f.Name=="src/Entry.cs" && phase=="Compile"?Encoding.UTF8.GetBytes("#line 9000 \"X:/OWN_PRIVATE_PATH.cs\"\n"+Encoding.UTF8.GetString(f.Bytes)):f.Bytes)).ToArray();
        var bundleType=library.GetType("ClaudeCodeProtection.Workspaces.WorkspaceBundle",true)!;
        var bundle=Call(bundleType,"Create",files,null)!;
        var baseline=(byte[])bundleType.GetMethod("Serialize",BindingFlags.NonPublic|BindingFlags.Instance)!.Invoke(bundle,null)!;
        var root=Path.Combine(AppContext.BaseDirectory,"own-failure-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        Call(library.GetType("ClaudeCodeProtection.Workspaces.WorkspaceFiles",true)!,"MaterializeNew",root,"project",baseline);
        var cwd=Environment.CurrentDirectory;var stdout=Console.Out;var stderr=Console.Error;object? failure=null;
        try{Call(library.GetType("ProtectionLifecycle.CallerCSharpProject",true)!,"BuildAndRun",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"ClaudeCodeProtection-PowerShell-7.4.22"),Path.Combine(root,"project"),baseline);}
        catch(Exception error)when(error.GetType().FullName=="ClaudeCodeProtection.Workspaces.ProjectTaskException")
        {failure=error.GetType().GetProperty("Failure",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(error);}
        if(failure is null || Environment.CurrentDirectory!=cwd || !ReferenceEquals(stdout,Console.Out) || !ReferenceEquals(stderr,Console.Error))
            throw new InvalidDataException("Expected bounded project failure and restored caller context");
        var encoded=JsonSerializer.Serialize(failure,failure.GetType());using var json=JsonDocument.Parse(encoded);var r=json.RootElement;
        if(r.GetProperty("Stage").GetString()!=phase || encoded.Contains("OWN_PRIVATE",StringComparison.Ordinal) || encoded.Contains("X:/",StringComparison.Ordinal))
            throw new InvalidDataException("Raw exception or mapped source path escaped");
        if(phase=="Compile")
        {
            var errors=r.GetProperty("Diagnostics").EnumerateArray().ToArray();
            if(!errors.Any(e=>e.GetProperty("Code").GetString()=="CS0103" && e.GetProperty("SourceIndex").GetInt32()==0 && e.GetProperty("Line").GetInt32() is >0 and <200))
                throw new InvalidDataException("Compiler diagnostics need actual source index and physical line");
        }
        else if(r.GetProperty("Diagnostics").GetArrayLength()!=0)throw new InvalidDataException("Execution failure contains compiler data");
        if(File.Exists(Path.Combine(root,"project","cpc-output","run-result.json")))throw new InvalidDataException("Failure wrote a successful run receipt");
        Console.WriteLine("PASS actual own ordinary "+phase+" failure: bounded structured stage/code/source-index/physical-location, no mapped path or private message, restored CWD/console, no success receipt; no LPAC/Job/UAC/host probe; fixture="+root);
    }
}
