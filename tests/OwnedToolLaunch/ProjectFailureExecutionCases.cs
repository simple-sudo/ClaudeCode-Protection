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
        var names=new[]{"cpc-project.json","src/Entry.cs","tests/Checks.cs","data/values.json","README.md"};
        var selected=names.Select(name=>
        {
            using var resource=Assembly.GetExecutingAssembly().GetManifestResourceStream("DataFixture."+name)??throw new InvalidDataException("Missing failure fixture");
            using var bytes=new MemoryStream();resource.CopyTo(bytes);return(Name:name,Bytes:bytes.ToArray());
        }).ToArray();
        var manifest=JsonNode.Parse(selected.Single(f=>f.Name=="cpc-project.json").Bytes)!.AsObject();
        var phase=mode switch {"caller-compile-failure"=>"Compile","caller-run-failure"=>"Run",_=>"Tests"};
        if(phase=="Compile")manifest["Edits"]![0]!["After"]="return MissingValue;";
        else if(phase=="Run")manifest["Edits"]![0]!["After"]="throw new System.InvalidOperationException(\"OWN_PRIVATE_EXCEPTION_MESSAGE\");";
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
