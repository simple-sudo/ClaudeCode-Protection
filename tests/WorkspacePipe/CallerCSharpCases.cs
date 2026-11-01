using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ClaudeCodeProtection.Workspaces;

internal static class CallerCSharpCases
{
    internal static void Run()
    {
        var checks=0;
        void Require(bool value,string reason){if(!value)throw new Exception(reason);checks++;}
        void Refuse(Action action,string reason)
        {try{action();}catch(Exception e)when(e is InvalidDataException or JsonException or BadImageFormatException or InvalidOperationException or DecoderFallbackException){checks++;return;}throw new Exception("Accepted "+reason);}
        var files=new[]{"cpc-project.json","src/Counter.cs","src/Entry.cs","tests/Checks.cs","README.md"}.Select(name=>
        {
            using var stream=Assembly.GetExecutingAssembly().GetManifestResourceStream("CallerFixture."+name)??throw new InvalidDataException();
            using var bytes=new MemoryStream();stream.CopyTo(bytes);return(name,Content:bytes.ToArray());
        }).ToArray();
        var baseline=WorkspaceBundle.Create(files).Serialize();var task=CSharpProjectTask.Parse(baseline);
        Require(task.Definition.Sources.Length==3 && task.Definition.ExpectedTests==3,"caller manifest selected independently of fixed sample");
        Require(Encoding.UTF8.GetString(task.ModifiedFiles().Single(f=>f.Path=="src/Counter.cs").Content).Contains("RemoveEmptyEntries"),"declared edit produces expected source");
        byte[] Change(Action<JsonObject> mutate)
        {
            var manifest=JsonNode.Parse(files.Single(f=>f.name==CSharpProjectTask.Manifest).Content)!.AsObject();mutate(manifest);
            return WorkspaceBundle.Create(files.Select(f=>(f.name,f.name==CSharpProjectTask.Manifest?JsonSerializer.SerializeToUtf8Bytes(manifest):f.Content))).Serialize();
        }
        foreach(var mutation in new Action<JsonObject>[] {
            j=>j["Command"]="unreviewed",j=>j["SchemaVersion"]=2,j=>j["Kind"]="DATA",j=>j["ExpectedTests"]=0,j=>j["ExpectedTests"]=257,
            j=>j["EntryType"]="C:\\private",j=>j["TestType"]=j["EntryType"]!.GetValue<string>(),j=>j["Edits"]=new JsonArray(),
            j=>j["Sources"]=new JsonArray(),j=>j["Sources"]=new JsonArray("src/Counter.cs","src/Counter.cs"),
            j=>j["Sources"]=new JsonArray("../escape.cs"),j=>j["Sources"]=new JsonArray("missing.cs"),
            j=>j["Edits"]![0]!["Path"]="README.md",j=>j["Edits"]![0]!["Before"]="NOT_PRESENT",
            j=>j["Edits"]![0]!["Before"]="e",j=>j["Edits"]![0]!["Before"]="",j=>j["Edits"]![0]!["Extra"]="value"
        })Refuse(()=>CSharpProjectTask.Parse(Change(mutation)),"invalid explicit source/edit/entry/test declaration");
        Refuse(()=>CSharpProjectTask.Parse(WorkspaceBundle.Create(files.Where(f=>f.name!=CSharpProjectTask.Manifest)).Serialize()),"missing task manifest");
        Refuse(()=>CSharpProjectTask.Parse(WorkspaceBundle.Create(files.Append(("cpc-output/already.txt","occupied"u8.ToArray()))).Serialize()),"preoccupied output namespace");
        var duplicate=files.Select(f=>(f.name,f.name==CSharpProjectTask.Manifest?Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(f.Content).Replace("\"SchemaVersion\": 1","\"SchemaVersion\": 1,\"SchemaVersion\": 1",StringComparison.Ordinal)):f.Content));
        Refuse(()=>CSharpProjectTask.Parse(WorkspaceBundle.Create(duplicate).Serialize()),"duplicate manifest fields");
        // A self-assembly is synthetic metadata-only output for result guards;
        // it is never loaded/invoked or claimed as a compiled caller project.
        var artifact=File.ReadAllBytes(Assembly.GetExecutingAssembly().Location);
        var output=new[]{("cpc-output/CpcProject.dll",artifact),("cpc-output/run-result.json","{\"SchemaVersion\":1,\"ExitCode\":0,\"TestsPassed\":3}"u8.ToArray()),
            ("cpc-output/test-result.txt","3"u8.ToArray()),("cpc-output/stdout.txt","words=3"u8.ToArray()),("cpc-output/stderr.txt",Array.Empty<byte>())};
        var resultFiles=task.ModifiedFiles().Select(f=>(f.Path,f.Content)).Concat(output).ToArray();
        var result=WorkspaceBundle.Create(resultFiles,task.BaselineSHA256).Serialize();task.VerifyResult(result);checks++;
        Refuse(()=>task.VerifyResult(WorkspaceBundle.Create(resultFiles,new string('A',64)).Serialize()),"wrong result baseline");
        Refuse(()=>task.VerifyResult(WorkspaceBundle.Create(resultFiles.Skip(1),task.BaselineSHA256).Serialize()),"missing result file");
        Refuse(()=>task.VerifyResult(WorkspaceBundle.Create(resultFiles.Select(f=>(f.Item1,f.Item1=="README.md"?"changed"u8.ToArray():f.Item2)),task.BaselineSHA256).Serialize()),"undeclared data mutation");
        Refuse(()=>task.VerifyResult(WorkspaceBundle.Create(resultFiles.Select(f=>(f.Item1,f.Item1=="cpc-output/test-result.txt"?"6"u8.ToArray():f.Item2)),task.BaselineSHA256).Serialize()),"wrong test count");
        Refuse(()=>task.VerifyResult(WorkspaceBundle.Create(resultFiles.Select(f=>(f.Item1,f.Item1=="cpc-output/CpcProject.dll"?new byte[512]:f.Item2)),task.BaselineSHA256).Serialize()),"non-managed artifact");
        var session=new string('a',32);HostPrivacyCase[] Cases()=>HostPrivacyContract.Roles.Select((r,i)=>new HostPrivacyCase(r,HostPrivacyContract.Kind(i),"ACCESS_DENIED",5)).ToArray();
        var privacy=new HostPrivacySummary(HostPrivacyContract.PolicySHA256,new string('F',64),session,111,222,Cases(),Cases());
        Dictionary<string,object?> Success()=>new(){["SchemaVersion"]=6,["Scope"]=WorkspacePipe.CallerProjectScope,["OwnerSealedBeforeCode"]=true,["HostPrivacy"]=privacy,
            ["ExitCode"]=0,["SessionId"]=session,["BaseSHA256"]=task.BaselineSHA256,["ResultSHA256"]=WorkspaceBundle.Hash(result),["Status"]="CALLER_CSHARP_PROJECT_BUILT_AND_CLEANED",
            ["FailureStage"]=null,["FailureKind"]=null,["FailureCode"]=null,["CreationEvidence"]=null,["StopEvidence"]=null};
        byte[] Bytes(Dictionary<string,object?> value)=>JsonSerializer.SerializeToUtf8Bytes(value);
        Require(WorkspacePipe.ParseReply(Bytes(Success()),task.BaselineSHA256,true,true).OwnerSealedBeforeCode,"caller v6 success requires owner sealing");
        Refuse(()=>WorkspacePipe.ParseReply(Bytes(Success()),task.BaselineSHA256),"caller execution as v3 DATA");
        Refuse(()=>WorkspacePipe.ParseReply(Bytes(Success()),task.BaselineSHA256,true),"caller execution as v5 sample");
        Refuse(()=>WorkspacePipe.ParseReply(Bytes(Success()),task.BaselineSHA256,false,true),"caller flag without explicit code scope");
        foreach(var mutation in new Action<Dictionary<string,object?>>[]{v=>v["OwnerSealedBeforeCode"]=false,v=>v.Remove("OwnerSealedBeforeCode"),
            v=>v["OwnerSealedBeforeCode"]=1,v=>v["SchemaVersion"]=5,v=>v["Scope"]=WorkspacePipe.ProjectScope,v=>v["HostPrivacy"]=null,
            v=>v["BaseSHA256"]=new string('A',64),v=>v["Status"]="BUNDLED_PROJECT_DEVELOPED_AND_CLEANED"})
        {var value=Success();mutation(value);Refuse(()=>WorkspacePipe.ParseReply(Bytes(value),task.BaselineSHA256,true,true),"caller reply cannot weaken binding or sealing");}
        Console.WriteLine($"PASS {checks} caller CSharp manifest/edit/result/v6 checks; synthetic output metadata and privacy records only, no product/Job/UAC/host probes or caller-code execution");
    }
}
