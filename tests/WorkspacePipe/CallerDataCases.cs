using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using ClaudeCodeProtection.Workspaces;

internal static class CallerDataCases
{
    internal static void Run()
    {
        var checks=0;
        void Require(bool value,string reason){if(!value)throw new Exception(reason);checks++;}
        void Refuse(Action action,string reason)
        {try{action();}catch(Exception e)when(e is InvalidDataException or JsonException or InvalidOperationException){checks++;return;}throw new Exception("Accepted "+reason);}
        var names=new[]{"cpc-project.json","src/Entry.cs","tests/Checks.cs","data/values.json","README.md"};
        var files=names.Select(name=>
        {
            using var stream=Assembly.GetExecutingAssembly().GetManifestResourceStream("DataFixture."+name)??throw new InvalidDataException("Missing data fixture");
            using var memory=new MemoryStream();stream.CopyTo(memory);return(Path:name,Content:memory.ToArray());
        }).ToArray();
        var input=WorkspaceBundle.Create(files).Serialize();var task=CSharpProjectTask.Parse(input);
        Require(task.Definition.Kind==CSharpProjectTask.DataKind && task.GeneratedFiles.Single().MaxBytes==1024 && task.ResultPaths.Length==11,"explicit data task and result inventory");
        byte[] Change(Action<JsonObject> change)
        {
            var json=JsonNode.Parse(files.Single(f=>f.Path==CSharpProjectTask.Manifest).Content)!.AsObject();change(json);
            return WorkspaceBundle.Create(files.Select(f=>(f.Path,f.Path==CSharpProjectTask.Manifest?JsonSerializer.SerializeToUtf8Bytes(json):f.Content))).Serialize();
        }
        foreach(var mutation in new Action<JsonObject>[] {
            j=>j["SchemaVersion"]=1,j=>j["Kind"]=CSharpProjectTask.Kind,j=>j["DataFiles"]=null,j=>j.Remove("DataFiles"),
            j=>j["DataFiles"]=new JsonArray("data/values.json"),j=>j["DataFiles"]=new JsonArray("../host.txt","README.md"),
            j=>j["DataFiles"]=new JsonArray("src/Entry.cs","README.md"),j=>j["DataFiles"]=new JsonArray("missing.txt","README.md"),
            j=>j["GeneratedFiles"]=null,j=>j["GeneratedFiles"]![0]!["Path"]="cpc-output/stdout.txt",
            j=>j["GeneratedFiles"]![0]!["Path"]="../host.txt",j=>j["GeneratedFiles"]![0]!["Path"]="cpc-results/../host.txt",
            j=>j["GeneratedFiles"]![0]!["MaxBytes"]=0,j=>j["GeneratedFiles"]![0]!["MaxBytes"]=WorkspaceBundle.MaxFileBytes+1,
            j=>j["GeneratedFiles"]![0]!["Extra"]=true,
            j=>j["GeneratedFiles"]=new JsonArray(new JsonObject{["Path"]="cpc-results/a",["MaxBytes"]=1024},new JsonObject{["Path"]="cpc-results/a/b",["MaxBytes"]=1024}),
            j=>j["GeneratedFiles"]=new JsonArray(new JsonObject{["Path"]="cpc-results/a",["MaxBytes"]=1024},new JsonObject{["Path"]="cpc-results/A",["MaxBytes"]=1024})
        })Refuse(()=>CSharpProjectTask.Parse(Change(mutation)),"invalid data/result declaration");
        Refuse(()=>CSharpProjectTask.Parse(WorkspaceBundle.Create(files.Append(("unselected.txt","not selected"u8.ToArray()))).Serialize()),"ambient unselected input");
        Refuse(()=>CSharpProjectTask.Parse(WorkspaceBundle.Create(files.Append(("cpc-results/preexisting.txt","occupied"u8.ToArray()))).Serialize()),"preexisting generated namespace");
        var outputs=new[]{(CSharpProjectTask.Outputs[0],File.ReadAllBytes(Assembly.GetExecutingAssembly().Location)),
            (CSharpProjectTask.Outputs[1],"{\"SchemaVersion\":1,\"ExitCode\":0,\"TestsPassed\":3}"u8.ToArray()),
            (CSharpProjectTask.Outputs[2],"3"u8.ToArray()),(CSharpProjectTask.Outputs[3],Array.Empty<byte>()),(CSharpProjectTask.Outputs[4],Array.Empty<byte>()),
            ("cpc-results/summary.json","{\"Count\":3,\"Total\":12}"u8.ToArray())};
        var resultFiles=task.ModifiedFiles().Select(f=>(f.Path,f.Content)).Concat(outputs).ToArray();
        byte[] Result(IEnumerable<(string,byte[])> selected)=>WorkspaceBundle.Create(selected,task.BaselineSHA256).Serialize();
        task.VerifyResult(Result(resultFiles));checks++;
        Refuse(()=>task.VerifyResult(Result(resultFiles.Where(f=>f.Item1!="cpc-results/summary.json"))),"missing declared result");
        Refuse(()=>task.VerifyResult(Result(resultFiles.Append(("cpc-results/unreviewed.txt",Array.Empty<byte>())))),"undeclared result");
        Refuse(()=>task.VerifyResult(Result(resultFiles.Select(f=>(f.Item1,f.Item1=="cpc-results/summary.json"?new byte[1025]:f.Item2)))),"per-result size exceeded");
        Refuse(()=>task.VerifyResult(Result(resultFiles.Select(f=>(f.Item1,f.Item1=="data/values.json"?"changed"u8.ToArray():f.Item2)))),"input data overwritten by project");
        Require(task.ModifiedFiles().Single(f=>f.Path=="data/values.json").Content.AsSpan().SequenceEqual(files.Single(f=>f.Path=="data/values.json").Content),"data grant does not modify or compile data");
        Console.WriteLine($"PASS {checks} explicit project data/generated-result contract checks; synthetic assembly metadata only, no project execution, Broker, LPAC, UAC or network");
    }
}
