using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ClaudeCodeProtection.Workspaces;
using ProtectionCenter;

internal static class ProjectFlowCases
{
    internal static int Run(string fixture)
    {
        var checks=0;
        void Require(bool value,string reason){if(!value)throw new InvalidDataException(reason);checks++;}
        void Refuse(Action action,string reason)
        {try{action();}catch(Exception error)when(error is InvalidDataException or IOException or UnauthorizedAccessException or InvalidOperationException or JsonException || error is System.ComponentModel.Win32Exception {NativeErrorCode:183}){checks++;return;}throw new Exception("Accepted "+reason);}
        var folder=Path.Combine(fixture,"caller-source");Directory.CreateDirectory(folder);
        var definition=new CSharpProjectDefinition(1,CSharpProjectTask.Kind,new[]{"Entry.cs","Checks.cs"},new[]{new CSharpProjectEdit("Entry.cs","return -1;","return 0;")},"Demo.Entry","Demo.Checks",1);
        File.WriteAllBytes(Path.Combine(folder,CSharpProjectTask.Manifest),JsonSerializer.SerializeToUtf8Bytes(definition));
        File.WriteAllText(Path.Combine(folder,"Entry.cs"),"namespace Demo; public static class Entry {public static int Run(){return -1;}}");
        File.WriteAllText(Path.Combine(folder,"Checks.cs"),"namespace Demo; public static class Checks {public static int Run(){return 1;}}");
        File.WriteAllText(Path.Combine(folder,"unselected.txt"),"OWN_NONSECRET_UNSELECTED");
        var session=CallerProjectSession.OpenFolder(folder);
        Require(session.ReviewText.Contains("Entry.cs") && session.ReviewText.Contains("return -1;") && session.ExpectedTests==1,"GUI displays declared project edits/tests");
        var run=session.PlanRun(fixture);Require(!Directory.Exists(run.Directory),"planning does not create output");session.WriteInput(run);
        var input=WorkspaceFiles.ReadBundle(run.InputPath);var task=CSharpProjectTask.Parse(input);
        Require(task.Baseline.Files.Length==3 && !task.Baseline.Files.Any(f=>f.Path=="unselected.txt"),"folder selection reads declared sources only");
        var imported=CallerProjectSession.OpenBundle(run.InputPath);Require(imported.InputSHA256==session.InputSHA256,"bundle import preserves exact reviewed snapshot");
        using(BackendClient.HoldReviewedInput(run.InputPath,session.InputSHA256))
            Refuse(()=>{using var changed=File.OpenWrite(run.InputPath);},"input held against replacement throughout caller launch");
        Refuse(()=>BackendClient.HoldReviewedInput(run.InputPath,new string('A',64)),"changed reviewed digest refuses before launch");
        Refuse(()=>session.WriteInput(run),"existing run directory refuses adoption");
        var programFiles=Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);var root=Path.Combine(programFiles,"ClaudeCodeProtection","versions",new string('a',32));
        var image=Path.Combine(root,"bin","center","ProtectionCenter.exe");var assembly=Path.Combine(root,"bin","center","ProtectionCenter.dll");
        BackendClient.RequireInstalledProjectLocation(root,image,assembly,programFiles);checks++;
        Refuse(()=>BackendClient.RequireInstalledProjectLocation(fixture,image,assembly,programFiles),"checkout GUI cannot launch installed project");
        Refuse(()=>BackendClient.RequireInstalledProjectLocation(root,"dotnet.exe",assembly,programFiles),"dotnet developer entry cannot launch project");
        Refuse(()=>BackendClient.RequireInstalledProjectLocation(root,image,assembly+".other",programFiles),"entry assembly binding required");
        Refuse(()=>BackendClient.BuildCallerProject(run.InputPath,run.ResultPath,session.InputSHA256).GetAwaiter().GetResult(),"actual development-context backend refuses before product/UAC");
        Require(CallerProjectSession.FailureMessage(new(125,"","Operation failed: Win32Exception; code=1223; stage=\r\n")).StartsWith("Windows取消"),"legacy 1223 has useful GUI status without assigning blame");
        Require(CallerProjectSession.FailureMessage(new(125,"","Operation failed: Win32Exception; code=1223; stage=UAC_START\r\n")).StartsWith("Windows取消"),"tagged 1223 has useful GUI status");
        Require(!CallerProjectSession.FailureMessage(new(125,"","other 1223")).StartsWith("Windows取消"),"unrelated error text not misclassified");
        var outputs=new[]{(CSharpProjectTask.Outputs[0],File.ReadAllBytes(Assembly.GetExecutingAssembly().Location)),(CSharpProjectTask.Outputs[1],"{\"SchemaVersion\":1,\"ExitCode\":0,\"TestsPassed\":1}"u8.ToArray()),
            (CSharpProjectTask.Outputs[2],"1"u8.ToArray()),(CSharpProjectTask.Outputs[3],Array.Empty<byte>()),(CSharpProjectTask.Outputs[4],Array.Empty<byte>())};
        var resultBytes=WorkspaceBundle.Create(task.ModifiedFiles().Select(f=>(f.Path,f.Content)).Concat(outputs),session.InputSHA256).Serialize();
        WorkspaceFiles.WriteBundleNew(run.ResultPath,resultBytes);
        var id=new string('b',32);HostPrivacyCase[] Cases()=>HostPrivacyContract.Roles.Select((r,i)=>new HostPrivacyCase(r,HostPrivacyContract.Kind(i),"ACCESS_DENIED",5)).ToArray();
        var privacy=new HostPrivacySummary(HostPrivacyContract.PolicySHA256,new string('F',64),id,111,222,Cases(),Cases());
        string Reply()=>JsonSerializer.Serialize(new{Status="CALLER_CSHARP_PROJECT_RESULT_RECEIVED",SessionId=id,BaseSHA256=session.InputSHA256,
            ResultSHA256=WorkspaceBundle.Hash(resultBytes),FileCount=8,Changes=WorkspaceBundle.Compare(input,resultBytes),OriginalProjectModified=false,ProjectCodeExecuted=true,
            HostPrivacy=privacy,OwnerSealedBeforeCode=true,FormalAdmissionIssued=false,NetworkOpened=false,UACAutoConfirmed=false});
        var response=new BackendResult(0,Reply(),"");var accepted=session.AcceptResult(run,response);checks++;
        foreach(var mutate in new Action<JsonObject>[] {j=>j["OwnerSealedBeforeCode"]=false,j=>j["OwnerSealedBeforeCode"]=1,j=>j["OwnerSealedBeforeCode"]="true",
            j=>j["FormalAdmissionIssued"]=true,j=>j["OriginalProjectModified"]=true,j=>j["NetworkOpened"]=true,j=>j["UACAutoConfirmed"]=true,
            j=>j["BaseSHA256"]=new string('A',64),j=>j["ResultSHA256"]=new string('A',64),j=>j["FileCount"]=7,
            j=>j["SessionId"]="other",j=>j["Status"]="WORKSPACE_DATA_RESULT_RECEIVED",j=>j["HostPrivacy"]=null,j=>j["Extra"]="untrusted",
            j=>j["Changes"]![0]!["Kind"]="DELETE"})
        {var json=JsonNode.Parse(Reply())!.AsObject();mutate(json);Refuse(()=>session.AcceptResult(run,new(0,json.ToJsonString(),"")),"GUI rejects weakened project completion");}
        Refuse(()=>session.AcceptResult(run,new(3,Reply(),"")),"failed caller cannot release results");
        Refuse(()=>session.AcceptResult(run,new(0,Reply(),"failure")),"stderr contradicts success");
        File.WriteAllText(run.InputPath,"replaced");File.WriteAllText(run.ResultPath,"replaced");
        var extracted=Path.Combine(run.Directory,"files");accepted.ExtractNew(extracted);
        Require(File.ReadAllText(Path.Combine(extracted,"Entry.cs")).Contains("return 0;"),"accepted immutable snapshots survive later input/result replacement");
        Require(File.ReadAllText(Path.Combine(folder,"Entry.cs")).Contains("return -1;"),"original source tree unchanged");
        return checks;
    }
}
