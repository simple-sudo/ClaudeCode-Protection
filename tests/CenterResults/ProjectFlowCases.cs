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
        {try{action();}catch(Exception error)when(error is InvalidDataException or IOException or UnauthorizedAccessException or InvalidOperationException or JsonException || error is System.ComponentModel.Win32Exception {NativeErrorCode:80 or 183}){checks++;return;}throw new Exception("Accepted "+reason);}
        void RefuseSelf(Action action)
        {try{action();}catch(InvalidDataException error)when(error.Message.StartsWith("保护系统",StringComparison.Ordinal)){checks++;return;}throw new Exception("Protection directory selection accepted");}
        var folder=Path.Combine(fixture,"caller-source");Directory.CreateDirectory(folder);
        var definition=new CSharpProjectDefinition(1,CSharpProjectTask.Kind,new[]{"Entry.cs","Checks.cs"},new[]{new CSharpProjectEdit("Entry.cs","return -1;","return 0;")},"Demo.Entry","Demo.Checks",1);
        File.WriteAllBytes(Path.Combine(folder,CSharpProjectTask.Manifest),JsonSerializer.SerializeToUtf8Bytes(definition));
        File.WriteAllText(Path.Combine(folder,"Entry.cs"),"namespace Demo; public static class Entry {public static int Run(){return -1;}}");
        File.WriteAllText(Path.Combine(folder,"Checks.cs"),"namespace Demo; public static class Checks {public static int Run(){return 1;}}");
        File.WriteAllText(Path.Combine(folder,"unselected.txt"),"OWN_NONSECRET_UNSELECTED");
        var session=CallerProjectSession.OpenFolder(folder);
        var authored=CallerProjectSession.Create(folder,definition.Sources,definition.Edits,definition.EntryType,definition.TestType,1);
        Require(authored.InputSHA256==session.InputSHA256,"authoring produces same task as explicit existing manifest");
        var saved=Path.Combine(fixture,"authored-task.json");authored.SaveBundle(saved);
        Require(CallerProjectSession.OpenBundle(saved).InputSHA256==authored.InputSHA256,"authored snapshot saves and reopens");
        Refuse(()=>authored.SaveBundle(saved),"saved task cannot overwrite existing file");
        Refuse(()=>CallerProjectSession.Create(folder,new[]{"../Entry.cs"},definition.Edits,definition.EntryType,definition.TestType,1),"selection cannot escape project root");
        Refuse(()=>CallerProjectSession.Create(folder,new[]{"unselected.txt"},definition.Edits,definition.EntryType,definition.TestType,1),"authoring cannot compile arbitrary selected data");
        Refuse(()=>CallerProjectSession.Create(folder,definition.Sources,new[]{new CSharpProjectEdit("Entry.cs","not present","replacement")},definition.EntryType,definition.TestType,1),"authoring rejects absent edit before execution");
        Refuse(()=>CallerProjectSession.Create(folder,definition.Sources,definition.Edits,definition.EntryType,definition.EntryType,1),"authoring requires separate entry and tests");
        var own=Path.Combine(fixture,"protection-checkout");
        Directory.CreateDirectory(Path.Combine(own,"src","ProtectionLifecycle"));Directory.CreateDirectory(Path.Combine(own,"src","ProtectionBootstrap"));
        File.WriteAllText(Path.Combine(own,"src","ProtectionLifecycle","ProtectionLifecycle.csproj"),"OWN_NONSECRET_MARKER");
        File.WriteAllText(Path.Combine(own,"src","ProtectionBootstrap","ApprovedPackage.json"),"OWN_NONSECRET_MARKER");
        RefuseSelf(()=>CallerProjectSession.OpenFolder(own));
        RefuseSelf(()=>CallerProjectSession.OpenBundle(Path.Combine(own,"task.json")));
        RefuseSelf(()=>authored.PlanRun(own));
        var pf=Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        foreach(var reserved in new[]{Path.Combine(pf,"ClaudeCodeProtection"),Path.Combine(pf,"ClaudeCodeProtection-State"),Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"ClaudeCodeProtection")})
            RefuseSelf(()=>WorkspaceFiles.RequireExternalProjectPath(Path.Combine(reserved,"absent.cs")));
        Require(!WorkspaceFiles.IsWithin(Path.Combine(pf,"ClaudeCodeProtection-Independent","Entry.cs"),Path.Combine(pf,"ClaudeCodeProtection")),"prefix sibling is not protection root");
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
        var compilerFailure=new ProjectTaskFailure("Compile",new[]{new ProjectCompilerDiagnostic("CS0103",0,7,9)});
        JsonObject Failure()=>JsonSerializer.SerializeToNode(new{Status="CALLER_CSHARP_PROJECT_NOT_CONFIRMED",SessionId=id,BaseSHA256=session.InputSHA256,
            FailureStage="processing",FailureKind="ProjectTaskFailed",FailureCode=3,CreationEvidence=(object?)null,StopEvidence=(object?)null,
            HostPrivacy=privacy,OwnerSealedBeforeCode=true,ProjectFailure=compilerFailure,ResultReleased=false,AutomaticRetry=false})!.AsObject();
        var display=session.DescribeFailure(new(3,Failure().ToJsonString(),""));
        Require(display.Contains("CS0103  Entry.cs：第7行，第9列") && display.Contains("结果未导出"),"compiler failure maps index to reviewed source name");
        foreach(var mutate in new Action<JsonObject>[]{j=>j["BaseSHA256"]=new string('A',64),j=>j["ResultReleased"]=true,j=>j["AutomaticRetry"]=true,
            j=>j["OwnerSealedBeforeCode"]=false,j=>j["ProjectFailure"]!["Diagnostics"]![0]!["SourceIndex"]=31,
            j=>j["ProjectFailure"]!["Diagnostics"]![0]!["SourcePath"]="C:\\PRIVATE",j=>j["PrivateMessage"]="SECRET"})
        {var json=Failure();mutate(json);Require(!session.DescribeFailure(new(3,json.ToJsonString(),"")).Contains("CS0103"),"unbound or unbounded diagnostic stays generic");}
        Refuse(()=>session.AcceptResult(run,new(3,Failure().ToJsonString(),"")),"failure feedback cannot enter result recovery");
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
        var dataFolder=Path.Combine(fixture,"data-project");Directory.CreateDirectory(dataFolder);
        File.WriteAllText(Path.Combine(dataFolder,"Entry.cs"),"namespace Demo; public static class Entry {public static int Run(){return -1;}}");
        File.WriteAllText(Path.Combine(dataFolder,"Checks.cs"),"namespace Demo; public static class Checks {public static int Run(){return 1;}}");
        File.WriteAllBytes(Path.Combine(dataFolder,"input.bin"),new byte[]{0,128,255});
        File.WriteAllText(Path.Combine(dataFolder,"unselected.txt"),"not selected");
        var dataTask=CallerProjectSession.Create(dataFolder,definition.Sources,definition.Edits,definition.EntryType,definition.TestType,1,
            new[]{"input.bin"},new[]{new CSharpProjectOutput("cpc-results/report.json",128)});
        Require(dataTask.ReviewText.Contains("数据：input.bin") && dataTask.ReviewText.Contains("cpc-results/report.json") && dataTask.ReviewText.Contains("128 字节"),"data and result limits reviewed before execution");
        var dataRun=dataTask.PlanRun(fixture);dataTask.WriteInput(dataRun);var dataBytes=WorkspaceFiles.ReadBundle(dataRun.InputPath);var dataParsed=CSharpProjectTask.Parse(dataBytes);
        Require(dataParsed.Definition.SchemaVersion==2 && dataParsed.Baseline.Files.Length==4 && dataParsed.ResultPaths.Length==10,"GUI captures explicit source/data/manifest only");
        File.WriteAllBytes(Path.Combine(dataFolder,CSharpProjectTask.Manifest),dataParsed.Baseline.Files.Single(f=>f.Path==CSharpProjectTask.Manifest).Content);
        Require(CallerProjectSession.OpenFolder(dataFolder).InputSHA256==dataTask.InputSHA256,"V2 folder import reads exactly declared data");
        File.WriteAllBytes(Path.Combine(dataFolder,"input.bin"),new byte[]{1});
        var savedData=Path.Combine(fixture,"data-task.json");dataTask.SaveBundle(savedData);
        Require(CallerProjectSession.OpenBundle(savedData).InputSHA256==dataTask.InputSHA256,"later data edits cannot change prepared snapshot");
        var dataResults=WorkspaceBundle.Create(dataParsed.ModifiedFiles().Select(f=>(f.Path,f.Content)).Concat(outputs).Append(
            ("cpc-results/report.json","{\"ok\":true}"u8.ToArray())),dataTask.InputSHA256).Serialize();
        WorkspaceFiles.WriteBundleNew(dataRun.ResultPath,dataResults);
        var dataReply=JsonSerializer.Serialize(new{Status="CALLER_CSHARP_PROJECT_RESULT_RECEIVED",SessionId=id,BaseSHA256=dataTask.InputSHA256,
            ResultSHA256=WorkspaceBundle.Hash(dataResults),FileCount=dataParsed.ResultPaths.Length,Changes=WorkspaceBundle.Compare(dataBytes,dataResults),
            OriginalProjectModified=false,ProjectCodeExecuted=true,HostPrivacy=privacy,OwnerSealedBeforeCode=true,FormalAdmissionIssued=false,NetworkOpened=false,UACAutoConfirmed=false});
        var dataAccepted=dataTask.AcceptResult(dataRun,new(0,dataReply,""));checks++;
        var dataExtracted=Path.Combine(dataRun.Directory,"files");dataAccepted.ExtractNew(dataExtracted);
        Require(File.ReadAllText(Path.Combine(dataExtracted,"cpc-results","report.json"))=="{\"ok\":true}" &&
            File.ReadAllBytes(Path.Combine(dataExtracted,"input.bin")).AsSpan().SequenceEqual(new byte[]{0,128,255}),"GUI restores declared result with reviewed unchanged binary data");
        Refuse(()=>CallerProjectSession.Create(dataFolder,definition.Sources,definition.Edits,definition.EntryType,definition.TestType,1,
            new[]{"../input.bin"},Array.Empty<CSharpProjectOutput>()),"data cannot escape selected project");
        return checks;
    }
}
