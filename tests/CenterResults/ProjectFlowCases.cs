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
        var identifier=new string('a',32);
        foreach(var directory in new[]{"ClaudeCodeProtection-Bootstrap","ClaudeCodeProtection-Update-"+identifier,
            "claudecodeprotection-task-"+identifier.ToUpperInvariant()})
            RefuseSelf(()=>WorkspaceFiles.RequireExternalProjectPath(Path.Combine(pf,directory,"absent.cs")));
        WorkspaceFiles.RequireExternalProjectPath(Path.Combine(pf,"ClaudeCodeProtection-Update-not-a-release","Entry.cs"));
        WorkspaceFiles.RequireExternalProjectPath(Path.Combine(pf,"ClaudeCodeProtection-Task-"+identifier+"-example","Entry.cs"));
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
        var privacy=new HostPrivacySummary(HostPrivacyContract.PolicySHA256,new string('F',64),id,111,222,Cases(),Enumerable.Range(0,HostPrivacyContract.CompilerCaseCount).Select(i=>{var c=HostPrivacyContract.CompilerCase(i);return new HostPrivacyCase(c.Role,c.Kind,"ACCESS_DENIED",5);}).ToArray()){ProbePid=333,ProbeCases=Cases()};
        string Reply()=>JsonSerializer.Serialize(new{Status="CALLER_CSHARP_PROJECT_RESULT_RECEIVED",SessionId=id,BaseSHA256=session.InputSHA256,
            ResultSHA256=WorkspaceBundle.Hash(resultBytes),FileCount=8,Changes=WorkspaceBundle.Compare(input,resultBytes),OriginalProjectModified=false,ProjectCodeExecuted=true,
            HostPrivacy=privacy,OwnerSealedBeforeCode=true,FormalAdmissionIssued=false,NetworkOpened=false,UACAutoConfirmed=false});
        var response=new BackendResult(0,Reply(),"");var accepted=session.AcceptResult(run,response);checks++;
        Require(session.DescribePrivacy(response).Contains("94") && !session.DescribePrivacy(response).Contains("缺失"),"all-present success describes actual denial count");
        var presentPrivacy=privacy;
        var absentRoot=Cases();var absentTool=Cases();
        absentRoot[7]=HostPrivacyContract.FileObservation(7,true,2);absentTool[7]=HostPrivacyContract.FileObservation(7,true,5);
        privacy=privacy with {RootCases=absentRoot,ProbeCases=absentTool};
        var resetResponse=new BackendResult(0,Reply(),"");_=session.AcceptResult(run,resetResponse);checks++;
        var resetText=session.DescribePrivacy(resetResponse);
        Require(resetText.Contains("92") && resetText.Contains("2 项") && resetText.Contains("缺失不代表权限拒绝"),"reset absence is visible separately from actual denials");
        privacy=presentPrivacy;
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
        var probeFailure=Cases();probeFailure[0]=probeFailure[0] with {Status="OPENED",Error=0};
        var compilerFailureCases=privacy.ToolCases.ToArray();compilerFailureCases[19]=compilerFailureCases[19] with {Status="UNKNOWN",Error=6};
        var privacyBlock=Failure();privacyBlock["FailureKind"]="ResourceSessionFailed";privacyBlock["OwnerSealedBeforeCode"]=false;
        privacyBlock["ProjectFailure"]=null;
        privacyBlock["HostPrivacy"]=JsonSerializer.SerializeToNode(privacy with {ProbeCases=probeFailure,ToolPid=null,ToolCases=Array.Empty<HostPrivacyCase>()});
        var blockReply=new BackendResult(3,privacyBlock.ToJsonString(),"");
        var blockText=session.DescribeFailure(blockReply);
        Require(blockText.Contains("1 项可打开，0 项无法确认") && blockText.Contains("独立探针 flclash-config-json") &&
            blockText.Contains("项目代码未获放行"),"probe exposure is attributed to the probe without implying execution");
        Refuse(()=>session.AcceptResult(run,blockReply),"privacy block cannot release output");
        privacyBlock["HostPrivacy"]!["ProbeCases"]![0]!["Role"]="C:\\PRIVATE";
        Require(!session.DescribeFailure(new(3,privacyBlock.ToJsonString(),"")).Contains("PRIVATE"),"unrecognized private resource label cannot cross GUI");
        privacyBlock["HostPrivacy"]=JsonSerializer.SerializeToNode(privacy with {ToolCases=compilerFailureCases});
        var compilerBlock=session.DescribeFailure(new(3,privacyBlock.ToJsonString(),""));
        Require(compilerBlock.Contains("0 项可打开，1 项无法确认") && compilerBlock.Contains("编译器 protection-root-memory"),"unknown compiler result stays distinct from exposure");
        foreach(var mutate in new Action<JsonObject>[] {j=>j["OwnerSealedBeforeCode"]=false,j=>j["OwnerSealedBeforeCode"]=1,j=>j["OwnerSealedBeforeCode"]="true",
            j=>j["FormalAdmissionIssued"]=true,j=>j["OriginalProjectModified"]=true,j=>j["NetworkOpened"]=true,j=>j["UACAutoConfirmed"]=true,
            j=>j["BaseSHA256"]=new string('A',64),j=>j["ResultSHA256"]=new string('A',64),j=>j["FileCount"]=7,
            j=>j["SessionId"]="other",j=>j["Status"]="WORKSPACE_DATA_RESULT_RECEIVED",j=>j["HostPrivacy"]=null,j=>j["Extra"]="untrusted",
            j=>j["Changes"]![0]!["Kind"]="DELETE"})
        {var json=JsonNode.Parse(Reply())!.AsObject();mutate(json);Refuse(()=>session.AcceptResult(run,new(0,json.ToJsonString(),"")),"GUI rejects weakened project completion");}
        Refuse(()=>session.AcceptResult(run,new(3,Reply(),"")),"failed caller cannot release results");
        Refuse(()=>session.AcceptResult(run,new(0,Reply(),"failure")),"stderr contradicts success");
        var revision=session.CreateRevision(resultBytes);
        Require(revision.Sources.SequenceEqual(definition.Sources) && revision.ExpectedTests==1,"continuation preserves source order and tests");
        Require(revision.ReadSource("Entry.cs").Contains("return 0;"),"preview exposes selected modified source for next literal edit");
        Refuse(()=>revision.ReadSource(CSharpProjectTask.Outputs[0]),"preview cannot expose compiled output as source");
        Refuse(()=>revision.Prepare(definition.Edits),"old edit cannot be blindly replayed on modified source");
        var nextEdit=new[]{new CSharpProjectEdit("Entry.cs","return 0;","return 2;")};
        var next=revision.Prepare(nextEdit);var nextPath=Path.Combine(fixture,"next-task.json");next.SaveBundle(nextPath);
        var nextParsed=CSharpProjectTask.Parse(WorkspaceFiles.ReadBundle(nextPath));
        Require(nextParsed.Baseline.Files.Length==3 && nextParsed.Baseline.BaseSHA256 is null &&
            nextParsed.Definition.SchemaVersion==1 && next.InputSHA256!=session.InputSHA256,"revision is a new V1 baseline without prior output/admission");
        Require(Encoding.UTF8.GetString(nextParsed.Baseline.Files.Single(f=>f.Path=="Entry.cs").Content).Contains("return 0;") &&
            Encoding.UTF8.GetString(nextParsed.ModifiedFiles().Single(f=>f.Path=="Entry.cs").Content).Contains("return 2;"),"next edit starts with previously modified source");
        var wrong=WorkspaceBundle.Create(task.ModifiedFiles().Select(f=>(f.Path,f.Content)).Concat(outputs),new string('A',64)).Serialize();
        Refuse(()=>session.CreateRevision(wrong),"continuation refuses wrong previous baseline");
        var tampered=WorkspaceBundle.Create(task.ModifiedFiles().Select(f=>(f.Path,f.Path=="Entry.cs"?"unreviewed"u8.ToArray():f.Content)).Concat(outputs),session.InputSHA256).Serialize();
        Refuse(()=>session.CreateRevision(tampered),"continuation refuses unexpected previous source");
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
        var dataRevision=CallerProjectSession.OpenRevision(dataRun.InputPath,dataRun.ResultPath);
        var capturedResultHash=dataRevision.PreviousResultSHA256;
        File.WriteAllText(dataRun.InputPath,"later replacement");File.WriteAllText(dataRun.ResultPath,"later replacement");
        var exposed=dataRevision.Sources;exposed[0]="unreviewed.cs";
        Require(dataRevision.Prepare(nextEdit,2).ExpectedTests==2,"continuation can explicitly update expected test count for new tests");
        Refuse(()=>dataRevision.Prepare(nextEdit,257),"continuation cannot exceed test-count bounds");
        var nextData=dataRevision.Prepare(nextEdit);var nextDataPath=Path.Combine(fixture,"next-data-task.json");nextData.SaveBundle(nextDataPath);
        var continued=CSharpProjectTask.Parse(WorkspaceFiles.ReadBundle(nextDataPath));
        Require(capturedResultHash==WorkspaceBundle.Hash(dataResults) && continued.Definition.SchemaVersion==2 && continued.Baseline.Files.Length==4,
            "selected V2 result is held as immutable snapshot through later path replacement");
        Require(continued.Definition.Sources.SequenceEqual(definition.Sources) && continued.Definition.DataFiles!.SequenceEqual(new[]{"input.bin"}) &&
            continued.GeneratedFiles.Single()==new CSharpProjectOutput("cpc-results/report.json",128),"V2 declaration and original output limit preserved without mutable arrays");
        Require(continued.Baseline.Files.All(f=>!f.Path.StartsWith("cpc-output/") && !f.Path.StartsWith("cpc-results/")) &&
            continued.Baseline.Files.Single(f=>f.Path=="input.bin").Content.AsSpan().SequenceEqual(new byte[]{0,128,255}),
            "previous DLL and generated files excluded while binary data bytes preserved");
        Refuse(()=>dataRevision.Prepare(new[]{new CSharpProjectEdit("input.bin","x","y")}),"data selection does not become editable executable source");
        var secondResults=WorkspaceBundle.Create(continued.ModifiedFiles().Select(f=>(f.Path,f.Content)).Concat(outputs).Append(
            ("cpc-results/report.json","{}"u8.ToArray())),nextData.InputSHA256).Serialize();
        var secondRevision=nextData.CreateRevision(secondResults);
        var third=secondRevision.Prepare(new[]{new CSharpProjectEdit("Entry.cs","return 2;","return 3;")});
        Require(third.ReviewText.Contains("return 2;") && third.ReviewText.Contains("return 3;") && third.InputSHA256!=nextData.InputSHA256,
            "repeated continuation advances the source with a new reviewed digest each time");
        Refuse(()=>CallerProjectSession.Create(dataFolder,definition.Sources,definition.Edits,definition.EntryType,definition.TestType,1,
            new[]{"../input.bin"},Array.Empty<CSharpProjectOutput>()),"data cannot escape selected project");
        return checks;
    }
}
