using System.Text.Json;
using System.Text.Json.Nodes;
using ClaudeCodeProtection.Workspaces;

internal static class ProjectFailureCases
{
    internal static void Run()
    {
        var checks=0;
        void Require(bool value,string reason){if(!value)throw new Exception(reason);checks++;}
        void Refuse(Action action,string reason)
        {try{action();}catch(Exception e)when(e is InvalidDataException or JsonException or InvalidOperationException){checks++;return;}throw new Exception("Accepted "+reason);}
        var failure=new ProjectTaskFailure("Compile",new[]{new ProjectCompilerDiagnostic("CS0103",0,7,9)});
        var encoded=ProjectFailureContract.Encode(failure);
        var decoded=ProjectFailureContract.ReadToolError("",encoded+"\r\n",2);
        Require(decoded?.Diagnostics.Single()==failure.Diagnostics[0],"bounded compiler failure roundtrips");
        foreach(var malformed in new[]{"raw host path C:\\PRIVATE",encoded+"tail",encoded.Replace("CS0103","CS01xx"),encoded.Replace("\"Line\":7","\"Line\":0"),
            encoded.Replace("\"SourceIndex\":0","\"SourceIndex\":2"),encoded.Replace("\"Code\":","\"Message\":\"PRIVATE\",\"Code\":")})
            Require(ProjectFailureContract.ReadToolError("",malformed,2) is null,"unreviewed diagnostic text cannot cross worker boundary");
        Require(ProjectFailureContract.ReadToolError("unexpected stdout",encoded,2) is null,"mixed output cannot become structured failure");
        Refuse(()=>ProjectFailureContract.Validate(new("Run",failure.Diagnostics)),"run cannot carry compiler payload");
        Refuse(()=>ProjectFailureContract.Validate(new("C:\\PRIVATE",Array.Empty<ProjectCompilerDiagnostic>())),"unknown stage");
        Refuse(()=>ProjectFailureContract.Validate(new("Compile",Enumerable.Repeat(failure.Diagnostics[0],9).ToArray())),"error count bound");
        Refuse(()=>ProjectFailureContract.Validate(new("Compile",new[]{new ProjectCompilerDiagnostic("CS0103",null,7,9)})),"global diagnostic cannot carry phantom location");
        var id=new string('a',32);HostPrivacyCase[] Cases()=>HostPrivacyContract.Checks.Select(check=>check.Observe(5)).ToArray();
        var privacy=new HostPrivacySummary(HostPrivacyContract.PolicySHA256,new string('F',64),id,111,222,Cases(),HostPrivacyContract.CompilerChecks.Select(check=>check.Observe(5)).ToArray()){ProbePid=333,ProbeCases=Cases()};
        JsonObject Reply()=>JsonSerializer.SerializeToNode(new{SchemaVersion=6,Scope=WorkspacePipe.CallerProjectScope,ExitCode=3,SessionId=id,BaseSHA256=new string('B',64),
            ResultSHA256=(string?)null,Status="CALLER_CSHARP_PROJECT_NOT_CONFIRMED",FailureStage="processing",FailureKind="ProjectTaskFailed",FailureCode=3,
            CreationEvidence=(object?)null,StopEvidence=(object?)null,HostPrivacy=privacy,OwnerSealedBeforeCode=true,ProjectFailure=failure})!.AsObject();
        byte[] Bytes(JsonObject value)=>JsonSerializer.SerializeToUtf8Bytes(value);
        var reply=WorkspacePipe.ParseReply(Bytes(Reply()),new string('B',64),true,true);
        Require(reply.ExitCode==3 && reply.ResultSHA256 is null && reply.ProjectFailure?.Stage=="Compile","failure data never yields result digest");
        foreach(var mutate in new Action<JsonObject>[]{j=>j["ExitCode"]=0,j=>j["ResultSHA256"]=new string('C',64),j=>j["OwnerSealedBeforeCode"]=false,
            j=>j["HostPrivacy"]=null,j=>j["FailureStage"]="export",j=>j["FailureKind"]="Other",j=>j["ProjectFailure"]=null,
            j=>j["ProjectFailure"]!["Diagnostics"]![0]!["SourcePath"]="C:\\PRIVATE",j=>j["SchemaVersion"]=5})
        {var json=Reply();mutate(json);Refuse(()=>WorkspacePipe.ParseReply(Bytes(json),new string('B',64),true,true),"weakened failure envelope");}
        Refuse(()=>WorkspacePipe.ParseReply(Bytes(Reply()),new string('B',64),true),"sample cannot carry caller failure extension");
        Refuse(()=>WorkspacePipe.ParseReply(Bytes(Reply()),new string('B',64)),"DATA cannot carry caller failure extension");
        var legacy=Reply();legacy.Remove("ProjectFailure");legacy["FailureKind"]="ResourceSessionFailed";
        Require(WorkspacePipe.ParseReply(Bytes(legacy),new string('B',64),true,true).ProjectFailure is null,"legacy failure shape remains valid");
        Console.WriteLine($"PASS {checks} bounded project failure and IPC refusal checks; synthetic only, no product, compiler, LPAC, UAC or private state");
    }
}
