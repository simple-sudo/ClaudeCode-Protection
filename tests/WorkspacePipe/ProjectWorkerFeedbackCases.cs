using System.Text.Json;
using System.Text.Json.Nodes;
using ClaudeCodeProtection.Workspaces;

internal static class ProjectWorkerFeedbackCases
{
    internal static void Run()
    {
        int passed=0;var session=new string('a',32);var hash=new string('A',64);
        JsonObject Child()=>JsonSerializer.SerializeToNode(new {SchemaVersion=1,Pid=111,Nonce=session,ToolExit=(int?)null,
            FailureType="TimeoutException",FailureCode=unchecked((int)0x80131505),FailureStage="WAIT_PROJECT_COMPILER",
            ProjectFailure=(object?)null,PrivateMessage="SECRET_NOT_FOR_PUBLIC_REPLY"})!.AsObject();
        ProjectWorkerFeedback.Failure? Read(JsonObject child)=>ProjectWorkerFeedback.FromOwnerChild(JsonSerializer.SerializeToElement(child),session,111);
        void Require(bool value){if(!value)throw new InvalidDataException("Worker feedback fixture failed");passed++;}
        Require(Read(Child()) is {Kind:"ProjectCompilerWaitTimeout",Code:unchecked((int)0x80131505)});
        var sample=Child();sample["ToolExit"]=0;Require(Read(sample) is {Kind:"ProjectCompilerDrainTimeout",Code:0});
        sample["FailureStage"]="WAIT_PROJECT_COMPILER/ProjectDevelopmentNotConfirmed";sample["FailureType"]="InvalidDataException";
        Require(Read(sample) is {Kind:"ProjectCompilerOutputUnexpected",Code:0});
        sample["ToolExit"]=unchecked((int)0xc0000005);Require(Read(sample) is {Kind:"ProjectCompilerExited",Code:unchecked((int)0xc0000005)});
        sample=Child();sample["FailureType"]="IOException";sample["FailureCode"]=5;Require(Read(sample) is {Kind:"ProjectCompilerWaitFailed",Code:5});
        sample["FailureStage"]="START_PROJECT_COMPILER/CREATE_PROCESS/InheritedToolCreateProcess";Require(Read(sample) is {Kind:"ProjectCompilerStartFailed",Code:5});
        foreach(var mutate in new Action<JsonObject>[] {j=>j["SchemaVersion"]=2,j=>j["Pid"]=222,j=>j["Nonce"]=new string('b',32),
            j=>j["FailureCode"]="PRIVATE",j=>j["FailureCode"]=null,j=>j["FailureType"]="PRIVATE",j=>j["FailureStage"]="WAIT_PROJECT_COMPILER/PRIVATE",
            j=>j["FailureStage"]="START_PROJECT_COMPILER/CREATE_PROCESS/PRIVATE",j=>j["ProjectFailure"]=new JsonObject(),j=>j.Remove("FailureStage")})
        {sample=Child();mutate(sample);Require(Read(sample) is null);}
        var text=Child().ToJsonString();using(var duplicate=JsonDocument.Parse(text[..^1]+",\"Pid\":111}"))
            Require(ProjectWorkerFeedback.FromOwnerChild(duplicate.RootElement,session,111) is null);
        Require(ProjectWorkerFeedback.FromOwnerChild(JsonSerializer.SerializeToElement(Child()),new string('A',32),111) is null);
        Require(!ProjectWorkerFeedback.IsKind("ProjectCompilerWaitTimeout_PRIVATE"));
        Require(!JsonSerializer.Serialize(Read(Child())).Contains("SECRET",StringComparison.Ordinal));

        HostPrivacyCase[] Cases()=>HostPrivacyContract.Roles.Select((role,i)=>new HostPrivacyCase(role,HostPrivacyContract.Kind(i),"ACCESS_DENIED",5)).ToArray();
        var privacy=new HostPrivacySummary(HostPrivacyContract.PolicySHA256,new string('F',64),session,111,222,Cases(),
            Enumerable.Range(0,HostPrivacyContract.CompilerCaseCount).Select(i=>{var c=HostPrivacyContract.CompilerCase(i);return new HostPrivacyCase(c.Role,c.Kind,"ACCESS_DENIED",5);}).ToArray())
            {ProbePid=333,ProbeCases=Cases()};
        JsonObject Reply()=>JsonSerializer.SerializeToNode(new {SchemaVersion=6,Scope=WorkspacePipe.CallerProjectScope,HostPrivacy=privacy,OwnerSealedBeforeCode=true,
            ExitCode=3,SessionId=session,BaseSHA256=hash,ResultSHA256=(string?)null,Status="CALLER_CSHARP_PROJECT_NOT_CONFIRMED",
            FailureStage="processing",FailureKind="ProjectCompilerExited",FailureCode=unchecked((int)0xc0000005),CreationEvidence=(object?)null,StopEvidence=(object?)null})!.AsObject();
        var reply=WorkspacePipe.ParseReply(JsonSerializer.SerializeToUtf8Bytes(Reply()),hash,true,true);
        Require(reply.FailureCode==unchecked((int)0xc0000005) && reply.ResultSHA256 is null);
        foreach(var mutate in new Action<JsonObject>[] {j=>j["OwnerSealedBeforeCode"]=false,j=>j["HostPrivacy"]=null,j=>j["ExitCode"]=0,
            j=>j["FailureStage"]="export",j=>j["ProjectFailure"]=null,j=>j["SessionId"]=new string('b',32)})
        {
            sample=Reply();mutate(sample);bool refused=false;
            try{_=WorkspacePipe.ParseReply(JsonSerializer.SerializeToUtf8Bytes(sample),hash,true,true);}catch(InvalidDataException){refused=true;}
            Require(refused);
        }
        Console.WriteLine(JsonSerializer.Serialize(new {Scope="ORDINARY_WORKER_FAILURE_CONTRACT_FIXTURES_ONLY",Passed=passed,NativeOrProductExecution=false,AdmissionIssued=false}));
    }
}
