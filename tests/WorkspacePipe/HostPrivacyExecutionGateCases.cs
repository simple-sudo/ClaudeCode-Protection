using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

internal static class HostPrivacyExecutionGateCases
{
    internal static void Run()
    {
        var session=new string('a',32);var hash=new string('F',64);var checks=0;
        HostPrivacyObservation Observation(int pid)=>new(1,session,hash,pid,
            HostPrivacyContract.Roles.Select((role,i)=>new HostPrivacyCase(role,HostPrivacyContract.Kind(i),"ACCESS_DENIED",5)).ToArray());
        HostPrivacyExecutionGate Gate()=>new(session,hash);
        void Require(bool value,string reason){if(!value)throw new InvalidDataException(reason);checks++;}
        void Refuse(Action action,string reason)
        {try{action();}catch(InvalidDataException){checks++;return;}throw new Exception("Gate accepted "+reason);}
        var empty=Gate();
        Refuse(empty.ReleaseExecution,"code before root");
        Refuse(empty.AuthorizeToolCreation,"compiler before root");
        Refuse(()=>empty.SealTool(Observation(222),222),"tool before root");
        Refuse(()=>empty.Snapshot(111,222),"snapshot before root");
        var gate=Gate();var root=Observation(111);gate.SealRoot(root,111);
        Refuse(gate.ReleaseExecution,"root-only code release");
        Refuse(()=>gate.SealRoot(root,111),"second root observation");
        Refuse(()=>gate.SealTool(Observation(222),222),"tool without original creation phase");
        Refuse(()=>gate.Snapshot(111,222),"root-only successful snapshot");
        gate.AuthorizeToolCreation();
        Refuse(gate.AuthorizeToolCreation,"second compiler creation");
        Refuse(()=>gate.SealTool(Observation(111),111),"root as compiler");
        Refuse(()=>gate.SealTool(Observation(222),333),"wrong held tool PID");
        Refuse(()=>gate.SealTool(Observation(222) with { SessionId=new string('b',32) },222),"foreign session");
        Refuse(()=>gate.SealTool(Observation(222) with { PlanSHA256=new string('A',64) },222),"foreign resource plan");
        var tool=Observation(222);gate.SealTool(tool,222);
        Refuse(()=>gate.SealTool(tool,222),"second tool observation");
        // Mutate every child-owned input slot, then every returned summary
        // slot. None may alter the original owner's pre-code observation.
        for(var i=0;i<HostPrivacyContract.Roles.Length;i++)
        {
            root.Cases[i]=root.Cases[i] with { Status="OPENED",Error=0 };
            tool.Cases[i]=tool.Cases[i] with { Status="UNKNOWN",Error=2 };
        }
        var sealedReport=gate.Snapshot(111,222);
        Require(sealedReport.RootCases.Concat(sealedReport.ToolCases).All(c=>c.Status=="ACCESS_DENIED" && c.Error==5),"source-array mutation cannot rewrite owner evidence");
        for(var i=0;i<HostPrivacyContract.Roles.Length;i++)
        {
            sealedReport.RootCases[i]=sealedReport.RootCases[i] with { Status="OPENED",Error=0 };
            sealedReport.ToolCases[i]=sealedReport.ToolCases[i] with { Status="OPENED",Error=0 };
        }
        Require(HostPrivacyContract.Satisfied(gate.Snapshot(111,222)),"exported-array mutation cannot rewrite owner evidence");
        Require(!gate.ExecutionReleased && gate.ToolCreationAuthorized,"sealing does not silently release code");
        gate.ReleaseExecution();Require(gate.ExecutionReleased,"paired sealed observations release code once");
        Refuse(gate.ReleaseExecution,"second execution release");
        Refuse(gate.AuthorizeToolCreation,"compiler after code release");
        Refuse(()=>gate.SealRoot(Observation(111),111),"root replacement after release");
        Refuse(()=>gate.SealTool(Observation(222),222),"tool replacement after release");
        Refuse(()=>gate.Snapshot(333,222),"changed root on final export");
        Refuse(()=>gate.Snapshot(111,333),"changed tool on final export");
        for(var i=0;i<HostPrivacyContract.Roles.Length;i++)
        {
            var deniedRoot=Gate();var opened=Observation(111);opened.Cases[i]=opened.Cases[i] with { Status="OPENED",Error=0 };
            Refuse(()=>deniedRoot.SealRoot(opened,111),"opened root slot "+i);
            Refuse(deniedRoot.AuthorizeToolCreation,"invalid root cannot authorize compiler "+i);
            var deniedTool=Gate();deniedTool.SealRoot(Observation(111),111);deniedTool.AuthorizeToolCreation();
            var unknown=Observation(222);unknown.Cases[i]=unknown.Cases[i] with { Status="UNKNOWN",Error=2 };
            Refuse(()=>deniedTool.SealTool(unknown,222),"unknown tool slot "+i);
            Refuse(deniedTool.ReleaseExecution,"invalid tool cannot release code "+i);
        }
        Console.WriteLine($"PASS {checks} original-owner pre-code gate checks: phase ordering, single compiler/release, exact actors/context, all14 failed slots, immutable source/returned snapshots; pure synthetic reports, NOT LPAC/native host privacy or live Job qualification");
    }
}
