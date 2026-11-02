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
        // Earlier V1 evidence cannot satisfy the new protection-owner policy,
        // including the case where the new fields were simply omitted.
        var legacy=Observation(111) with {Cases=Observation(111).Cases.Take(14).ToArray()};
        Refuse(()=>Gate().SealRoot(legacy,111),"old 14-slot root evidence");
        Require(HostPrivacyContract.Roles.Length==33,"14 host, nine owner and ten control file access cases required");
        var masks=Enumerable.Range(14,9).Select(HostPrivacyContract.OwnerAccess).ToArray();
        Require(masks.SequenceEqual(new uint[]{0x10,0x1,0x2,0x8,0x20,0x40,0x800,0x40000,0x80000}),"each owner right has exact minimal mask");
        Require(masks.Distinct().Count()==9 && masks.All(m=>(m&(m-1))==0),"no combined or repeated rights hide exposure");
        Refuse(()=>HostPrivacyContract.OwnerAccess(13),"host case cannot request owner rights");
        Refuse(()=>HostPrivacyContract.OwnerAccess(23),"undefined owner rights");
        var fileMasks=new uint[]{1,2,0x40000,0x80000,2,0x40000,0x80000,2,0x40000,0x80000};
        for(var i=0;i<fileMasks.Length;i++)Require(HostPrivacyContract.ControlFileAccess(i+23)==fileMasks[i],"one minimal file right per role");
        Refuse(()=>HostPrivacyContract.ControlFileAccess(22),"process index is not a control file grant");
        Refuse(()=>HostPrivacyContract.ControlFileAccess(33),"undefined control file rights");
        var processOnly=Observation(111) with {Cases=Observation(111).Cases.Take(23).ToArray()};
        Refuse(()=>Gate().SealRoot(processOnly,111),"previous process-only inventory omits control file checks");
        Console.WriteLine($"PASS {checks} original-owner pre-code gate checks: phase ordering, single compiler/release, exact actors/context, all{HostPrivacyContract.Roles.Length} failed slots, legacy inventory refusal, minimal owner masks, immutable snapshots; pure synthetic reports, NOT LPAC/native host privacy or live Job qualification");
    }
}
