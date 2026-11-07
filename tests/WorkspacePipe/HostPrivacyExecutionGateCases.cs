using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

internal static class HostPrivacyExecutionGateCases
{
    internal static void Run()
    {
        var session=new string('a',32);var hash=new string('F',64);var checks=0;
        HostPrivacyObservation Observation(int pid)=>new(1,session,hash,pid,
            HostPrivacyContract.Checks.Select(check=>check.Observe(5)).ToArray());
        HostPrivacyObservation Compiler(int pid)=>new(1,session,hash,pid,
            HostPrivacyContract.CompilerChecks.Select(check=>check.Observe(5)).ToArray());
        HostPrivacyExecutionGate Gate()=>new(session,hash);
        HostPrivacyExecutionGate Probed()
        {var g=Gate();g.SealRoot(Observation(111),111);g.AuthorizeProbeCreation();g.SealProbe(Observation(222),222);return g;}
        void Require(bool value,string reason){if(!value)throw new InvalidDataException(reason);checks++;}
        void Refuse(Action action,string reason)
        {try{action();}catch(InvalidDataException){checks++;return;}throw new Exception("Gate accepted "+reason);}
        Require(HostPrivacyContract.PolicySHA256=="8034D0E54F887AF61C34280AA9815D53F59A40C24D602A5BF851BF19ADC3336C",
            "pre-refactor privacy v5 policy identity");
        Require(HostPrivacyContract.Checks.Count==33 && HostPrivacyContract.CompilerChecks.Count==28 &&
            HostPrivacyContract.Checks.Where(check=>check.AllowsOwnerObservedAbsence).Single().Target==HostPrivacyTarget.ClaudeSettings,
            "original inventory and sole optional target");
        Require(HostPrivacyContract.CompilerChecks.GroupBy(check=>check.TargetKind).Select(group=>(group.Key,group.Count())).SequenceEqual(new[]{
            (HostPrivacyTargetKind.OwnerProcess,9),(HostPrivacyTargetKind.ControlFile,10),(HostPrivacyTargetKind.RootProcess,9)}),
            "compiler uses only owner, public control files and held root in wire order");
        var empty=Gate();Refuse(empty.ReleaseExecution,"code before root");Refuse(empty.AuthorizeProbeCreation,"probe before root");
        Refuse(empty.AuthorizeToolCreation,"compiler before root");Refuse(()=>empty.SealProbe(Observation(222),222),"probe before root");
        var gate=Gate();var root=Observation(111);gate.SealRoot(root,111);
        Refuse(gate.AuthorizeToolCreation,"compiler before probe");Refuse(gate.ReleaseExecution,"root-only release");
        gate.AuthorizeProbeCreation();Refuse(gate.AuthorizeProbeCreation,"second probe");
        Refuse(()=>gate.SealProbe(Observation(111),111),"root as probe");
        var probe=Observation(222);gate.SealProbe(probe,222);
        Refuse(gate.ReleaseExecution,"probe is not compiler evidence");
        Refuse(()=>gate.SealTool(Compiler(333),333),"compiler before owner authorizes creation");
        gate.AuthorizeToolCreation();Refuse(gate.AuthorizeToolCreation,"second compiler creation");
        Refuse(()=>gate.SealTool(Compiler(111),111),"root as compiler");Refuse(()=>gate.SealTool(Compiler(222),222),"probe as compiler");
        Refuse(()=>gate.SealTool(Observation(333),333),"full host report cannot masquerade as compiler control checks");
        Refuse(()=>gate.SealTool(Compiler(333) with {SessionId=new string('b',32)},333),"foreign session");
        Refuse(()=>gate.SealTool(Compiler(333) with {PlanSHA256=new string('A',64)},333),"foreign plan");
        var compiler=Compiler(333);gate.SealTool(compiler,333);
        foreach(var input in new[]{root,probe,compiler})for(var i=0;i<input.Cases.Length;i++)input.Cases[i]=input.Cases[i] with {Status="OPENED",Error=0};
        Require(HostPrivacyContract.Satisfied(gate.Snapshot(111,333)),"untrusted source array mutations cannot replace owner evidence");
        var exported=gate.Snapshot(111,333);foreach(var cases in new[]{exported.RootCases,exported.ProbeCases,exported.ToolCases})
            for(var i=0;i<cases.Length;i++)cases[i]=cases[i] with {Status="OPENED",Error=0};
        Require(HostPrivacyContract.Satisfied(gate.Snapshot(111,333)),"export array mutations cannot replace owner evidence");
        Require(!gate.ExecutionReleased,"sealing does not release code");gate.ReleaseExecution();Require(gate.ExecutionReleased,"three sealed actors release code once");
        Refuse(gate.ReleaseExecution,"second release");Refuse(()=>gate.Snapshot(111,444),"replacement compiler");
        for(var i=0;i<HostPrivacyContract.Checks.Count;i++)
        {
            var bad=Observation(111);bad.Cases[i]=bad.Cases[i] with {Status="OPENED",Error=0};Refuse(()=>Gate().SealRoot(bad,111),"root exposed "+i);
            var g=Gate();g.SealRoot(Observation(111),111);g.AuthorizeProbeCreation();var unknown=Observation(222);unknown.Cases[i]=unknown.Cases[i] with {Status="UNKNOWN",Error=2};
            Refuse(()=>g.SealProbe(unknown,222),"probe unknown "+i);Refuse(g.AuthorizeToolCreation,"unknown probe blocks compiler "+i);
        }
        for(var i=0;i<HostPrivacyContract.CompilerChecks.Count;i++)
        {
            var g=Probed();g.AuthorizeToolCreation();var bad=Compiler(333);bad.Cases[i]=bad.Cases[i] with {Status="OPENED",Error=0};
            Refuse(()=>g.SealTool(bad,333),"compiler exposed "+i);Refuse(g.ReleaseExecution,"compiler exposure blocks code "+i);
        }
        foreach(var error in new[]{2,3,5})
        {
            var r=Observation(111);var p=Observation(222);r.Cases[7]=HostPrivacyContract.Checks[7].Observe(error,true);p.Cases[7]=HostPrivacyContract.Checks[7].Observe(error,true);
            Refuse(()=>Gate().SealRoot(r,111),"child cannot select absence");
            var g=new HostPrivacyExecutionGate(session,hash,true);g.SealRoot(r,111);g.AuthorizeProbeCreation();g.SealProbe(p,222);g.AuthorizeToolCreation();g.SealTool(Compiler(333),333);g.ReleaseExecution();
            var report=g.Snapshot(111,333);Require(HostPrivacyContract.Satisfied(report) && report.RootCases.Concat(report.ProbeCases).Concat(report.ToolCases).Count(c=>c.Status=="ACCESS_DENIED")==92,"92 actual denials and two owner-selected absence observations");
        }
        Require(HostPrivacyContract.Checks.Where(check=>check.TargetKind==HostPrivacyTargetKind.OwnerProcess).Select(check=>check.Access).SequenceEqual(new uint[]{0x10,1,2,8,0x20,0x40,0x800,0x40000,0x80000}),"one minimal process right per case");
        Require(HostPrivacyContract.CompilerChecks.Where(check=>check.TargetKind==HostPrivacyTargetKind.RootProcess).Select(check=>check.Role).All(r=>r.StartsWith("protection-root-",StringComparison.Ordinal)),"compiler checks actual root memory and control separately");
        Console.WriteLine($"PASS {checks} separate-probe owner gate checks; synthetic reports only, NOT native exit, LPAC, plan withdrawal or system qualification");
    }
}
