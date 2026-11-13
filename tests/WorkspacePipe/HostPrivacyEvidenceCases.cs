using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

internal static class HostPrivacyEvidenceCases
{
    internal static void Run()
    {
        var now=DateTimeOffset.Parse("2026-11-13T12:00:00Z");
        const string session="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",actor="lpac-actor-1";
        var hash=new string('A',64);
        HostPrivacyEvidenceRecord Record(string id,string target,string field,string value,string source,string family,
            HostPrivacyEvidenceVisibility visibility=HostPrivacyEvidenceVisibility.RestrictedActor,
            HostPrivacyEvidenceOutcome outcome=HostPrivacyEvidenceOutcome.ContentRead,bool p0=true,
            string claim="",string key="",string actorId=actor,bool owner=true,bool verified=true,int? error=null,
            DateTimeOffset? expiry=null)=>new(id,session,visibility==HostPrivacyEvidenceVisibility.HostReferenceOnly?"":actorId,
                target,field,value,source,family,claim,key,visibility,outcome,owner,verified,p0,error,now.AddMinutes(-1),expiry,hash);
        void Require(bool value,string reason){if(!value)throw new InvalidDataException(reason);}
        void Reject(IEnumerable<HostPrivacyEvidenceRecord> items,string reason)
        {try{_=HostPrivacyEvidenceRules.Evaluate(session,actor,items,now);}catch(InvalidDataException){return;}throw new InvalidDataException("Accepted "+reason);}
        var host=Record("00000000000000000000000000000001","network.adapter","mac","AA-BB","host-1","adapter",
            HostPrivacyEvidenceVisibility.HostReferenceOnly,p0:true);
        var direct=Record("00000000000000000000000000000002","network.adapter","mac","AA-BB","iphelper-1","iphelper",claim:"device.network.identity",key:"AA-BB");
        var profile=HostPrivacyEvidenceRules.Evaluate(session,actor,new[]{host,direct},now);
        Require(profile.Assessments.Single(item=>item.EvidenceId==host.EvidenceId).Classification==HostPrivacyEvidenceClass.HostReferenceOnly,
            "host reference is not Claude exposure");
        Require(profile.Assessments.Single(item=>item.EvidenceId==direct.EvidenceId).Classification==HostPrivacyEvidenceClass.ConfirmedDirect &&
            profile.P0Exposure,"one confirmed P0 content read blocks regardless of other evidence");
        Require(profile.P0Unknown==false,"a confirmed restricted observation resolves the target's unknown state");
        Require(HostPrivacyEvidenceRules.Evaluate(session,actor,new[]{host},now).P0Unknown,
            "host-only reference cannot resolve restricted-actor visibility");
        var denied=Record("00000000000000000000000000000003","network.tcp","table","","iphelper-2","iphelper",
            outcome:HostPrivacyEvidenceOutcome.AccessDenied,verified:false,error:5);
        var deniedProfile=HostPrivacyEvidenceRules.Evaluate(session,actor,new[]{denied},now);
        Require(deniedProfile.Assessments.Single().Classification==HostPrivacyEvidenceClass.DeniedConfirmed &&
            !deniedProfile.P0Exposure,"explicit native access denied is a denial, not content");
        var missing=Record("00000000000000000000000000000004","network.tcp","table","","iphelper-3","iphelper",
            outcome:HostPrivacyEvidenceOutcome.TargetAbsent,verified:false,error:2);
        Require(HostPrivacyEvidenceRules.Evaluate(session,actor,new[]{missing},now).Assessments.Single().Classification==
            HostPrivacyEvidenceClass.TargetAbsent,"target absence is not denial");
        var unknown=Record("00000000000000000000000000000005","network.tcp","table","","iphelper-4","iphelper",
            outcome:HostPrivacyEvidenceOutcome.Unknown,verified:false);
        Require(HostPrivacyEvidenceRules.Evaluate(session,actor,new[]{unknown},now).P0Unknown,"unknown P0 remains unknown");
        var notRun=Record("00000000000000000000000000000010","network.tcp","table","","iphelper-5","iphelper",
            outcome:HostPrivacyEvidenceOutcome.NotRun,verified:false);
        Require(HostPrivacyEvidenceRules.Evaluate(session,actor,new[]{notRun},now).P0Unknown,
            "NOT_RUN P0 cannot be treated as a pass");
        var a=Record("00000000000000000000000000000006","proxy.config","node","route-x","flclash-config","file",
            claim:"proxy.route",key:"route-x");
        var b=Record("00000000000000000000000000000007","network.tcp","remote-endpoint","route-x","tcp-table","iphelper",
            claim:"proxy.route",key:"route-x");
        var correlated=HostPrivacyEvidenceRules.Evaluate(session,actor,new[]{a,b},now);
        Require(correlated.Inferences.Length==1 && correlated.Inferences[0].EvidenceIds.Length==2,
            "independent source families support deterministic inference");
        var duplicate=Record("00000000000000000000000000000008","proxy.config","node","route-x","flclash-config-copy","file",
            claim:"proxy.route",key:"route-x");
        Require(HostPrivacyEvidenceRules.Evaluate(session,actor,new[]{a,duplicate},now).Inferences.Length==0,
            "same source family cannot masquerade as independent corroboration");
        var expired=Record("00000000000000000000000000000009","device.gpu","uuid","GPU-1","cuda","cuda",
            expiry:now.AddSeconds(-1));
        Require(HostPrivacyEvidenceRules.Evaluate(session,actor,new[]{expired},now).Assessments.Single().Classification==
            HostPrivacyEvidenceClass.Unknown,"expired evidence is unknown");
        Reject(new[]{direct with {ActorId="other-actor"}},"foreign actor");
        Reject(new[]{direct with {OwnerSealed=false}},"unsealed actor result");
        Reject(new[]{direct with {ContentVerified=false}},"unverified content");
        Reject(new[]{direct with {ArtifactSHA256="bad"}},"invalid evidence digest");
        Reject(new[]{direct with {SessionId=new string('b',32)}},"foreign session");
        Reject(new[]{direct,direct},"duplicate evidence identifier");
        Reject(new[]{direct with {Outcome=HostPrivacyEvidenceOutcome.AccessDenied,NativeError=5,Value="secret"}},"denial carrying content");
        Reject(new[]{direct with {Outcome=HostPrivacyEvidenceOutcome.ContentRead,Value="",ContentVerified=true}},"empty content read");
        Console.WriteLine("PASS host privacy evidence provenance, visibility, content/denial distinction, expiry, duplicate-source independence and P0 one-vote blocking");
    }
}
