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
            HostPrivacyEvidenceOutcome outcome=HostPrivacyEvidenceOutcome.ContentRead,bool p0=true,bool sensitive=true,
            string claim="",string key="",string actorId=actor,bool owner=true,bool verified=true,int? error=null,
            DateTimeOffset? expiry=null)=>new(id,session,visibility==HostPrivacyEvidenceVisibility.HostReferenceOnly?"":actorId,
                target,field,value,source,family,claim,key,visibility,outcome,owner,verified,p0,sensitive,error,now.AddMinutes(-1),expiry,hash);
        void Require(bool value,string reason){if(!value)throw new InvalidDataException(reason);}
        HostPrivacyEvidenceProfile Evaluate(IEnumerable<HostPrivacyEvidenceRecord> items,params string[] requiredTargets)=>
            HostPrivacyEvidenceRules.Evaluate(session,actor,items,now,requiredTargets);
        void Reject(IEnumerable<HostPrivacyEvidenceRecord> items,string reason)
        {try{_=Evaluate(items,"network.adapter");}catch(InvalidDataException){return;}throw new InvalidDataException("Accepted "+reason);}
        var host=Record("00000000000000000000000000000001","network.adapter","mac","AA-BB","host-1","adapter",
            HostPrivacyEvidenceVisibility.HostReferenceOnly,p0:true);
        var direct=Record("00000000000000000000000000000002","network.adapter","mac","AA-BB","iphelper-1","iphelper",claim:"device.network.identity",key:"AA-BB");
        var profile=Evaluate(new[]{host,direct},"network.adapter");
        Require(profile.Assessments.Single(item=>item.EvidenceId==host.EvidenceId).Classification==HostPrivacyEvidenceClass.HostReferenceOnly,
            "host reference is not Claude exposure");
        Require(profile.Assessments.Single(item=>item.EvidenceId==direct.EvidenceId).Classification==HostPrivacyEvidenceClass.ConfirmedDirect &&
            profile.P0Exposure,"one confirmed P0 content read blocks regardless of other evidence");
        Require(profile.P0Unknown==false,"a confirmed restricted observation resolves the target's unknown state");
        var emptyInventory=Record("00000000000000000000000000000011","network.adapter","inventory","[]","iphelper-empty","iphelper",
            sensitive:false,claim:"",key:"");
        var emptyProfile=Evaluate(new[]{host,emptyInventory},"network.adapter");
        Require(emptyProfile.Assessments.Single(item=>item.EvidenceId==emptyInventory.EvidenceId).Classification==HostPrivacyEvidenceClass.ConfirmedDirect &&
            !emptyProfile.P0Exposure && !emptyProfile.P0Unknown,
            "a successfully read empty inventory resolves coverage without fabricating sensitive exposure");
        Require(Evaluate(new[]{host},"network.adapter").P0Unknown,
            "host-only reference cannot resolve restricted-actor visibility");
        Require(Evaluate(new[]{direct},"network.adapter","network.tcp").P0Unknown,
            "required P0 target without any observation remains unknown");
        var denied=Record("00000000000000000000000000000003","network.tcp","table","","iphelper-2","iphelper",
            outcome:HostPrivacyEvidenceOutcome.AccessDenied,verified:false,error:5);
        var hostTcp=Record("00000000000000000000000000000012","network.tcp","inventory","[]","host-tcp","iphelper",
            HostPrivacyEvidenceVisibility.HostReferenceOnly,sensitive:false);
        var deniedProfile=Evaluate(new[]{hostTcp,denied},"network.tcp");
        Require(deniedProfile.Assessments.Single().Classification==HostPrivacyEvidenceClass.DeniedConfirmed &&
            !deniedProfile.P0Exposure,"explicit native access denied is a denial, not content");
        var missing=Record("00000000000000000000000000000004","network.tcp","table","","iphelper-3","iphelper",
            outcome:HostPrivacyEvidenceOutcome.TargetAbsent,verified:false,error:2);
        Require(Evaluate(new[]{missing},"network.tcp").Assessments.Single().Classification==
            HostPrivacyEvidenceClass.TargetAbsent,"target absence is not denial");
        var unknown=Record("00000000000000000000000000000005","network.tcp","table","","iphelper-4","iphelper",
            outcome:HostPrivacyEvidenceOutcome.Unknown,verified:false);
        Require(Evaluate(new[]{unknown},"network.tcp").P0Unknown,"unknown P0 remains unknown");
        var notRun=Record("00000000000000000000000000000010","network.tcp","table","","iphelper-5","iphelper",
            outcome:HostPrivacyEvidenceOutcome.NotRun,verified:false);
        Require(Evaluate(new[]{notRun},"network.tcp").P0Unknown,
            "NOT_RUN P0 cannot be treated as a pass");
        var a=Record("00000000000000000000000000000006","proxy.config","node","route-x","flclash-config","file",
            claim:"proxy.route",key:"route-x");
        var b=Record("00000000000000000000000000000007","network.tcp","remote-endpoint","route-x","tcp-table","iphelper",
            claim:"proxy.route",key:"route-x");
        var correlated=Evaluate(new[]{a,b},"proxy.config","network.tcp");
        Require(correlated.Inferences.Length==1 && correlated.Inferences[0].EvidenceIds.Length==2,
            "independent source families support deterministic inference");
        var duplicate=Record("00000000000000000000000000000008","proxy.config","node","route-x","flclash-config-copy","file",
            claim:"proxy.route",key:"route-x");
        Require(Evaluate(new[]{a,duplicate},"proxy.config").Inferences.Length==0,
            "same source family cannot masquerade as independent corroboration");
        var expired=Record("00000000000000000000000000000009","device.gpu","uuid","GPU-1","cuda","cuda",
            expiry:now.AddSeconds(-1));
        Require(Evaluate(new[]{expired},"device.gpu").Assessments.Single().Classification==
            HostPrivacyEvidenceClass.Unknown,"expired evidence is unknown");
        Reject(new[]{direct with {ActorId="other-actor"}},"foreign actor");
        Reject(new[]{direct with {RequiredP0=false}},"evidence cannot downgrade a required P0 target");
        Reject(new[]{direct with {OwnerSealed=false}},"unsealed actor result");
        Require(Evaluate(new[]{direct with {ContentVerified=false}},"network.adapter").Assessments.Single().Classification==
            HostPrivacyEvidenceClass.Unknown,"unverified content is unknown, never confirmed exposure");
        Reject(new[]{direct with {ArtifactSHA256="bad"}},"invalid evidence digest");
        Reject(new[]{direct with {SessionId=new string('b',32)}},"foreign session");
        Reject(new[]{direct,direct},"duplicate evidence identifier");
        Require(Evaluate(new[]{direct with {Outcome=HostPrivacyEvidenceOutcome.AccessDenied,NativeError=5,Value="secret"}},"network.adapter").Assessments.Single().Classification==
            HostPrivacyEvidenceClass.Unknown,"denial carrying content is contradictory and unknown");
        Require(Evaluate(new[]{direct with {Outcome=HostPrivacyEvidenceOutcome.ContentRead,Value="",ContentVerified=true}},"network.adapter").Assessments.Single().Classification==
            HostPrivacyEvidenceClass.Unknown,"empty content cannot be confirmed as a content read");
        Console.WriteLine("PASS host privacy evidence provenance, visibility, content/denial distinction, expiry, duplicate-source independence and P0 one-vote blocking");
    }
}
