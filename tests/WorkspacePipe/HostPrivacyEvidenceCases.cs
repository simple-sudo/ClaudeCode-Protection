using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

internal static class HostPrivacyEvidenceCases
{
    internal static void Run()
    {
        var now=DateTimeOffset.Parse("2026-11-13T12:00:00Z");
        const string session="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",actor="lpac-actor-1";
        var hash=new string('A',64);
        var sequence=0;
        HostPrivacyEvidenceRecord Record(string target,string field,string value,string source,string family,
            HostPrivacyEvidenceVisibility visibility=HostPrivacyEvidenceVisibility.RestrictedActor,
            HostPrivacyEvidenceOutcome outcome=HostPrivacyEvidenceOutcome.ContentRead,string claim="",string key="",string actorId=actor,bool owner=true,bool verified=true,int? error=null,
            DateTimeOffset? expiry=null)
        {
            sequence++;
            var sensitiveField=target switch {
                "network.adapter.guid" when field=="interface-guid"=>true,
                "network.adapter.mac" when field=="mac"=>true,
                "network.adapter.address" when field=="unicast"=>true,
                "network.adapter.dns" when field=="dns"=>true,
                "network.adapter.gateway" when field=="gateway"=>true,
                "network.tcp.v4" or "network.tcp.v6" when field is "connection" or "process-pid"=>true,
                "network.processes" when field=="process"=>true,
                _=>false
            };
            return new(sequence.ToString("x32"),session,
                visibility==HostPrivacyEvidenceVisibility.HostReferenceOnly?"":actorId,
                target,field,value,source,family,claim,key,visibility,outcome,owner,verified,
                HostPrivacyEvidenceRules.RequiredP0Targets.Contains(target,StringComparer.Ordinal),
                sensitiveField && value.Length>0,error,now.AddMinutes(-1),expiry??now.AddMinutes(14),hash);
        }
        void Require(bool value,string reason){if(!value)throw new InvalidDataException(reason);}
        HostPrivacyEvidenceProfile Evaluate(IEnumerable<HostPrivacyEvidenceRecord> items)=>
            HostPrivacyEvidenceRules.Evaluate(session,actor,items,now);
        void Reject(IEnumerable<HostPrivacyEvidenceRecord> items,string reason)
        {
            var rejected=false;try{_=Evaluate(items);}catch(InvalidDataException){rejected=true;}
            Require(rejected,"Accepted "+reason);
        }
        HostPrivacyEvidenceRecord Host(string target,string field="inventory")=>
            Record(target,field,field=="mac"?"HOST-MAC":"[]","host-"+target,"iphelper-adapters",
                HostPrivacyEvidenceVisibility.HostReferenceOnly);
        HostPrivacyEvidenceRecord Empty(string target,string field="inventory")=>
            Record(target,field,"[]","restricted-"+target,"iphelper-adapters");
        HostPrivacyEvidenceRecord[] CompleteCoverage()
        {
            var result=new List<HostPrivacyEvidenceRecord>();
            foreach(var target in HostPrivacyEvidenceRules.RequiredP0Targets)
            {
                result.Add(Host(target));
                result.Add(Empty(target));
            }
            return result.ToArray();
        }

        Require(HostPrivacyEvidenceRules.RequiredP0Targets.Count==8,
            "the immutable P0 matrix contains all eight network/process targets");
        var direct=Record("network.adapter.mac","mac","AA-BB","iphelper-1","iphelper-adapters",
            claim:"device.network.identity",key:"AA-BB");
        var hostMac=Host("network.adapter.mac","mac");
        var metadata=Record("network.adapter.metadata","description","Wireless adapter","host-metadata","iphelper-adapters");
        var metadataProfile=Evaluate(new[]{metadata});
        Require(metadataProfile.Assessments.Single().Classification==HostPrivacyEvidenceClass.ConfirmedDirect &&
            !metadataProfile.P0Exposure && metadataProfile.P0Unknown,
            "non-P0 adapter metadata remains auditable without being mislabeled as sensitive P0 content");
        var profile=Evaluate(CompleteCoverage().Append(direct));
        Require(profile.Assessments.Single(item=>item.EvidenceId==direct.EvidenceId).Classification==HostPrivacyEvidenceClass.ConfirmedDirect &&
            profile.P0Exposure && !profile.P0Unknown,
            "one confirmed P0 content read blocks even when all required targets are covered");
        Require(profile.Assessments.Single(item=>item.EvidenceId==hostMac.EvidenceId).Value is null,
            "host reference raw values never enter the exposure profile");
        Require(profile.PolicyId==HostPrivacyEvidenceRules.PolicyId && profile.SchemaVersion==1,
            "profile carries a stable policy identity and schema version");

        var partial=Evaluate(new[]{hostMac,direct});
        Require(partial.P0Exposure && partial.P0Unknown,
            "one direct observation blocks while unobserved required P0 targets remain unknown");
        var hostOnly=Evaluate(new[]{hostMac});
        Require(hostOnly.P0Unknown,"host-only reference cannot resolve restricted-actor visibility");

        var emptyInventory=Empty("network.adapter.mac");
        var emptyProfile=Evaluate(new[]{hostMac,emptyInventory});
        Require(emptyProfile.Assessments.Single(item=>item.EvidenceId==emptyInventory.EvidenceId).Classification==HostPrivacyEvidenceClass.ConfirmedDirect &&
            !emptyProfile.P0Exposure && emptyProfile.P0Unknown,
            "a successfully read empty inventory resolves one target without fabricating sensitive exposure");
        var staleHost=hostMac with {ExpiresAtUtc=now.AddSeconds(-1)};
        Require(Evaluate(new[]{staleHost,direct}).P0Unknown,
            "expired host reference cannot qualify a restricted observation");
        Require(Evaluate(new[]{direct}).P0Unknown,
            "required P0 targets without host and restricted observations remain unknown");

        var denied=Record("network.tcp.v4","buffer-status","","iphelper-2","iphelper-tcp",
            outcome:HostPrivacyEvidenceOutcome.AccessDenied,verified:false,error:5);
        var hostTcp=Host("network.tcp.v4");
        var deniedProfile=Evaluate(new[]{hostTcp,denied});
        Require(deniedProfile.Assessments.Single(item=>item.EvidenceId==denied.EvidenceId).Classification==HostPrivacyEvidenceClass.DeniedConfirmed &&
            !deniedProfile.P0Exposure && deniedProfile.P0Unknown,
            "explicit native access denied is a denial, not content, and does not resolve unrelated P0 targets");
        var missing=Record("network.tcp.v4","buffer-status","","iphelper-3","iphelper-tcp",
            outcome:HostPrivacyEvidenceOutcome.TargetAbsent,verified:false,error:2);
        Require(Evaluate(new[]{missing}).Assessments.Single().Classification==
            HostPrivacyEvidenceClass.TargetAbsent && Evaluate(new[]{missing}).P0Unknown,
            "target absence is not denial and leaves the P0 target unresolved");
        var unknown=Record("network.tcp.v4","decode-status","","iphelper-4","iphelper-tcp",
            outcome:HostPrivacyEvidenceOutcome.Unknown,verified:false);
        Require(Evaluate(new[]{unknown}).P0Unknown,"unknown P0 remains unknown");
        var notRun=Record("network.tcp.v4","decode-status","","iphelper-5","iphelper-tcp",
            outcome:HostPrivacyEvidenceOutcome.NotRun,verified:false);
        Require(Evaluate(new[]{notRun}).P0Unknown,"NOT_RUN P0 cannot be treated as a pass");

        var mixed=Evaluate(CompleteCoverage().Append(direct).Append(denied));
        Require(mixed.P0Exposure && !mixed.P0Unknown,
            "one direct P0 exposure remains blocking even alongside a confirmed denial");
        var a=Record("network.adapter.mac","mac","route-x","flclash-config","file",
            claim:"proxy.route",key:"route-x");
        var b=Record("network.tcp.v4","connection","route-x","tcp-table","iphelper-tcp",
            claim:"proxy.route",key:"route-x");
        var correlated=Evaluate(CompleteCoverage().Append(a).Append(b));
        Require(correlated.Inferences.Length==1 && correlated.Inferences[0].EvidenceIds.Length==2,
            "independent source families support deterministic inference");
        var duplicate=Record("network.adapter.mac","mac","route-x","flclash-config-copy","file",
            claim:"proxy.route",key:"route-x");
        Require(Evaluate(CompleteCoverage().Append(a).Append(duplicate)).Inferences.Length==0,
            "same source family cannot masquerade as independent corroboration");

        var expired=Record("network.adapter.mac","mac","GPU-1","gpu-query","gpu",
            expiry:now.AddSeconds(-1));
        Require(Evaluate(new[]{expired}).Assessments.Single().Classification==HostPrivacyEvidenceClass.Unknown,
            "expired evidence is unknown");
        Reject(new[]{direct with {ActorId="other-actor"}},"foreign actor");
        Reject(new[]{direct with {RequiredP0=false}},"evidence cannot downgrade a required P0 target");
        Reject(new[]{direct with {OwnerSealed=false}},"unsealed actor result");
        Require(Evaluate(new[]{direct with {ContentVerified=false}}).Assessments.Single().Classification==
            HostPrivacyEvidenceClass.Unknown,"unverified content is unknown, never confirmed exposure");
        Reject(new[]{direct with {ArtifactSHA256="bad"}},"invalid evidence digest");
        Reject(new[]{direct with {SessionId=new string('b',32)}},"foreign session");
        Reject(new[]{direct,direct},"duplicate evidence identifier");
        Reject(new[]{direct with {SensitiveContent=false}},"sensitive MAC field cannot be downgraded");
        Reject(new[]{direct with {Value="",SensitiveContent=false}},"empty field cannot retain a correlation claim");
        Reject(new[]{direct with {Field="unreviewed-field"}},"unknown field cannot enter the trusted evidence profile");
        Reject(new[]{direct with {ExpiresAtUtc=now.AddMinutes(-2)}},"evidence expiry cannot predate observation");
        Reject(new[]{direct with {ExpiresAtUtc=null}},"evidence cannot have an unbounded lifetime");
        var localObserved=now.AddHours(-1).ToOffset(TimeSpan.FromHours(-5));
        Reject(new[]{direct with {ObservedAtUtc=localObserved,ExpiresAtUtc=localObserved.AddMinutes(15)}},
            "local-offset timestamps cannot be mislabeled as UTC evidence");
        Reject(new[]{direct with {Outcome=HostPrivacyEvidenceOutcome.AccessDenied,NativeError=5,Value="secret"}},"denial carrying content");
        Reject(new[]{direct with {Outcome=HostPrivacyEvidenceOutcome.ContentRead,NativeError=5}},"content read carrying native failure");
        Reject(new[]{direct with {Outcome=HostPrivacyEvidenceOutcome.Unknown,Value="secret",ContentVerified=false}},"unknown outcome carrying unverified raw content");
        var emptyMac=direct with {Value="",SensitiveContent=false,Claim="",CorrelationKey=""};
        var emptyMacProfile=Evaluate(new[]{emptyMac});
        Require(emptyMacProfile.Assessments.Single().Classification==HostPrivacyEvidenceClass.ConfirmedDirect &&
            !emptyMacProfile.P0Exposure && emptyMacProfile.P0Unknown,
            "a verified empty field is not sensitive content and cannot resolve unrelated P0 targets");
        Console.WriteLine("PASS host privacy evidence: immutable P0 matrix, field sensitivity, owner-sealed actor provenance, bounded expiry, content/denial distinction, independent-source inference and one-vote blocking");
    }
}
