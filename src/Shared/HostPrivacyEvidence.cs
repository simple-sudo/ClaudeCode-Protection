namespace ClaudeCodeProtection.Workspaces;

internal enum HostPrivacyEvidenceVisibility { HostReferenceOnly, RestrictedActor }
internal enum HostPrivacyEvidenceOutcome { ContentRead, AccessDenied, Unknown, NotRun, TargetAbsent }
internal enum HostPrivacyEvidenceClass { HostReferenceOnly, ConfirmedDirect, DeniedConfirmed, Unknown, NotRun, TargetAbsent }

internal sealed record HostPrivacyEvidenceRecord(
    string EvidenceId,string SessionId,string ActorId,string Target,string Field,string Value,
    string SourceId,string SourceFamily,string Claim,string CorrelationKey,
    HostPrivacyEvidenceVisibility Visibility,HostPrivacyEvidenceOutcome Outcome,
    bool OwnerSealed,bool ContentVerified,bool RequiredP0,bool SensitiveContent,int? NativeError,
    DateTimeOffset ObservedAtUtc,DateTimeOffset? ExpiresAtUtc,string ArtifactSHA256);

internal sealed record HostPrivacyEvidenceAssessment(
    string EvidenceId,string Target,string Field,HostPrivacyEvidenceClass Classification,
    bool RequiredP0,bool SensitiveContent,string SourceId,string SourceFamily,string? Value);

internal sealed record HostPrivacyInference(
    string Claim,string CorrelationKey,string[] EvidenceIds,string[] SourceFamilies);

internal sealed record HostPrivacyEvidenceProfile(
    string SessionId,DateTimeOffset EvaluatedAtUtc,HostPrivacyEvidenceAssessment[] Assessments,
    HostPrivacyInference[] Inferences,bool P0Exposure,bool P0Unknown)
{
    public int SchemaVersion {get;init;}=1;
    public string PolicyId {get;init;}=HostPrivacyEvidenceRules.PolicyId;
    public string? ActorId {get;init;}
    public string? OwnerIdentityReceiptSHA256 {get;init;}
    public string? NetworkSurveyReceiptSHA256 {get;init;}
}

internal static class HostPrivacyEvidenceRules
{
    internal const string PolicyId="CPC-HOST-PRIVACY-EVIDENCE-P0-V1";
    private static readonly TimeSpan MaximumEvidenceLifetime=TimeSpan.FromMinutes(15);

    // This matrix is policy, not caller input. A caller cannot remove a target
    // from the required set by passing a shorter or weaker list.
    internal static IReadOnlyList<string> RequiredP0Targets {get;}=Array.AsReadOnly(new[]{
        "network.adapter.guid","network.adapter.mac","network.adapter.address","network.adapter.dns",
        "network.adapter.gateway","network.tcp.v4","network.tcp.v6","network.processes"
    });

    // Field-level sensitivity is also policy. In particular, an empty inventory
    // can prove coverage without being misreported as sensitive content.
    private static readonly IReadOnlyDictionary<string,IReadOnlyDictionary<string,bool>> FieldPolicy=
        new Dictionary<string,IReadOnlyDictionary<string,bool>>(StringComparer.Ordinal)
        {
            ["network.adapter.metadata"]=Fields(("description",false),("friendly-name",false),("dns-suffix",false)),
            ["network.adapter.guid"]=Fields(("interface-guid",true),("inventory",false),("buffer-status",false),("decode-status",false)),
            ["network.adapter.mac"]=Fields(("mac",true),("inventory",false),("buffer-status",false),("decode-status",false)),
            ["network.adapter.address"]=Fields(("unicast",true),("unicast-inventory",false),("inventory",false),("buffer-status",false),("decode-status",false)),
            ["network.adapter.dns"]=Fields(("dns",true),("dns-inventory",false),("inventory",false),("buffer-status",false),("decode-status",false)),
            ["network.adapter.gateway"]=Fields(("gateway",true),("gateway-inventory",false),("inventory",false),("buffer-status",false),("decode-status",false)),
            ["network.tcp.v4"]=Fields(("connection",true),("process-pid",true),("inventory",false),("buffer-status",false),("decode-status",false)),
            ["network.tcp.v6"]=Fields(("connection",true),("process-pid",true),("inventory",false),("buffer-status",false),("decode-status",false)),
            ["network.processes"]=Fields(("process",true),("inventory",false),("inventory-status",false))
        };

    private static IReadOnlyDictionary<string,bool> Fields(params (string Name,bool Sensitive)[] fields)=>
        new System.Collections.ObjectModel.ReadOnlyDictionary<string,bool>(
            fields.ToDictionary(item=>item.Name,item=>item.Sensitive,StringComparer.Ordinal));

    internal static HostPrivacyEvidenceProfile Evaluate(string session,string actor,
        IEnumerable<HostPrivacyEvidenceRecord> evidence,DateTimeOffset now)
    {
        if(!IsHex(session,32) || string.IsNullOrWhiteSpace(actor) || actor.Length>256 ||
            evidence is null || now.Offset!=TimeSpan.Zero)
            throw new InvalidDataException("Host privacy evidence context differs");

        var requiredTargets=RequiredP0Targets;
        var requiredSet=requiredTargets.ToHashSet(StringComparer.Ordinal);
        var records=evidence.ToArray();
        if(records.Length>4096)throw new InvalidDataException("Host privacy evidence count exceeds limit");
        var ids=new HashSet<string>(StringComparer.Ordinal);
        var assessments=new List<HostPrivacyEvidenceAssessment>();
        var inferenceInputs=new List<HostPrivacyEvidenceRecord>();
        foreach(var item in records)
        {
            Validate(item,session,actor,now,requiredSet);
            if(!ids.Add(item.EvidenceId))throw new InvalidDataException("Duplicate host privacy evidence id");
            var classification=Classify(item,now);
            if(item.Visibility==HostPrivacyEvidenceVisibility.HostReferenceOnly)
            {
                assessments.Add(new(item.EvidenceId,item.Target,item.Field,classification,
                    item.RequiredP0,item.SensitiveContent,item.SourceId,item.SourceFamily,null));
                continue;
            }
            assessments.Add(new(item.EvidenceId,item.Target,item.Field,classification,item.RequiredP0,item.SensitiveContent,
                item.SourceId,item.SourceFamily,classification==HostPrivacyEvidenceClass.ConfirmedDirect?item.Value:null));
            if(classification==HostPrivacyEvidenceClass.ConfirmedDirect && item.SensitiveContent &&
                item.Claim.Length>0 && item.CorrelationKey.Length>0)
                inferenceInputs.Add(item);
        }

        var inferences=inferenceInputs
            .GroupBy(item=>item.Claim+"\u001f"+item.CorrelationKey,StringComparer.Ordinal)
            .Select(group=>new {Items=group.GroupBy(item=>item.SourceFamily,StringComparer.Ordinal)
                .Select(family=>family.OrderBy(item=>item.EvidenceId,StringComparer.Ordinal).First()).ToArray(),Key=group.Key})
            .Where(group=>group.Items.Select(item=>item.SourceFamily).Distinct(StringComparer.Ordinal).Count()>=2 &&
                group.Items.Select(item=>item.SourceId).Distinct(StringComparer.Ordinal).Count()>=2)
            .Select(group=>{
                var split=group.Key.Split('\u001f',2);
                return new HostPrivacyInference(split[0],split[1],
                    group.Items.Select(item=>item.EvidenceId).Order(StringComparer.Ordinal).ToArray(),
                    group.Items.Select(item=>item.SourceFamily).Order(StringComparer.Ordinal).ToArray());
            })
            .OrderBy(item=>item.Claim,StringComparer.Ordinal).ThenBy(item=>item.CorrelationKey,StringComparer.Ordinal).ToArray();

        var p0Exposure=assessments.Any(item=>item.RequiredP0 && item.SensitiveContent &&
            item.Classification==HostPrivacyEvidenceClass.ConfirmedDirect);
        var p0Unknown=requiredTargets.Any(target=>{
            var targetRecords=records.Where(item=>item.RequiredP0 && item.Target==target).ToArray();
            var targetResults=assessments.Where(item=>item.RequiredP0 && item.Target==target).ToArray();
            if(targetRecords.Length==0 ||
                !targetRecords.Any(item=>item.Visibility==HostPrivacyEvidenceVisibility.HostReferenceOnly) ||
                !targetRecords.Any(item=>item.Visibility==HostPrivacyEvidenceVisibility.RestrictedActor))return true;
            return !targetResults.Any(item=>item.Classification is HostPrivacyEvidenceClass.DeniedConfirmed or HostPrivacyEvidenceClass.ConfirmedDirect) ||
                targetResults.Any(item=>item.Classification is HostPrivacyEvidenceClass.Unknown or HostPrivacyEvidenceClass.NotRun or HostPrivacyEvidenceClass.TargetAbsent);
        });
        return new(session,now,assessments.ToArray(),inferences,p0Exposure,p0Unknown);
    }

    internal static HostPrivacyEvidenceClass Classify(HostPrivacyEvidenceRecord item,DateTimeOffset now)
    {
        if(item.ExpiresAtUtc is not { } expiry || expiry.Offset!=TimeSpan.Zero || expiry<=now)
            return HostPrivacyEvidenceClass.Unknown;
        if(item.Visibility==HostPrivacyEvidenceVisibility.HostReferenceOnly)return HostPrivacyEvidenceClass.HostReferenceOnly;
        return item.Outcome switch {
            HostPrivacyEvidenceOutcome.ContentRead when item.OwnerSealed && item.ContentVerified &&
                item.NativeError is null && (!item.SensitiveContent || item.Value.Length>0) => HostPrivacyEvidenceClass.ConfirmedDirect,
            HostPrivacyEvidenceOutcome.AccessDenied when item.OwnerSealed && item.Value.Length==0 &&
                item.NativeError==5 && !item.ContentVerified => HostPrivacyEvidenceClass.DeniedConfirmed,
            HostPrivacyEvidenceOutcome.TargetAbsent when item.OwnerSealed && item.Value.Length==0 &&
                item.NativeError is 2 or 3 && !item.ContentVerified => HostPrivacyEvidenceClass.TargetAbsent,
            HostPrivacyEvidenceOutcome.NotRun=>HostPrivacyEvidenceClass.NotRun,
            _=>HostPrivacyEvidenceClass.Unknown
        };
    }

    private static void Validate(HostPrivacyEvidenceRecord item,string session,string actor,DateTimeOffset now,
        IReadOnlySet<string> requiredSet)
    {
        if(item is null || !IsHex(item.EvidenceId,32) || item.SessionId!=session ||
            !SafeLabel(item.Target,256) || !SafeLabel(item.Field,256) ||
            item.ActorId is null || item.Value is null || item.Value.Length>65536 ||
            !SafeLabel(item.SourceId,256) || !SafeLabel(item.SourceFamily,128) ||
            item.Claim is null || item.CorrelationKey is null ||
            item.Claim.Length>256 || item.Claim.Contains('\u001f') ||
            item.CorrelationKey.Length>1024 || item.CorrelationKey.Contains('\u001f') ||
            (item.Claim.Length==0)!=(item.CorrelationKey.Length==0) ||
            item.ObservedAtUtc.Offset!=TimeSpan.Zero || item.ObservedAtUtc<=DateTimeOffset.UnixEpoch ||
            item.ObservedAtUtc>now || item.ExpiresAtUtc is not { } expiry || expiry.Offset!=TimeSpan.Zero ||
            expiry<=item.ObservedAtUtc || expiry-item.ObservedAtUtc>MaximumEvidenceLifetime ||
            item.NativeError is <0 || !IsHex(item.ArtifactSHA256,64) ||
            !Enum.IsDefined(item.Visibility) || !Enum.IsDefined(item.Outcome))
            throw new InvalidDataException("Host privacy evidence shape or provenance differs");

        if(item.RequiredP0!=requiredSet.Contains(item.Target))
            throw new InvalidDataException("Evidence P0 severity differs from immutable target matrix");
        if(!FieldPolicy.TryGetValue(item.Target,out var fields) || !fields.TryGetValue(item.Field,out var sensitiveField))
            throw new InvalidDataException("Host privacy target/field is not in the evidence policy");
        if(item.SensitiveContent!=(sensitiveField && item.Value.Length>0))
            throw new InvalidDataException("Evidence sensitivity differs from immutable target/field policy");

        if(item.Visibility==HostPrivacyEvidenceVisibility.RestrictedActor)
        {
            if(item.ActorId!=actor || !item.OwnerSealed)
                throw new InvalidDataException("Restricted evidence lacks owner actor attestation");
            if(item.Outcome==HostPrivacyEvidenceOutcome.ContentRead && item.NativeError is not null ||
                item.Outcome==HostPrivacyEvidenceOutcome.AccessDenied &&
                    (item.Value.Length!=0 || item.NativeError!=5 || item.ContentVerified) ||
                item.Outcome==HostPrivacyEvidenceOutcome.TargetAbsent &&
                    (item.Value.Length!=0 || item.NativeError is not (2 or 3) || item.ContentVerified) ||
                item.Outcome is HostPrivacyEvidenceOutcome.Unknown or HostPrivacyEvidenceOutcome.NotRun &&
                    (item.Value.Length!=0 || item.ContentVerified))
                throw new InvalidDataException("Restricted evidence outcome contradicts its native read state");
        }
        else if(item.Visibility==HostPrivacyEvidenceVisibility.HostReferenceOnly)
        {
            if(item.ActorId.Length!=0 || item.Outcome!=HostPrivacyEvidenceOutcome.ContentRead ||
                !item.OwnerSealed || !item.ContentVerified || item.NativeError is not null)
                throw new InvalidDataException("Host reference evidence shape differs");
        }
        else throw new InvalidDataException("Unknown host privacy evidence visibility");
    }

    private static bool SafeLabel(string value,int maximum)=>!string.IsNullOrWhiteSpace(value) &&
        value.Length<=maximum && !value.Any(char.IsControl);

    private static bool IsHex(string? value,int length)=>value is not null && value.Length==length &&
        value.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');
}
