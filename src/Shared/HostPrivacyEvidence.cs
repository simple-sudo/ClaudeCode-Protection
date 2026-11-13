namespace ClaudeCodeProtection.Workspaces;

internal enum HostPrivacyEvidenceVisibility { HostReferenceOnly, RestrictedActor }
internal enum HostPrivacyEvidenceOutcome { ContentRead, AccessDenied, Unknown, NotRun, TargetAbsent }
internal enum HostPrivacyEvidenceClass { HostReferenceOnly, ConfirmedDirect, DeniedConfirmed, Unknown, NotRun, TargetAbsent }

internal sealed record HostPrivacyEvidenceRecord(
    string EvidenceId,string SessionId,string ActorId,string Target,string Field,string Value,
    string SourceId,string SourceFamily,string Claim,string CorrelationKey,
    HostPrivacyEvidenceVisibility Visibility,HostPrivacyEvidenceOutcome Outcome,
    bool OwnerSealed,bool ContentVerified,bool RequiredP0,int? NativeError,
    DateTimeOffset ObservedAtUtc,DateTimeOffset? ExpiresAtUtc,string ArtifactSHA256);

internal sealed record HostPrivacyEvidenceAssessment(
    string EvidenceId,string Target,string Field,HostPrivacyEvidenceClass Classification,
    bool RequiredP0,string SourceId,string SourceFamily,string? Value);

internal sealed record HostPrivacyInference(
    string Claim,string CorrelationKey,string[] EvidenceIds,string[] SourceFamilies);

internal sealed record HostPrivacyEvidenceProfile(
    string SessionId,DateTimeOffset EvaluatedAtUtc,HostPrivacyEvidenceAssessment[] Assessments,
    HostPrivacyInference[] Inferences,bool P0Exposure,bool P0Unknown);

internal static class HostPrivacyEvidenceRules
{
    internal static HostPrivacyEvidenceProfile Evaluate(string session,string actor,
        IEnumerable<HostPrivacyEvidenceRecord> evidence,DateTimeOffset now,IEnumerable<string> requiredP0Targets)
    {
        if(!IsHex(session,32) || string.IsNullOrWhiteSpace(actor) || actor.Length>256 ||
            evidence is null || requiredP0Targets is null || now.Offset!=TimeSpan.Zero)
            throw new InvalidDataException("Host privacy evidence context differs");
        var requiredTargets=requiredP0Targets.ToArray();
        if(requiredTargets.Length is <1 or >1024 || requiredTargets.Any(target=>string.IsNullOrWhiteSpace(target) || target.Length>256) ||
            requiredTargets.Distinct(StringComparer.Ordinal).Count()!=requiredTargets.Length)
            throw new InvalidDataException("Required P0 target matrix differs");
        var requiredSet=requiredTargets.ToHashSet(StringComparer.Ordinal);
        var records=evidence.ToArray();
        if(records.Length>4096)throw new InvalidDataException("Host privacy evidence count exceeds limit");
        var ids=new HashSet<string>(StringComparer.Ordinal);
        var sourceObservations=new HashSet<string>(StringComparer.Ordinal);
        var assessments=new List<HostPrivacyEvidenceAssessment>();
        var inferenceInputs=new List<HostPrivacyEvidenceRecord>();
        foreach(var item in records)
        {
            Validate(item,session,actor,now);
            if(item.RequiredP0!=requiredSet.Contains(item.Target))
                throw new InvalidDataException("Evidence P0 severity differs from trusted target matrix");
            if(!ids.Add(item.EvidenceId))throw new InvalidDataException("Duplicate host privacy evidence id");
            if(item.Visibility==HostPrivacyEvidenceVisibility.HostReferenceOnly)
            {
                assessments.Add(new(item.EvidenceId,item.Target,item.Field,HostPrivacyEvidenceClass.HostReferenceOnly,
                    item.RequiredP0,item.SourceId,item.SourceFamily,null));
                continue;
            }
            var sourceKey=string.Join("\u001f",item.ActorId,item.SourceFamily,item.SourceId,item.Field);
            if(!sourceObservations.Add(sourceKey))continue;
            var classification=Classify(item,now);
            assessments.Add(new(item.EvidenceId,item.Target,item.Field,classification,item.RequiredP0,
                item.SourceId,item.SourceFamily,classification==HostPrivacyEvidenceClass.ConfirmedDirect?item.Value:null));
            if(classification==HostPrivacyEvidenceClass.ConfirmedDirect && item.Claim.Length>0 && item.CorrelationKey.Length>0)
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
        var p0Exposure=assessments.Any(item=>item.RequiredP0 && item.Classification==HostPrivacyEvidenceClass.ConfirmedDirect);
        var p0Unknown=requiredTargets.Any(target=>{
                var targetRecords=records.Where(item=>item.RequiredP0 && item.Target==target).ToArray();
                var targetResults=assessments.Where(item=>item.RequiredP0 && item.Target==target).ToArray();
                if(targetRecords.Length==0)return true;
                return !targetResults.Any(item=>item.Classification is HostPrivacyEvidenceClass.DeniedConfirmed or HostPrivacyEvidenceClass.ConfirmedDirect) ||
                    targetResults.Any(item=>item.Classification is HostPrivacyEvidenceClass.Unknown or HostPrivacyEvidenceClass.NotRun or HostPrivacyEvidenceClass.TargetAbsent) ||
                    targetRecords.Any(item=>item.Visibility==HostPrivacyEvidenceVisibility.HostReferenceOnly) &&
                        !targetRecords.Any(item=>item.Visibility==HostPrivacyEvidenceVisibility.RestrictedActor);
            });
        return new(session,now,assessments.ToArray(),inferences,p0Exposure,p0Unknown);
    }

    internal static HostPrivacyEvidenceClass Classify(HostPrivacyEvidenceRecord item,DateTimeOffset now)
    {
        if(item.Visibility==HostPrivacyEvidenceVisibility.HostReferenceOnly)return HostPrivacyEvidenceClass.HostReferenceOnly;
        if(item.ExpiresAtUtc is { } expiry && (expiry.Offset!=TimeSpan.Zero || expiry<=now))
            return HostPrivacyEvidenceClass.Unknown;
        return item.Outcome switch {
            HostPrivacyEvidenceOutcome.ContentRead when item.OwnerSealed && item.ContentVerified &&
                item.Value.Length>0 && item.NativeError is null => HostPrivacyEvidenceClass.ConfirmedDirect,
            HostPrivacyEvidenceOutcome.AccessDenied when item.OwnerSealed && item.Value.Length==0 &&
                item.NativeError==5 && !item.ContentVerified => HostPrivacyEvidenceClass.DeniedConfirmed,
            HostPrivacyEvidenceOutcome.TargetAbsent when item.OwnerSealed && item.Value.Length==0 &&
                item.NativeError is 2 or 3 && !item.ContentVerified => HostPrivacyEvidenceClass.TargetAbsent,
            HostPrivacyEvidenceOutcome.NotRun=>HostPrivacyEvidenceClass.NotRun,
            _=>HostPrivacyEvidenceClass.Unknown
        };
    }

    private static void Validate(HostPrivacyEvidenceRecord item,string session,string actor,DateTimeOffset now)
    {
        if(item is null || !IsHex(item.EvidenceId,32) || item.SessionId!=session ||
            string.IsNullOrWhiteSpace(item.Target) || item.Target.Length>256 ||
            string.IsNullOrWhiteSpace(item.Field) || item.Field.Length>256 ||
            item.Value is null || item.Value.Length>65536 ||
            string.IsNullOrWhiteSpace(item.SourceId) || item.SourceId.Length>256 ||
            string.IsNullOrWhiteSpace(item.SourceFamily) || item.SourceFamily.Length>128 ||
            item.ObservedAtUtc.Offset!=TimeSpan.Zero || item.ObservedAtUtc>now ||
            !IsHex(item.ArtifactSHA256,64))
            throw new InvalidDataException("Host privacy evidence shape or provenance differs");
        if(item.Visibility==HostPrivacyEvidenceVisibility.RestrictedActor)
        {
            if(item.ActorId!=actor || !item.OwnerSealed)
                throw new InvalidDataException("Restricted evidence lacks owner actor attestation");
        }
        else if(item.Visibility==HostPrivacyEvidenceVisibility.HostReferenceOnly)
        {
            if(item.ActorId.Length!=0 || item.Outcome!=HostPrivacyEvidenceOutcome.ContentRead ||
                !item.OwnerSealed || !item.ContentVerified || item.Value.Length==0)
                throw new InvalidDataException("Host reference evidence shape differs");
        }
        else throw new InvalidDataException("Unknown host privacy evidence visibility");
        if(item.Claim.Length>256 || item.CorrelationKey.Length>1024)
            throw new InvalidDataException("Host privacy correlation bounds differ");
    }

    private static bool IsHex(string value,int length)=>value.Length==length &&
        value.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');
}
