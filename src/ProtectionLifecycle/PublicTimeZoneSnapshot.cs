using System.Reflection;
using System.Text;
using System.Text.Json;

namespace ProtectionLifecycle;

// Functional compatibility for the fixed managed worker, NOT an OS privacy
// boundary or an assertion that LPAC can read registry keys. No capability,
// host permission, clock, global timezone, native hook or foreign memory write.
// Private CoreLib layout is intentionally pinned; unsupported runtimes refuse.
internal sealed class PublicTimeZoneSnapshot
{
    internal const int MaxPayloadCharacters=16384;
    internal const string CoreLibModule="3e106481-9524-4ebf-a276-c71cb5b3f877";
    private sealed record TransitionData(bool Fixed,long TimeTicks,int Month,int Day,int Week,int DayOfWeek);
    private sealed record RuleData(long StartTicks,long EndTicks,long DeltaTicks,long BaseDeltaTicks,TransitionData Start,TransitionData End);
    private sealed record DefinitionData(string Id,long OffsetTicks,bool DisableDst,RuleData[] Rules);
    private sealed record PayloadData(int SchemaVersion,string SessionId,DefinitionData Definition);
    private readonly TimeZoneInfo zone;
    internal string TimeZoneId=>zone.Id;
    internal string Payload {get;}
    internal string SHA256 {get;}
    private PublicTimeZoneSnapshot(TimeZoneInfo zone,string payload)
    {this.zone=zone;Payload=payload;SHA256=Digest(payload);}

    internal static PublicTimeZoneSnapshot Capture(string sessionId)
    {
        RequirePinnedRuntime();_=Identifiers.Hex32(sessionId);
        var local=TimeZoneInfo.Local;_=PublicTimeZoneDefinition.PathFor(local.Id,"ZONE_DEFINITION");
        // Keep real offsets/rules and the selected ID. Localized display names
        // are unnecessary host UI information and are not sent to the worker.
        var value=TimeZoneInfo.CreateCustomTimeZone(local.Id,local.BaseUtcOffset,local.Id,local.Id,local.Id,
            local.GetAdjustmentRules(),!local.SupportsDaylightSavingTime);
        if(!value.HasSameRules(local))throw WfpNative.Contract("PublicTimeZoneRulesDiffer");
        var payload=JsonSerializer.Serialize(new PayloadData(2,sessionId,Describe(value)));
        RequireBounds(payload);
        var snapshot=new PublicTimeZoneSnapshot(value,payload);
        var roundtrip=Read(payload,snapshot.SHA256,sessionId,local.Id);
        if(!roundtrip.HasSameRules(local))throw WfpNative.Contract("PublicTimeZoneRoundtripDiffers");
        return snapshot;
    }
    internal void AssertCurrent()
    {
        RequirePinnedRuntime();var local=TimeZoneInfo.Local;
        if(local.Id!=zone.Id || !local.HasSameRules(zone) || Digest(Payload)!=SHA256)
            throw WfpNative.Contract("PublicTimeZoneOwnerSnapshotChanged");
        // Managed-cache consistency only; original environment qualification
        // remains responsible for native timezone drift and formal admission.
    }
    private static string Digest(string payload)=>Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
        Encoding.UTF8.GetBytes("CPC_PUBLIC_TIMEZONE_V2\n"+payload)));
    private static void RequireBounds(string payload)
    {
        if(payload.Length is <2 or >MaxPayloadCharacters || payload.Contains('\0') || Encoding.UTF8.GetByteCount(payload)>MaxPayloadCharacters)
            throw WfpNative.Contract("PublicTimeZonePayloadBounds");
    }
    private static TimeZoneInfo Read(string payload,string digest,string sessionId,string expectedId)
    {
        RequireBounds(payload);_=Identifiers.Hex32(sessionId);_=Identifiers.Hash(digest);
        _=PublicTimeZoneDefinition.PathFor(expectedId,"ZONE_DEFINITION");
        if(Digest(payload)!=digest)throw WfpNative.Contract("PublicTimeZonePayloadDigestDiffers");
        using var json=JsonDocument.Parse(payload,new JsonDocumentOptions{MaxDepth=6});
        StrictJson.Fields(json.RootElement,"SchemaVersion","SessionId","Definition");
        var definition=json.RootElement.GetProperty("Definition");
        StrictJson.Fields(definition,"Id","OffsetTicks","DisableDst","Rules");
        var rules=definition.GetProperty("Rules");
        if(rules.ValueKind!=JsonValueKind.Array || rules.GetArrayLength()>128)throw WfpNative.Contract("PublicTimeZoneRuleBounds");
        foreach(var rule in rules.EnumerateArray())
        {
            StrictJson.Fields(rule,"StartTicks","EndTicks","DeltaTicks","BaseDeltaTicks","Start","End");
            foreach(var name in new[]{"Start","End"})
                StrictJson.Fields(rule.GetProperty(name),"Fixed","TimeTicks","Month","Day","Week","DayOfWeek");
        }
        var data=JsonSerializer.Deserialize<PayloadData>(payload)??throw WfpNative.Contract("PublicTimeZonePayloadMissing");
        if(data.SchemaVersion!=2 || data.SessionId!=sessionId || data.Definition is null || data.Definition.Id!=expectedId ||
            data.Definition.Rules is null || data.Definition.Rules.Any(rule=>rule is null))
            throw WfpNative.Contract("PublicTimeZonePayloadBindingDiffers");
        // CoreLib's string serializer parses transition times with missing date
        // components. That invokes DateTime.Now before Local has been bound and
        // can open the registry in LPAC. Construct only from validated integers.
        var value=TimeZoneInfo.CreateCustomTimeZone(expectedId,new TimeSpan(data.Definition.OffsetTicks),expectedId,expectedId,expectedId,
            data.Definition.Rules.Select(Restore).ToArray(),data.Definition.DisableDst);
        if(value.Id!=expectedId || value.DisplayName!=expectedId || value.StandardName!=expectedId ||
            (value.DaylightName!=expectedId && (value.SupportsDaylightSavingTime || value.DaylightName!="")))
            throw WfpNative.Contract("PublicTimeZoneDefinitionDiffers");
        return value;
    }
    private static DefinitionData Describe(TimeZoneInfo value)
    {
        var rules=value.GetAdjustmentRules();
        if(rules.Length>128)throw WfpNative.Contract("PublicTimeZoneRuleBounds");
        var described=rules.Select(rule=>new RuleData(rule.DateStart.Ticks,rule.DateEnd.Ticks,rule.DaylightDelta.Ticks,rule.BaseUtcOffsetDelta.Ticks,
            DescribeTransition(rule.DaylightTransitionStart),DescribeTransition(rule.DaylightTransitionEnd))).ToArray();
        // Unsupported private rule forms must refuse at the owner. Never lose
        // rule information merely to fit the public construction overload.
        if(rules.Where((rule,index)=>!rule.Equals(Restore(described[index]))).Any())throw WfpNative.Contract("PublicTimeZoneRuleNotRepresentable");
        return new(value.Id,value.BaseUtcOffset.Ticks,!value.SupportsDaylightSavingTime,described);
    }
    private static TransitionData DescribeTransition(TimeZoneInfo.TransitionTime value)=>
        new(value.IsFixedDateRule,value.TimeOfDay.Ticks,value.Month,value.Day,value.Week,(int)value.DayOfWeek);
    private static TimeZoneInfo.AdjustmentRule Restore(RuleData value)=>TimeZoneInfo.AdjustmentRule.CreateAdjustmentRule(
        new DateTime(value.StartTicks,DateTimeKind.Unspecified),new DateTime(value.EndTicks,DateTimeKind.Unspecified),new TimeSpan(value.DeltaTicks),
        RestoreTransition(value.Start),RestoreTransition(value.End),new TimeSpan(value.BaseDeltaTicks));
    private static TimeZoneInfo.TransitionTime RestoreTransition(TransitionData value)
    {
        if(value is null)throw WfpNative.Contract("PublicTimeZoneTransitionMissing");
        var time=new DateTime(value.TimeTicks,DateTimeKind.Unspecified);
        var result=value.Fixed?TimeZoneInfo.TransitionTime.CreateFixedDateRule(time,value.Month,value.Day):
            TimeZoneInfo.TransitionTime.CreateFloatingDateRule(time,value.Month,value.Week,(DayOfWeek)value.DayOfWeek);
        if(DescribeTransition(result)!=value)throw WfpNative.Contract("PublicTimeZoneTransitionNotCanonical");
        return result;
    }
    private static void RequirePinnedRuntime()
    {
        if(!Environment.Is64BitProcess || typeof(TimeZoneInfo).Assembly.ManifestModule.ModuleVersionId!=Guid.Parse(CoreLibModule))
            throw new PlatformNotSupportedException("PublicTimeZoneRuntimeNotQualified");
    }
    internal static void ApplyForFixedWorker(string payload,string digest,string sessionId,string expectedId)
    {
        RequirePinnedRuntime();var value=Read(payload,digest,sessionId,expectedId);
        const BindingFlags flags=BindingFlags.NonPublic|BindingFlags.Static;
        var cacheField=typeof(TimeZoneInfo).GetField("s_cachedData",flags)??throw WfpNative.Contract("PublicTimeZoneCacheLayoutDiffers");
        var cache=cacheField.GetValue(null)??throw WfpNative.Contract("PublicTimeZoneCacheMissing");
        var type=cache.GetType();
        if(type.Assembly!=typeof(TimeZoneInfo).Assembly || type.FullName!="System.TimeZoneInfo+CachedData")
            throw WfpNative.Contract("PublicTimeZoneCacheTypeDiffers");
        var localField=type.GetField("_localTimeZone",BindingFlags.NonPublic|BindingFlags.Instance);
        if(localField is null || localField.FieldType!=typeof(TimeZoneInfo) || localField.IsInitOnly)
            throw WfpNative.Contract("PublicTimeZoneLocalLayoutDiffers");
        lock(cache)
        {
            if(localField.GetValue(cache) is TimeZoneInfo existing)
            {
                if(existing.Id!=value.Id || !existing.HasSameRules(value))throw WfpNative.Contract("PublicTimeZoneExistingViewDiffers");
            }
            else localField.SetValue(cache,value);
            if(!ReferenceEquals(cacheField.GetValue(null),cache) || TimeZoneInfo.Local.Id!=value.Id || !TimeZoneInfo.Local.HasSameRules(value))
                throw WfpNative.Contract("PublicTimeZoneCacheBindingLost");
        }
        // DateTime.Now still obtains the current-year native Windows offset.
        // Reject disagreement with the supplied real calendar, not mask it.
        var before=DateTime.UtcNow;var current=DateTime.Now.ToUniversalTime();var after=DateTime.UtcNow;
        if(current<before.AddSeconds(-1) || current>after.AddSeconds(1))throw WfpNative.Contract("PublicTimeZoneNativeClockDisagrees");
    }
}
