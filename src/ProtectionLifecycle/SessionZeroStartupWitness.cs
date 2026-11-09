using System.Globalization;
using System.Text;
using System.Text.Json.Serialization;

namespace ProtectionLifecycle;

// Fixed installed diagnostic. The creator only receives a purpose bit, never
// a pathname, arguments, environment overrides, or a second creation request.
internal static class SessionZeroStartupWitness
{
    internal const string Scope="FIXED_INDEPENDENT_STARTUP_WITNESS_FULL_QUARANTINE";
    internal static bool UsesBranchTrace(int schema)=>schema is PackageAssetCatalog.SessionZeroStartupBranchSchema or PackageAssetCatalog.SessionZeroWindowAccessSchema;
    private static readonly string[] Checkpoints=[
        "ENTRY","BEFORE_USER32","AFTER_USER32","BEFORE_DESKTOP","AFTER_DESKTOP",
        "BEFORE_SHELL32","AFTER_SHELL32","BEFORE_UCRT","AFTER_UCRT"
    ];
    private static readonly string[] DiagnosticFields=[
        "WIN32K_QUERY","WIN32K_BLOCKED","USER32_FILE","USER32_MAP","WIN32U_LOAD","GDI32_LOAD","GDI32FULL_LOAD"
    ];

    internal static string ReviewedImage(FixedLayout layout,VerifiedVersion version)
    {
        var schema=version.Package.SchemaVersion;
        if(!(schema is PackageAssetCatalog.SessionZeroStartupWitnessSchema or PackageAssetCatalog.SessionZeroStartupDiagnosticsSchema || UsesBranchTrace(schema)) ||
            !version.Package.Files.Any(file=>file.Asset.Id==PackageAssetCatalog.SessionZeroStartupWitnessId))
            throw WfpNative.Contract("StartupWitnessRequiresReviewedAsset");
        return WindowsPathSeal.Child(layout.Version(version.Package.Release),PackageAssetCatalog.SessionZeroStartupWitnessPath);
    }

    internal sealed record Win32kObservation(uint QueryError,bool? Blocked);
    internal sealed record SystemCallFilterObservation(uint QueryError,uint? FilterId);
    internal sealed record ImageDiagnostics(uint Win32kQueryError,bool? Win32kBlocked,uint User32FileError,uint? User32MapError,
        uint Win32uLoadError,uint Gdi32LoadError,uint Gdi32FullLoadError);
    internal sealed record Observation(string Status,string? LastCheckpoint,uint? Win32Error)
    {
        [JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]
        public Win32kObservation? BeforeResumeWin32k {get;init;}
        [JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]
        public SystemCallFilterObservation? BeforeResumeSystemCallFilter {get;init;}
        [JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]
        public SessionZeroStartupBranchTrace.Evidence? BranchTrace {get;init;}
        [JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]
        public SessionZeroWindowAccess.Evidence? CreatorWindowAccess {get;init;}
        [JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]
        public ImageDiagnostics? Diagnostics {get;init;}
    }

    internal static Observation Observe(int packageSchema,uint? exit,OfflineConsoleOutput? stdout,OfflineConsoleOutput? stderr)
    {
        var hasDiagnostics=packageSchema==PackageAssetCatalog.SessionZeroStartupDiagnosticsSchema;
        var branchTrace=UsesBranchTrace(packageSchema);
        if(exit is null || stdout is not {Overflow:false} || stderr is not {Overflow:false,Bytes.Length:0})
            return new("CAPTURE_UNAVAILABLE",null,null);
        if(stdout.Bytes.Length>(hasDiagnostics?384:256) || stdout.Bytes.Any(value=>value>127))
            return new("OUTPUT_REJECTED",null,null);
        if(stdout.Bytes.Length==0)
            return new(exit==0?"OUTPUT_REJECTED":"NO_ENTRY_CHECKPOINT",null,null);

        var lines=Encoding.ASCII.GetString(stdout.Bytes).Split('\n');
        if(lines[^1].Length!=0)return new("OUTPUT_REJECTED",null,null);
        var payload=lines.AsSpan(0,lines.Length-1);
        var count=0;
        while(count<Checkpoints.Length && count<payload.Length && payload[count]==Checkpoints[count])count++;
        var last=count==0?null:Checkpoints[count-1];
        var tail=payload[count..];
        if(branchTrace)
        {
            if((exit,count) is (0,3) && tail.IsEmpty)return new("FIRST_USER32_LOAD_SUCCEEDED",last,null);
            if((exit,count) is (71,1) && tail.IsEmpty)return new("ATTACHMENT_WAIT_EXPIRED",last,null);
            if((exit,count) is (65,2) && tail.Length==1 && ReadValue(tail[0],"WIN32",out var error))
                return new("WIN32_FAILURE_AFTER_CHECKPOINT",last,error);
            return count is >0 and <=3 && tail.IsEmpty && exit>=0xc0000000?
                new("NATIVE_EXIT_AFTER_CHECKPOINT",last,null):new("OUTPUT_REJECTED",null,null);
        }
        if(count==Checkpoints.Length && exit==0)
            return Terminal("ALL_CHECKPOINTS_OBSERVED",last,null,tail,hasDiagnostics);
        if(count>0 && tail.IsEmpty && exit>=0xc0000000)
            return new("NATIVE_EXIT_AFTER_CHECKPOINT",last,null);
        if(!tail.IsEmpty &&
            (exit,count) is (65,2) or (66 or 67,4) or (68,6) or (69,8) &&
            ReadValue(tail[0],"WIN32",out var code))
            return Terminal("WIN32_FAILURE_AFTER_CHECKPOINT",last,code,tail[1..],hasDiagnostics && exit==65);
        return new("OUTPUT_REJECTED",null,null);
    }

    private static Observation Terminal(string status,string? last,uint? code,ReadOnlySpan<string> tail,bool hasDiagnostics)
    {
        if(!hasDiagnostics)return tail.IsEmpty?new(status,last,code):new("OUTPUT_REJECTED",null,null);
        var diagnostics=ReadDiagnostics(tail);
        return diagnostics is null?new("DIAGNOSTICS_REJECTED",last,code):new(status,last,code){Diagnostics=diagnostics};
    }

    private static ImageDiagnostics? ReadDiagnostics(ReadOnlySpan<string> tail)
    {
        if(tail.Length!=DiagnosticFields.Length)return null;
        Span<uint> values=stackalloc uint[DiagnosticFields.Length];
        for(var i=0;i<values.Length;i++)
            if(!ReadValue(tail[i],DiagnosticFields[i],out values[i]))return null;
        var query=values[0];var blocked=values[1];var file=values[2];var map=values[3];
        if((query==0?blocked>1:blocked!=uint.MaxValue) || (file==0)==(map==uint.MaxValue))return null;
        return new(query,query==0?blocked==1:null,file,file==0?map:null,values[4],values[5],values[6]);
    }

    private static bool ReadValue(string line,string field,out uint value)
    {
        value=0;
        return line.Length==field.Length+11 && line.StartsWith(field,StringComparison.Ordinal) &&
            line.AsSpan(field.Length,3).SequenceEqual("=0x") &&
            uint.TryParse(line.AsSpan(field.Length+3),NumberStyles.AllowHexSpecifier,CultureInfo.InvariantCulture,out value);
    }
}
