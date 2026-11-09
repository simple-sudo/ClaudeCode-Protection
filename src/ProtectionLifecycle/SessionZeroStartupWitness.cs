using System.Globalization;
using System.Text;

namespace ProtectionLifecycle;

// Fixed installed diagnostic. The creator only receives a purpose bit, never
// a pathname, arguments, environment overrides, or a second creation request.
internal static class SessionZeroStartupWitness
{
    internal const string Scope="FIXED_INDEPENDENT_STARTUP_WITNESS_FULL_QUARANTINE";
    private static readonly string[] Checkpoints=[
        "ENTRY","BEFORE_USER32","AFTER_USER32","BEFORE_DESKTOP","AFTER_DESKTOP",
        "BEFORE_SHELL32","AFTER_SHELL32","BEFORE_UCRT","AFTER_UCRT"
    ];

    internal static string ReviewedImage(FixedLayout layout,VerifiedVersion version)
    {
        if(version.Package.SchemaVersion!=PackageAssetCatalog.SessionZeroStartupWitnessSchema ||
            !version.Package.Files.Any(file=>file.Asset.Id==PackageAssetCatalog.SessionZeroStartupWitnessId))
            throw WfpNative.Contract("StartupWitnessRequiresReviewedAsset");
        return WindowsPathSeal.Child(layout.Version(version.Package.Release),PackageAssetCatalog.SessionZeroStartupWitnessPath);
    }

    internal sealed record Observation(string Status,string? LastCheckpoint,uint? Win32Error);

    internal static Observation Observe(uint? exit,OfflineConsoleOutput? stdout,OfflineConsoleOutput? stderr)
    {
        if(exit is null || stdout is not {Overflow:false} || stderr is not {Overflow:false,Bytes.Length:0})
            return new("CAPTURE_UNAVAILABLE",null,null);
        if(stdout.Bytes.Length>256 || stdout.Bytes.Any(value=>value>127))
            return new("OUTPUT_REJECTED",null,null);
        if(stdout.Bytes.Length==0)
            return new(exit==0?"OUTPUT_REJECTED":"NO_ENTRY_CHECKPOINT",null,null);

        var lines=Encoding.ASCII.GetString(stdout.Bytes).Split('\n');
        var count=0;
        while(count<Checkpoints.Length && count<lines.Length-1 && lines[count]==Checkpoints[count])count++;
        var last=count==0?null:Checkpoints[count-1];
        if(count==Checkpoints.Length && lines.Length==count+1 && lines[^1].Length==0 && exit==0)
            return new("ALL_CHECKPOINTS_OBSERVED",last,null);
        if(count>0 && lines.Length==count+1 && lines[^1].Length==0 && exit>=0xc0000000)
            return new("NATIVE_EXIT_AFTER_CHECKPOINT",last,null);
        if(count>0 && lines.Length==count+2 && lines[^1].Length==0 &&
            (exit,count) is (65,2) or (66 or 67,4) or (68,6) or (69,8) &&
            lines[count] is {Length:16} error && error.StartsWith("WIN32=0x",StringComparison.Ordinal) &&
            uint.TryParse(error.AsSpan(8),NumberStyles.AllowHexSpecifier,CultureInfo.InvariantCulture,out var code))
            return new("WIN32_FAILURE_AFTER_CHECKPOINT",last,code);
        return new("OUTPUT_REJECTED",null,null);
    }
}
