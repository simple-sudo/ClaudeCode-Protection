using System.Security.AccessControl;

namespace ProtectionLifecycle;

// Contract for fresh noninteractive objects held by the trusted window owner.
// The station mask is a candidate. The desktop mask passed an ordinary LPAC control.
internal sealed class SessionZeroWindowPolicy
{
    private const uint StationPackageAccess=0x23; // Enumerate desktops, read attributes, use private global atoms.
    private const uint DesktopPackageAccess=0xc7; // Read/write objects, create windows/menus, enumerate.
    private const uint ReadControl=0x00020000;
    internal const string DesktopName="Task";
    internal string StationName {get;}
    internal string DesktopPath=>StationName+"\\"+DesktopName;
    internal static string DesktopPathForJob(string jobId)=>StationNameForJob(jobId)+"\\"+DesktopName;
    private static string StationNameForJob(string jobId)=>"CpcTask."+Identifiers.Hex32(jobId);
    private readonly string stationSddl,desktopSddl;

    internal static bool SupportsConsole(int schema)=>schema is PackageAssetCatalog.SessionZeroPrivateWindowConsoleSchema or
        PackageAssetCatalog.SessionZeroIdentitySurveySchema or PackageAssetCatalog.SessionZeroNetworkSurveySchema or
        PackageAssetCatalog.ReviewedProxyRouteSchema or PackageAssetCatalog.SessionZeroGitInitSchema;
    internal static bool RequiresStationReadControl(int schema)=>schema==PackageAssetCatalog.SessionZeroPrivateWindowReadControlSchema ||
        SupportsConsole(schema);

    internal SessionZeroWindowPolicy(OwnedJobIntent job,bool stationReadControl):this(job.InstallationId,job.JobId,CreatorFor(job),stationReadControl){}

    private static string CreatorFor(OwnedJobIntent job)
    {
        if(job.SchemaVersion!=3 || job.CreatorServiceSid is not { } creator)
            throw WfpNative.Contract("PrivateWindowsRequireCreatorJob");
        return creator;
    }

    internal SessionZeroWindowPolicy(string installationId,string jobId,string creator,bool stationReadControl)
    {
        OwnedJobIntent.AssertCreatorSid(creator);
        // The child can query the name. Expose the ephemeral Job ID only.
        StationName=StationNameForJob(jobId);
        using var package=InstallationPackageSid.FromInstallationId(installationId);
        stationSddl=Build(SessionZeroWindowAccess.StationRights,StationGrant(stationReadControl));
        desktopSddl=Build(SessionZeroWindowAccess.DesktopRights,DesktopPackageAccess);

        string Build(uint ownerAccess,uint packageAccess)=>
            $"O:SYG:SYD:P(A;;0x{ownerAccess:X};;;SY)(A;;0x{(ReadControl|packageAccess):X};;;{creator})"+
            $"(A;;0x{packageAccess:X};;;{package.Value})S:(ML;;NW;;;LW)";
    }

    internal RawSecurityDescriptor Descriptor(bool station)=>new(station?stationSddl:desktopSddl);

    // On the matched Windows build, the AppContainer window-station test
    // requests READ_CONTROL and access to the station's own global atoms.
    private static uint StationGrant(bool stationReadControl)=>StationPackageAccess|(stationReadControl?ReadControl:0);

    internal static void AssertGrants(SessionZeroWindowAccess.Evidence evidence,bool stationReadControl)
    {
        if(evidence.Station!=new SessionZeroWindowAccess.ObjectAccess(0,ReadControl|StationPackageAccess,StationGrant(stationReadControl)) ||
            evidence.Desktop!=new SessionZeroWindowAccess.ObjectAccess(0,ReadControl|DesktopPackageAccess,DesktopPackageAccess))
            throw WfpNative.Contract("CreatorPrivateWindowGrantsMismatch");
    }

    internal void AssertDescriptor(bool station,RawSecurityDescriptor actual)
    {
        var expected=Descriptor(station);
        if(!Equals(actual.Owner,expected.Owner) || !Equals(actual.Group,expected.Group) ||
            (actual.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0 ||
            !ExactAcl(actual.DiscretionaryAcl,expected.DiscretionaryAcl!) || !ExactAcl(actual.SystemAcl,expected.SystemAcl!))
            throw WfpNative.Contract("PrivateWindowObjectDescriptorMismatch");
    }

    private static bool ExactAcl(RawAcl? actual,RawAcl expected)
    {
        if(actual is null || actual.Count!=expected.Count || actual.Revision!=expected.Revision)return false;
        for(var i=0;i<expected.Count;i++)
            if(!actual[i].Equals(expected[i]))return false;
        return true;
    }
}
