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
    private readonly string stationSddl,desktopSddl;

    internal SessionZeroWindowPolicy(OwnedJobIntent job)
    {
        if(job.SchemaVersion!=3 || job.CreatorServiceSid is not { } creator)
            throw WfpNative.Contract("PrivateWindowsRequireCreatorJob");
        OwnedJobIntent.AssertCreatorSid(creator);
        // The child can query the name. Expose the ephemeral Job ID only.
        StationName="CpcTask."+Identifiers.Hex32(job.JobId);
        using var package=InstallationPackageSid.FromInstallationId(job.InstallationId);
        stationSddl=Build(SessionZeroWindowAccess.StationRights,StationPackageAccess);
        desktopSddl=Build(SessionZeroWindowAccess.DesktopRights,DesktopPackageAccess);

        string Build(uint ownerAccess,uint packageAccess)=>
            $"O:SYG:SYD:P(A;;0x{ownerAccess:X};;;SY)(A;;0x{(ReadControl|packageAccess):X};;;{creator})"+
            $"(A;;0x{packageAccess:X};;;{package.Value})S:(ML;;NW;;;LW)";
    }

    internal RawSecurityDescriptor Descriptor(bool station)=>new(station?stationSddl:desktopSddl);

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
