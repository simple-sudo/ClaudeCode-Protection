using System.Security.AccessControl;
using System.Security.Principal;

namespace ProtectionLifecycle;

// Candidate policy for NEW objects created by an original-owner LPAC child.
// Pure ACL transformation only: no token setter, native import, persistent
// resource grant or launch permit. Not connected to process creation yet.
internal static class OwnedObjectDefaultDaclPolicy
{
    private const int GenericAll=0x10000000;
    private const int GenericReadExecute=unchecked((int)0xa0000000);
    private const int MaximumAclBytes=2048;

    internal static byte[] AddExactOwnerAce(byte[] original,string ownerSid,string packageSid)
    {
        ArgumentNullException.ThrowIfNull(original);
        var owner=new SecurityIdentifier(ownerSid);
        var package=new SecurityIdentifier(packageSid);
        if(owner.Value!=ownerSid || !owner.IsAccountSid() || !owner.Value.StartsWith("S-1-5-21-",StringComparison.Ordinal) ||
            package.Value!=packageSid || package.BinaryLength!=40 || !package.Value.StartsWith("S-1-15-2-",StringComparison.Ordinal))
            throw new InvalidDataException("OwnedDefaultDaclExactUserAndPackageRequired");
        if(original.Length is <8 or >MaximumAclBytes)throw new InvalidDataException("OwnedDefaultDaclBounds");
        var acl=new RawAcl(original,0);
        if(acl.BinaryLength!=original.Length || acl.Revision!=GenericAcl.AclRevision || acl.Count!=4)
            throw new InvalidDataException("OwnedDefaultDaclOriginalShapeDiffers");
        var canonical=new byte[acl.BinaryLength];acl.GetBinaryForm(canonical,0);
        if(!canonical.AsSpan().SequenceEqual(original))throw new InvalidDataException("OwnedDefaultDaclNoncanonicalOriginal");
        RequireAce(acl[0],"S-1-5-32-544",GenericAll);
        RequireAce(acl[1],"S-1-5-18",GenericAll);
        if(acl[2] is not CommonAce logon || !IsLogonSid(logon.SecurityIdentifier))
            throw new InvalidDataException("OwnedDefaultDaclLogonRequired");
        RequireAce(logon,logon.SecurityIdentifier.Value,GenericReadExecute);
        RequireAce(acl[3],packageSid,GenericAll);
        // Preserve every original ACE byte and order; only the actual user
        // half gains access to this child's FUTURE default objects. The package
        // grant already exists and receives no new right.
        acl.InsertAce(3,new CommonAce(AceFlags.None,AceQualifier.AccessAllowed,GenericAll,owner,false,null));
        var result=new byte[acl.BinaryLength];acl.GetBinaryForm(result,0);
        if(result.Length>MaximumAclBytes)throw new InvalidDataException("OwnedDefaultDaclResultBounds");
        return result;
    }

    internal static bool IsExactOwnerAddition(byte[] observed,byte[] original,string ownerSid,string packageSid)
        =>observed.AsSpan().SequenceEqual(AddExactOwnerAce(original,ownerSid,packageSid));

    private static bool IsLogonSid(SecurityIdentifier sid)
    {
        var bytes=new byte[sid.BinaryLength];sid.GetBinaryForm(bytes,0);
        return sid.Value.StartsWith("S-1-5-5-",StringComparison.Ordinal) && bytes[1]==3;
    }

    private static void RequireAce(GenericAce entry,string sid,int access)
    {
        if(entry is not CommonAce ace || ace.AceFlags!=AceFlags.None || ace.AceQualifier!=AceQualifier.AccessAllowed ||
            ace.IsCallback || ace.OpaqueLength!=0 || ace.AccessMask!=access || ace.SecurityIdentifier.Value!=sid)
            throw new InvalidDataException("OwnedDefaultDaclOriginalAceDiffers");
    }
}
