using System.Security.AccessControl;
using System.Security.Principal;

namespace ClaudeProtection.Storage;

// Shared by the daily CLI and GUI. User data never belongs beside installed
// executables, and these operations are never an elevated maintenance channel.
internal static class UserDataPaths
{
    internal static void AssertUserContext()
    {
        using var identity=WindowsIdentity.GetCurrent();
        if(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator) || identity.User is null || identity.User.IsWellKnown(WellKnownSidType.LocalSystemSid))
            throw new InvalidOperationException("Daily configuration maintenance requires the ordinary user's context");
    }
    private static string Root
    {
        get
        {
            AssertUserContext();var local=Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if(string.IsNullOrWhiteSpace(local) || !Path.IsPathFullyQualified(local))throw new InvalidOperationException("User data folder unavailable");
            var path=Path.Combine(local,"ClaudeCodeProtection");EnsurePrivate(path);return path;
        }
    }
    internal static string ProxyBackups=>Child("proxy-backups");
    internal static string Reports=>Child("reports");
    private static string Child(string leaf){var path=Path.Combine(Root,leaf);EnsurePrivate(path);return path;}
    private static void EnsurePrivate(string path)
    {
        // Reject redirects rather than silently moving private data. A missing
        // or inaccessible existing ancestor is an error, never a new location.
        for(var ancestor=Directory.GetParent(path);ancestor is not null;ancestor=ancestor.Parent)
            if((ancestor.Attributes&FileAttributes.ReparsePoint)!=0)throw new InvalidDataException("User data ancestor is redirected");
        using var identity=WindowsIdentity.GetCurrent();var user=identity.User??throw new InvalidOperationException("User identity missing");
        var subjects=new[]{user,new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null)};
        var security=new DirectorySecurity();security.SetOwner(user);security.SetAccessRuleProtection(true,false);
        foreach(var sid in subjects)security.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        var directory=new DirectoryInfo(path);directory.Create(security); // Initial ACL; existing directories are not normalized.
        if((directory.Attributes&FileAttributes.ReparsePoint)!=0)throw new InvalidDataException("User data directory is redirected");
        var actual=directory.GetAccessControl(AccessControlSections.Owner|AccessControlSections.Access);
        if(!actual.AreAccessRulesProtected || !user.Equals(actual.GetOwner(typeof(SecurityIdentifier))))throw new InvalidDataException("User data owner/ACL differs");
        var remaining=new HashSet<string>(subjects.Select(s=>s.Value),StringComparer.Ordinal);
        foreach(FileSystemAccessRule rule in actual.GetAccessRules(true,true,typeof(SecurityIdentifier)))
            if(rule.IsInherited || rule.AccessControlType!=AccessControlType.Allow || rule.FileSystemRights!=FileSystemRights.FullControl ||
                rule.InheritanceFlags!=(InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit) || rule.PropagationFlags!=PropagationFlags.None || !remaining.Remove(rule.IdentityReference.Value))
                throw new InvalidDataException("User data grant differs");
        if(remaining.Count!=0)throw new InvalidDataException("User data grants incomplete");
    }
}
