using System.Globalization;
using System.Security.AccessControl;
using System.Security.Principal;

namespace ProtectionLifecycle;

// Scope policy for a proposed original-owner registry lease. No OS mutation,
// capability, state record, process creation or automatic runtime activation.
// The installed compiler proved exact package leaf access without registryRead;
// predefined hive mapping still needs its own handle. Root READ_CONTROL carries
// neither value-query nor subkey-enumeration authority.
internal static class WinsockRegistryScope
{
    internal const int RootAccess = 0x20000, CatalogAccess = 0x20019;
    internal const int ProtocolEntries = 14, NamespaceEntries = 5;
    internal sealed record Target(string Path, int Access);

    // This candidate is deliberately tied to the reviewed x64 catalog shape.
    // Other catalog names/counts, 32-bit tools and catalog changes need review.
    internal static Target[] Targets(int controlSet)
    {
        if (controlSet is < 1 or > 999) throw WfpNative.Contract("WinsockControlSetRequired");
        var prefix = @"SYSTEM\ControlSet" + controlSet.ToString("D3", CultureInfo.InvariantCulture) +
            @"\Services\WinSock2\Parameters";
        var targets = new List<Target> { new("", RootAccess), new(prefix, CatalogAccess) };
        AddCatalog("Protocol_Catalog9", ProtocolEntries);
        AddCatalog("NameSpace_Catalog5", NamespaceEntries);
        return targets.ToArray();

        void AddCatalog(string catalog, int count)
        {
            var root = prefix + "\\" + catalog;
            targets.Add(new(root, CatalogAccess));
            targets.Add(new(root + @"\Catalog_Entries64", CatalogAccess));
            for (var i = 1; i <= count; i++)
                targets.Add(new(root + @"\Catalog_Entries64\" + i.ToString("D12", CultureInfo.InvariantCulture), CatalogAccess));
        }
    }

    internal static void RequireExactTargets(int controlSet, IReadOnlyList<Target> targets)
    {
        var expected = Targets(controlSet);
        if (targets.Count != expected.Length || !targets.SequenceEqual(expected))
            throw WfpNative.Contract("WinsockRegistryTargetsDiffer");
    }

    // Retain the existing system-owner, untrusted-writer and canonical ACL
    // policy. Replace only the newly added exact package ACE's access mask.
    // There is no inheritance, AAP/ARP/capability grant or value-write access.
    internal static string AddReadAce(string original, string packageSid, int access)
    {
        if (access is not (RootAccess or CatalogAccess))
            throw WfpNative.Contract("WinsockRegistryAccessMaskRefused");
        var granted = SessionTimeZoneReadAccess.AddReadAce(original, packageSid);
        var descriptor = new RawSecurityDescriptor(granted);
        var sid = new SecurityIdentifier(packageSid);
        var found = 0;
        foreach (GenericAce ace in descriptor.DiscretionaryAcl!)
        {
            if (ace is CommonAce common && common.SecurityIdentifier == sid)
            {
                if (common.AceQualifier != AceQualifier.AccessAllowed || common.AceFlags != AceFlags.None ||
                    common.AccessMask != CatalogAccess || common.IsCallback)
                    throw WfpNative.Contract("WinsockPackageAceShapeRefused");
                common.AccessMask = access;
                found++;
            }
        }
        if (found != 1) throw WfpNative.Contract("WinsockPackageAceCountRefused");
        return descriptor.GetSddlForm(AccessControlSections.Owner | AccessControlSections.Access);
    }
}
