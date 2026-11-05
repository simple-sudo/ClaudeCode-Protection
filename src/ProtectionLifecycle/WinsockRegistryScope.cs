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

    // Native OWNER|DACL queries, rather than the provider projection, qualified
    // a no-P/no-AI own-key grant/restore with unchanged existing child security.
    // Legacy roots must have explicit ACEs and representable control bits.
    // This admits only the separate fixed qualification; formal launch stays held.
    internal static void RequireSupportedRootSecurity(string security)
    {
        var descriptor=new RawSecurityDescriptor(security);var flags=descriptor.ControlFlags;
        const ControlFlags required=ControlFlags.DiscretionaryAclPresent|ControlFlags.SelfRelative;
        const ControlFlags supported=required|ControlFlags.DiscretionaryAclProtected|ControlFlags.DiscretionaryAclAutoInherited;
        if((flags&required)!=required || (flags&~supported)!=0 || descriptor.DiscretionaryAcl is null)
            throw WfpNative.Contract("WinsockRootControlNotSupported");
        if((flags&(ControlFlags.DiscretionaryAclProtected|ControlFlags.DiscretionaryAclAutoInherited))==0)
            foreach(GenericAce ace in descriptor.DiscretionaryAcl)
                if((ace.AceFlags&AceFlags.Inherited)!=0)throw WfpNative.Contract("LegacyWinsockInheritedAceNotQualified");
    }

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
    // The first IPv4 TCP match is reached after the stock Tcpip6 then Tcpip
    // mappings. No entire service/Parameters tree, transport child, Bluetooth,
    // adapter configuration, capability or device grant is included.
    internal static Target[] TransportTargets(int controlSet)
    {
        var existing=Targets(controlSet);
        var services=@"SYSTEM\ControlSet"+controlSet.ToString("D3",CultureInfo.InvariantCulture)+@"\Services\";
        return existing.Concat(new[]{new Target(services+@"Winsock\Parameters",CatalogAccess),
            new Target(services+@"Tcpip6\Parameters\Winsock",CatalogAccess),
            new Target(services+@"Tcpip\Parameters\Winsock",CatalogAccess)}).ToArray();
    }
    internal static void RequireExactTransportTargets(int controlSet,IReadOnlyList<Target> targets)
    {
        if(!targets.SequenceEqual(TransportTargets(controlSet)))throw WfpNative.Contract("WinsockTransportTargetsDiffer");
    }
    // The stock helper lookup also opens this separate migration map before
    // loading Tcpip6/Tcpip. Only its empty parent and these two GUID leaves are
    // included; other provider leaves and service configuration remain excluded.
    internal static Target[] ProviderTargets(int controlSet)
    {
        var existing=TransportTargets(controlSet);
        var providers=@"SYSTEM\ControlSet"+controlSet.ToString("D3",CultureInfo.InvariantCulture)+
            @"\Services\Winsock\Setup Migration\Providers";
        return existing.Concat(new[]{new Target(providers,CatalogAccess),
            new Target(providers+@"\Tcpip6",CatalogAccess),new Target(providers+@"\Tcpip",CatalogAccess)}).ToArray();
    }
    internal static void RequireExactProviderTargets(int controlSet,IReadOnlyList<Target> targets)
    {
        if(!targets.SequenceEqual(ProviderTargets(controlSet)))throw WfpNative.Contract("WinsockProviderTargetsDiffer");
    }
    internal static void RequireProviderSelection(string[] names)
    {
        var expected=new[]{"afunix","Psched","RFCOMM","Tcpip","Tcpip6","vmbus"}.Order(StringComparer.Ordinal);
        if(!names.Order(StringComparer.Ordinal).SequenceEqual(expected,StringComparer.Ordinal))
            throw WfpNative.Contract("WinsockProviderSelectionChanged");
    }
    internal static void RequireProviderId(byte[] bytes,int family)
    {
        if(family is not (2 or 23) || !bytes.SequenceEqual(Guid.Parse(family==23?
            "f9eab0c0-26d4-11d0-bbbf-00aa006c34e4":"e70f1aa0-ab8b-11cf-8ca3-00805f48a192").ToByteArray()))
            throw WfpNative.Contract("WinsockProviderIdChanged");
    }
    internal static void RequireTransportSelection(string[] names)
    {
        if(!names.SequenceEqual(new[]{"Tcpip6","Tcpip","vmbus","Psched","afunix","RFCOMM"},StringComparer.Ordinal))
            throw WfpNative.Contract("WinsockTransportSelectionChanged");
    }
    internal static void RequireTransportMapping(byte[] bytes,int family)
    {
        if(family is not (2 or 23) || bytes.Length!=104 || BitConverter.ToInt32(bytes,0)!=8 || BitConverter.ToInt32(bytes,4)!=3)
            throw WfpNative.Contract("WinsockTransportMappingShapeChanged");
        var pairs=new[]{(1,6),(1,0),(0,6),(2,17),(2,0),(0,17),(3,255),(3,0)};
        for(var i=0;i<pairs.Length;i++)
            if(BitConverter.ToInt32(bytes,8+i*12)!=family || BitConverter.ToInt32(bytes,12+i*12)!=pairs[i].Item1 ||
                BitConverter.ToInt32(bytes,16+i*12)!=pairs[i].Item2)throw WfpNative.Contract("WinsockTransportMappingChanged");
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
