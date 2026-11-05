using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.AccessControl;

internal static class WinsockRegistryScopeCases
{
    internal static void Run(Assembly library)
    {
        var scope = library.GetType("ProtectionLifecycle.WinsockRegistryScope", true)!;
        const BindingFlags shared = BindingFlags.Static | BindingFlags.NonPublic;
        var count = 0;
        void Check(bool ok) { if (!ok) throw new InvalidOperationException("Winsock registry scope differs"); count++; }
        object? Call(string method, params object?[] values)
        {
            try { return scope.GetMethod(method, shared)!.Invoke(null, values); }
            catch (TargetInvocationException ex) when (ex.InnerException is not null)
            { ExceptionDispatchInfo.Capture(ex.InnerException).Throw(); throw; }
        }
        void Refuse(Action action)
        {
            var refused = false; try { action(); } catch (InvalidDataException) { refused = true; }
            Check(refused);
        }
        foreach (var invalid in new[] { int.MinValue, 0, 1000, int.MaxValue }) Refuse(() => Call("Targets", invalid));
        foreach (var controlSet in new[] { 1, 999 })
        {
            var targets = (Array)Call("Targets", controlSet)!;
            Check(targets.Length == 25);
            var target = targets.GetValue(0)!.GetType();
            string PathOf(object value) => (string)target.GetProperty("Path")!.GetValue(value)!;
            int AccessOf(object value) => (int)target.GetProperty("Access")!.GetValue(value)!;
            Check(PathOf(targets.GetValue(0)!) == "" && AccessOf(targets.GetValue(0)!) == 0x20000);
            Check(targets.Cast<object>().Skip(1).All(t => AccessOf(t) == 0x20019 &&
                PathOf(t).StartsWith(@"SYSTEM\ControlSet" + controlSet.ToString("D3") + @"\Services\WinSock2\Parameters", StringComparison.Ordinal)));
            Check(targets.Cast<object>().Select(PathOf).Distinct(StringComparer.Ordinal).Count() == 25 &&
                targets.Cast<object>().All(t => !PathOf(t).Contains("Catalog_Entries\\", StringComparison.Ordinal)));
            Call("RequireExactTargets", controlSet, targets);
            foreach (var replacement in new[] { new object[] { "", 1 }, new object[] { @"SOFTWARE\Microsoft\Cryptography", 0x20000 } })
            {
                var changed = (Array)targets.Clone(); changed.SetValue(Activator.CreateInstance(target, replacement), 0);
                Refuse(() => Call("RequireExactTargets", controlSet, changed));
            }
            var reordered = (Array)targets.Clone();
            reordered.SetValue(targets.GetValue(2), 1); reordered.SetValue(targets.GetValue(1), 2);
            Refuse(() => Call("RequireExactTargets", controlSet, reordered));
            var shortList = Array.CreateInstance(target, targets.Length - 1);
            Array.Copy(targets, shortList, shortList.Length);
            Refuse(() => Call("RequireExactTargets", controlSet, shortList));
        }
        const string package = "S-1-15-2-1-2-3-4-5-6-7";
        string Canonical(string text) => new RawSecurityDescriptor(text).GetSddlForm(AccessControlSections.Owner | AccessControlSections.Access);
        foreach (var before in new[] { Canonical("O:SYD:P(A;;KA;;;SY)(A;;KR;;;BU)"), Canonical("O:SYD:AI(A;;KA;;;SY)(A;ID;KR;;;BU)") })
        foreach (var access in new[] { 0x20000, 0x20019 })
        {
            var after = (string)Call("AddReadAce", before, package, access)!;
            var original = new RawSecurityDescriptor(before); var descriptor = new RawSecurityDescriptor(after);
            Check(original.Owner == descriptor.Owner && original.ControlFlags == descriptor.ControlFlags);
            var dacl = descriptor.DiscretionaryAcl!;
            var added = dacl.Cast<GenericAce>().OfType<CommonAce>().Single(a => a.SecurityIdentifier.Value == package);
            Check(added.AccessMask == access && added.AceFlags == AceFlags.None && added.AceQualifier == AceQualifier.AccessAllowed);
            Check((added.AccessMask & 0x500D0026) == 0 && (access != 0x20000 || (added.AccessMask & 0x19) == 0));
            var retained = new RawAcl(dacl.Revision, dacl.Count - 1);
            foreach (GenericAce ace in dacl)
                if (ace is not CommonAce common || common.SecurityIdentifier.Value != package) retained.InsertAce(retained.Count, ace);
            descriptor.DiscretionaryAcl = retained;
            Check(descriptor.GetSddlForm(AccessControlSections.Owner | AccessControlSections.Access) == before);
            Refuse(() => Call("AddReadAce", after, package, access));
        }
        var baseline = Canonical("O:SYD:P(A;;KA;;;SY)(A;;KR;;;BU)");
        foreach (var invalid in new[] { 0, 1, 4, 0xF003F, unchecked((int)0x80000000) })
            Refuse(() => Call("AddReadAce", baseline, package, invalid));
        foreach (var invalid in new[] { "S-1-15-2-1", "S-1-15-2-2", "S-1-5-32-545" })
            Refuse(() => Call("AddReadAce", baseline, invalid, 0x20000));
        Console.WriteLine($"PASS {count} exact x64 Winsock target, root READ_CONTROL-only, non-inherited ACL preservation and unsafe-scope refusal checks. Memory policy only; no registry mutation, LPAC/network launch or lease activation.");
    }
}
