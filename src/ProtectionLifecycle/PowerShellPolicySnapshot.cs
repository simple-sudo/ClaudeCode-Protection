using System.Reflection;
using Microsoft.Win32;

namespace ProtectionLifecycle;

// PowerShell 7.4.22 queries GPO before its JSON settings, and its native CLI
// does not handle denied HKCU access. Supply negative cache entries ONLY after
// the original Broker has observed actual absence of every relevant key.
// Present, inaccessible, changed or unsupported policy is never treated absent.
internal static class PowerShellPolicySnapshot
{
    private static readonly (string Name,string Key)[] policies={
        ("ScriptExecution",@"Software\Policies\Microsoft\PowerShellCore"),
        ("ScriptBlockLogging",@"Software\Policies\Microsoft\PowerShellCore\ScriptBlockLogging"),
        ("ModuleLogging",@"Software\Policies\Microsoft\PowerShellCore\ModuleLogging"),
        ("ProtectedEventLogging",@"Software\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging"),
        ("Transcription",@"Software\Policies\Microsoft\PowerShellCore\Transcription"),
        ("UpdatableHelp",@"Software\Policies\Microsoft\PowerShellCore\UpdatableHelp"),
        ("ConsoleSessionConfiguration",@"Software\Policies\Microsoft\PowerShellCore\ConsoleSessionConfiguration")};
    private static readonly string[] fallback={@"Software\Policies\Microsoft\Windows\PowerShell",
        @"Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",@"Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
        @"Software\Policies\Microsoft\Windows\PowerShell\Transcription",@"Software\Policies\Microsoft\Windows\PowerShell\UpdatableHelp"};
    internal static void AssertActuallyAbsent()
    {
        foreach(var hive in new[]{RegistryHive.CurrentUser,RegistryHive.LocalMachine})
        {
            using var root=RegistryKey.OpenBaseKey(hive,RegistryView.Registry64);
            foreach(var path in policies.Select(p=>p.Key).Concat(fallback))
            {
                using var key=root.OpenSubKey(path,false);
                if(key is not null)throw WfpNative.Contract("PresentPowerShellRegistryPolicyNeedsSupportedSnapshot");
            }
        }
    }
    internal static void SeedConfirmedAbsence(Assembly automation)
    {
        if(automation.GetName().Name!="System.Management.Automation" || automation.GetName().Version!=new Version(7,4,6,500))
            throw WfpNative.Contract("PowerShellPolicyCacheAssemblyVersionUnreviewed");
        var utils=automation.GetType("System.Management.Automation.Utils",true)!;
        var keys=(System.Collections.IDictionary?)utils.GetField("GroupPolicyKeys",BindingFlags.Static|BindingFlags.NonPublic)?.GetValue(null)
            ??throw WfpNative.Contract("PowerShellPolicyKeyContractMissing");
        if(keys.Count!=policies.Length || policies.Any(p=>keys[p.Name] as string!=p.Key))throw WfpNative.Contract("PowerShellPolicyKeyContractChanged");
        var cache=utils.GetField("s_cachedPoliciesFromRegistry",BindingFlags.Static|BindingFlags.NonPublic)?.GetValue(null)
            ??throw WfpNative.Contract("PowerShellPolicyCacheContractMissing");
        var type=cache.GetType();var arguments=type.GetGenericArguments();
        if(arguments.Length!=2 || (int)type.GetProperty("Count")!.GetValue(cache)! !=0)throw WfpNative.Contract("PowerShellPolicyCacheAlreadyInitialized");
        foreach(var scope in new[]{"AllUsers","CurrentUser"})
        {
            var dictionary=Activator.CreateInstance(arguments[1])??throw WfpNative.Contract("PowerShellPolicyCacheConstructionFailed");
            var add=dictionary.GetType().GetMethod("TryAdd")!;
            foreach(var policy in policies)
                if(!(bool)add.Invoke(dictionary,new object?[]{policy.Name,null})!)throw WfpNative.Contract("PowerShellPolicyCacheDuplicate");
            if(!(bool)type.GetMethod("TryAdd")!.Invoke(cache,new[]{Enum.Parse(arguments[0],scope),dictionary})!)
                throw WfpNative.Contract("PowerShellPolicyScopeDuplicate");
        }
    }
}
