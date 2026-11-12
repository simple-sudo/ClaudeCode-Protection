using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

internal static class RestrictedPowerShellHost
{
    internal static int Run(string[] arguments)
    {
        try
        {
            var actualPackage=AtomicChild.AssertRestrictedToolSelf();
            var raw=Environment.GetEnvironmentVariable("CPC_RESOURCE_PLAN")??throw WfpNative.Contract("PowerShellResourcePlanMissing");
            var plan=ResourceProbePlan.Parse(raw);
            using var package=InstallationPackageSid.FromInstallationId(plan.InstallationId);
            if(actualPackage!=package.Value || Environment.GetEnvironmentVariable("CPC_POWERSHELL_POLICY_NONCE")!=plan.Nonce ||
                !string.Equals(Environment.ProcessPath,plan.PowerShellLaunchImage,StringComparison.OrdinalIgnoreCase))
                throw WfpNative.Contract("PowerShellOriginalOwnerBindingMissing");
            var expected=ResourceChildRunner.PowerShellStart(plan,plan.Workspace(package.Value)).ArgumentList.Skip(1).ToArray();
            if(!expected.SequenceEqual(arguments))throw WfpNative.Contract("PowerShellCompiledProgramRequired");
            return InvokeConfirmedAbsentPolicies(plan.PowerShellDirectory,arguments);
        }
        catch(Exception error)
        {
            // This is the confined tool's stderr, captured privately by its
            // original owner. It is never itself an admission or result.
            Console.Error.WriteLine(error);return 125;
        }
    }
    internal static int InvokeConfirmedAbsentPolicies(string directory,string[] arguments)
    {
        var assets=SessionPowerShellToolchain.ReadAssets();
        var paths=assets.Files.ToDictionary(a=>WindowsPathSeal.Child(directory,a.Path),a=>a,StringComparer.OrdinalIgnoreCase);
        Assembly Load(string path)
        {
            path=WindowsPathSeal.Canonical(path);
            if(!paths.TryGetValue(path,out var asset))throw WfpNative.Contract("PowerShellDependencyOutsideFixedDistribution");
            using(var file=File.OpenRead(path))
                if(file.Length!=asset.Length || Convert.ToHexString(SHA256.HashData(file))!=asset.SHA256)throw WfpNative.Contract("PowerShellDependencyChanged");
            return AssemblyLoadContext.Default.LoadFromAssemblyPath(path);
        }
        var resolver=new AssemblyDependencyResolver(WindowsPathSeal.Child(directory,"pwsh.dll"));
        Assembly? Resolve(AssemblyLoadContext context,AssemblyName name)
        {var path=resolver.ResolveAssemblyToPath(name);return path is null?null:Load(path);}
        IntPtr ResolveNative(Assembly assembly,string name)
        {
            var path=resolver.ResolveUnmanagedDllToPath(name);if(path is null)return IntPtr.Zero;
            if(!paths.TryGetValue(WindowsPathSeal.Canonical(path),out var asset))throw WfpNative.Contract("PowerShellNativeDependencyOutsideDistribution");
            using(var file=File.OpenRead(path))if(Convert.ToHexString(SHA256.HashData(file))!=asset.SHA256)throw WfpNative.Contract("PowerShellNativeDependencyChanged");
            return NativeLibrary.Load(path);
        }
        AssemblyLoadContext.Default.Resolving+=Resolve;AssemblyLoadContext.Default.ResolvingUnmanagedDll+=ResolveNative;
        try
        {
            var automation=Load(WindowsPathSeal.Child(directory,"System.Management.Automation.dll"));
            PowerShellPolicySnapshot.SeedConfirmedAbsence(automation);
            var entry=Load(WindowsPathSeal.Child(directory,"pwsh.dll")).GetType("Microsoft.PowerShell.ManagedPSEntry",true)!
                .GetMethod("Main",BindingFlags.Static|BindingFlags.Public|BindingFlags.NonPublic)
                ??throw WfpNative.Contract("PowerShellManagedEntryMissing");
            try{return (int)(entry.Invoke(null,new object[]{arguments})??throw WfpNative.Contract("PowerShellManagedExitMissing"));}
            catch(TargetInvocationException error)when(error.InnerException is not null){ExceptionDispatchInfo.Capture(error.InnerException).Throw();throw;}
        }
        finally{AssemblyLoadContext.Default.Resolving-=Resolve;AssemblyLoadContext.Default.ResolvingUnmanagedDll-=ResolveNative;}
    }
}
