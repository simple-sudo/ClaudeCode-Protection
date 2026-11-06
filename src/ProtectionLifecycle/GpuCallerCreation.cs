using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

internal sealed partial class AtomicChild
{
    internal static HostGpuReferenceChild CreateHostGpuFromCaller(FixedLayout layout,ProtectedState state,VerifiedVersion version,
        OwnedKernelJob job,GpuProbePlan plan,GpuReferenceCaller caller)
    {
        // Reserve before checking the ordinary peer again: a peer exit after
        // the owner created its empty Job must still close this admission.
        var jobHandle=job.ReserveAtomicAdmission(version);
        MaintenanceIdentity.RequireCurrentAdministrator();state.AssertHeld();version.AssertHeld(state);plan.Validate();caller.AssertCurrent();
        if(!Environment.Is64BitProcess || plan.ProgressProtocol!=1 || Marshal.SizeOf<StartupInfoEx>()!=112 || Marshal.SizeOf<ProcessInfo>()!=24)
            throw WfpNative.Contract("HostGpuBoundParentX64Required");
        using var owner=WindowsIdentity.GetCurrent(TokenAccessLevels.Query|TokenAccessLevels.Duplicate);
        var ownerBefore=GpuHostToken.Capture(owner.AccessToken);GpuReferenceCaller.RequireSameHuman(ownerBefore,caller.Expected);
        var image=WindowsPathSeal.Child(layout.Version(version.Package.Release),"bin/admin/ProtectionBroker.exe");
        var held=false;var initialized=false;var processCreated=false;
        IntPtr attributes=IntPtr.Zero,parent=IntPtr.Zero,jobList=IntPtr.Zero,environment=IntPtr.Zero;ProcessInfo info=default;
        SafeProcessHandle? processHandle=null;SafeWaitHandle? threadHandle=null;HostGpuReferenceChild? child=null;
        try
        {
            jobHandle.DangerousAddRef(ref held);nuint size=0;_=InitializeProcThreadAttributeList(IntPtr.Zero,2,0,ref size);
            if(size is 0 or >65536)throw Error("HostGpuParentAttributeSize");attributes=Marshal.AllocHGlobal(checked((int)size));
            if(!InitializeProcThreadAttributeList(attributes,2,0,ref size))throw Error("HostGpuParentAttributes");initialized=true;
            parent=caller.AllocateParentValue();
            if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)0x20000,parent,(nuint)IntPtr.Size,IntPtr.Zero,IntPtr.Zero))throw Error("HostGpuBoundParentAttribute");
            jobList=Marshal.AllocHGlobal(IntPtr.Size);Marshal.WriteIntPtr(jobList,jobHandle.DangerousGetHandle());
            if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)0x2000d,jobList,(nuint)IntPtr.Size,IntPtr.Zero,IntPtr.Zero))throw Error("HostGpuParentAtomicJobList");
            var env=new SortedDictionary<string,string>(StringComparer.OrdinalIgnoreCase);
            foreach(var name in new[]{"SystemRoot","windir","SystemDrive","ProgramFiles","ProgramFiles(x86)","ProgramW6432","PROCESSOR_ARCHITECTURE","USERPROFILE","LOCALAPPDATA","TEMP","TMP"})
            {var value=Environment.GetEnvironmentVariable(name);if(value is not null)env[name]=value;}
            env["PATH"]="C:\\Program Files\\dotnet;C:\\Windows\\System32;C:\\Windows";env["DOTNET_ROOT"]="C:\\Program Files\\dotnet";
            env["DOTNET_ROLL_FORWARD"]="LatestPatch";env["CUDA_CACHE_DISABLE"]="1";
            env["CPC_HOST_GPU_REFERENCE"]=JsonSerializer.Serialize(plan);
            env["CPC_HOST_GPU_REPORT_OWNER"]=Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture);
            environment=Marshal.StringToHGlobalUni(string.Join('\0',env.Select(p=>p.Key+"="+p.Value))+"\0\0");
            var startup=new StartupInfoEx{Basic=new(){Size=Marshal.SizeOf<StartupInfoEx>()},Attributes=attributes};
            using var seal=new KernelJobSeal.SessionObjectDescriptor();var processSecurity=seal.Attributes;var threadSecurity=seal.Attributes;
            caller.AssertCurrent();
            // No HANDLE_LIST and inherit=false: no source/parent handles,
            // standard streams or control handles enter the ordinary child.
            var ok=CreateBoundParentHost(image,new StringBuilder("\""+image+"\" gpu-host-reference-child"),ref processSecurity,ref threadSecurity,
                false,0x08080404,environment,Path.GetDirectoryName(image)!,ref startup,out info);
            var code=ok?0:Marshal.GetLastWin32Error();processCreated=ok;if(!ok)info=default;
            using(var current=WindowsIdentity.GetCurrent(TokenAccessLevels.Query|TokenAccessLevels.Duplicate))
                if(GpuHostToken.Capture(current.AccessToken)!=ownerBefore)throw WfpNative.Contract("HostGpuCreatingOwnerTokenDrift");
            if(!ok){var error=new Win32Exception(code,"Create fixed GPU reference with bound ordinary parent");error.Data["Stage"]="HostGpuBoundParentCreateProcess";throw error;}
            processHandle=new(info.Process,true);info.Process=IntPtr.Zero;threadHandle=new(info.Thread,true);info.Thread=IntPtr.Zero;
            child=new(state,version,job,processHandle,threadHandle,info.ProcessId,image,caller.Expected);processHandle=null;threadHandle=null;info=default;
            caller.AssertCurrent();child.AssertOwner(state,version,job);
            state.WriteNew("gpu-host-created-"+plan.Nonce+".json",JsonSerializer.SerializeToUtf8Bytes(new{SchemaVersion=1,state.InstallationId,plan.Nonce,job.JobId,
                Pid=child.Pid,CallerPid=caller.Pid,Scope="BOUND_INSTALLED_ORDINARY_PARENT_FIXED_HOST_CUDA_ONLY",AtomicJob=true,ProcessAndThreadSealed=true,
                NoHandlesInherited=true,CreatedToken=child.VerifiedToken,ElevatedOwnerTokenUnchanged=true,LinkedTokenRead=false,TokenAssignedOrAdjusted=false,NetworkGrant=false}));
            return child;
        }
        catch{child?.Dispose();throw;}
        finally
        {
            processHandle?.Dispose();threadHandle?.Dispose();
            if(processCreated && info.Thread!=IntPtr.Zero)new SafeWaitHandle(info.Thread,true).Dispose();
            if(processCreated && info.Process!=IntPtr.Zero)new SafeProcessHandle(info.Process,true).Dispose();
            if(initialized)DeleteProcThreadAttributeList(attributes);
            foreach(var pointer in new[]{attributes,parent,jobList,environment})if(pointer!=IntPtr.Zero)Marshal.FreeHGlobal(pointer);
            if(held)jobHandle.DangerousRelease();
        }
    }
    [DllImport("kernel32.dll",EntryPoint="CreateProcessW",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]private static extern bool CreateBoundParentHost(string image,StringBuilder command,
        ref KernelJobSeal.SecurityAttributes processSecurity,ref KernelJobSeal.SecurityAttributes threadSecurity,[MarshalAs(UnmanagedType.Bool)]bool inherit,
        uint flags,IntPtr environment,string directory,ref StartupInfoEx startup,out ProcessInfo info);
}
