using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

internal sealed partial class AtomicChild
{
    // Separate type: it cannot satisfy the LPAC child's admission/runtime API.
    internal sealed class HostGpuReferenceChild : IDisposable
    {
        private readonly ProtectedState state;private readonly VerifiedVersion version;private readonly OwnedKernelJob job;
        private readonly SafeProcessHandle process;private readonly SafeWaitHandle thread;private readonly string image;
        private readonly GpuHostTokenFacts expected;private bool resumed,disposed;
        internal uint Pid {get;}
        internal GpuHostTokenFacts? VerifiedToken {get;private set;}
        internal HostGpuReferenceChild(ProtectedState state,VerifiedVersion version,OwnedKernelJob job,SafeProcessHandle processHandle,SafeWaitHandle threadHandle,uint pid,string image,GpuHostTokenFacts expected)
        {this.state=state;this.version=version;this.job=job;this.image=image;this.expected=expected;Pid=pid;process=processHandle;thread=threadHandle;}
        internal void AssertOwner(ProtectedState exactState,VerifiedVersion exactVersion,OwnedKernelJob exactJob)
        {
            if(disposed || resumed || !ReferenceEquals(state,exactState) || !ReferenceEquals(version,exactVersion) || !ReferenceEquals(job,exactJob) ||
                Pid==0 || GetProcessId(process)!=Pid || WaitForSingleObject(process,0)!=0x102 || !job.ContainsProcess(process))throw WfpNative.Contract("HostGpuOriginalSuspendedOwnerRequired");
            state.AssertHeld();version.AssertHeld(state);
            KernelJobSeal.SessionObjectDescriptor.AssertSeal(process);KernelJobSeal.SessionObjectDescriptor.AssertSeal(thread);
            var members=job.Observe();if(!members.ExpectedLimits || members.ActiveBefore!=1 || members.ActiveAfter!=1 || members.ProcessIds.Length!=1 || members.ProcessIds[0]!=Pid)
                throw WfpNative.Contract("HostGpuAtomicJobBindingMismatch");
            var path=new StringBuilder(32768);uint length=(uint)path.Capacity;
            if(!QueryFullProcessImageName(process,0,path,ref length))throw Error("HostGpuImageReadback");
            if(!string.Equals(WindowsPathSeal.Canonical(path.ToString()),image,StringComparison.OrdinalIgnoreCase))throw WfpNative.Contract("HostGpuImageMismatch");
            if(!OpenProcessToken(process,0x0a,out var token))throw Error("HostGpuTokenReadback");
            using(token){var actual=GpuHostToken.Capture(token);GpuHostToken.RequireCreated(expected,actual);VerifiedToken=actual;}
        }
        internal void Resume()
        {
            AssertOwner(state,version,job);
            var plans=FencePlan.ReadAll(state);if(plans.Count==0)throw WfpNative.Contract("HostGpuQuarantineRequired");
            foreach(var plan in plans){using var fence=PersistentFence.OpenExisting(state,plan.Data.FenceId);if(!fence.Observe().FullQuarantineObserved)throw WfpNative.Contract("HostGpuQuarantineDrift");}
            resumed=true;if(ResumeThread(thread)!=1)throw Error("HostGpuSingleResume");
        }
        internal uint? ObserveExit()
        {
            if(!resumed || disposed)throw WfpNative.Contract("HostGpuNotResumed");var result=WaitForSingleObject(process,100);
            if(result==0x102)return null;if(result!=0)throw Error("HostGpuWait");
            if(!GetExitCodeProcess(process,out var exit))throw Error("HostGpuExit");return exit;
        }
        public void Dispose(){if(disposed)return;disposed=true;thread.Dispose();process.Dispose();}
    }
    internal static HostGpuReferenceChild CreateHostGpuReference(FixedLayout layout,ProtectedState state,VerifiedVersion version,OwnedKernelJob job,GpuProbePlan plan,IntPtr output)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();version.AssertHeld(state);plan.Validate();
        if(!Environment.Is64BitProcess || output==IntPtr.Zero || plan.ProgressProtocol!=1 || Marshal.SizeOf<StartupInfoEx>()!=112 || Marshal.SizeOf<ProcessInfo>()!=24 || Marshal.SizeOf<KernelJobSeal.SecurityAttributes>()!=24)
            throw WfpNative.Contract("HostGpuFixedPipeAndX64Required");
        var image=WindowsPathSeal.Child(layout.Version(version.Package.Release),"bin/admin/ProtectionBroker.exe");
        var jobHandle=job.ReserveAtomicAdmission(version);using var lower=GpuHostToken.OpenOwnLinkedNormalToken();
        IntPtr attributes=IntPtr.Zero,jobList=IntPtr.Zero,handles=IntPtr.Zero,environment=IntPtr.Zero;
        var initialized=false;var held=false;var processCreated=false;HostGpuReferenceChild? created=null;ProcessInfo info=default;
        SafeProcessHandle? processHandle=null;SafeWaitHandle? threadHandle=null;
        try
        {
            jobHandle.DangerousAddRef(ref held);nuint size=0;_=InitializeProcThreadAttributeList(IntPtr.Zero,2,0,ref size);
            if(size is 0 or >65536)throw Error("HostGpuAttributeSize");attributes=Marshal.AllocHGlobal(checked((int)size));
            if(!InitializeProcThreadAttributeList(attributes,2,0,ref size))throw Error("HostGpuAttributes");initialized=true;
            jobList=Marshal.AllocHGlobal(IntPtr.Size);Marshal.WriteIntPtr(jobList,jobHandle.DangerousGetHandle());
            if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)0x2000d,jobList,(nuint)IntPtr.Size,IntPtr.Zero,IntPtr.Zero))throw Error("HostGpuAtomicJobList");
            handles=Marshal.AllocHGlobal(IntPtr.Size);Marshal.WriteIntPtr(handles,output);
            if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)0x20002,handles,(nuint)IntPtr.Size,IntPtr.Zero,IntPtr.Zero))throw Error("HostGpuOnlyReportHandle");
            var env=new SortedDictionary<string,string>(StringComparer.OrdinalIgnoreCase);
            foreach(var name in new[]{"SystemRoot","windir","SystemDrive","ProgramFiles","ProgramFiles(x86)","ProgramW6432","PROCESSOR_ARCHITECTURE","USERPROFILE","LOCALAPPDATA","TEMP","TMP"})
            {var value=Environment.GetEnvironmentVariable(name);if(value is not null)env[name]=value;}
            env["PATH"]="C:\\Program Files\\dotnet;C:\\Windows\\System32;C:\\Windows";env["DOTNET_ROOT"]="C:\\Program Files\\dotnet";
            env["DOTNET_ROLL_FORWARD"]="LatestPatch";env["CUDA_CACHE_DISABLE"]="1";env["CPC_HOST_GPU_REFERENCE"]=JsonSerializer.Serialize(plan);
            environment=Marshal.StringToHGlobalUni(string.Join('\0',env.Select(p=>p.Key+"="+p.Value))+"\0\0");
            var startup=new StartupInfoEx{Basic=new(){Size=Marshal.SizeOf<StartupInfoEx>(),Flags=0x100,Output=output,Error=output},Attributes=attributes};
            using var descriptor=new KernelJobSeal.SessionObjectDescriptor();var processAttributes=descriptor.Attributes;var threadAttributes=descriptor.Attributes;
            var ok=CreateHostAsUser(lower.Primary,image,new StringBuilder("\""+image+"\" gpu-host-reference-child"),ref processAttributes,ref threadAttributes,true,
                0x08080404,environment,Path.GetDirectoryName(image)!,ref startup,out info);
            var error=ok?0:Marshal.GetLastWin32Error();
            processCreated=ok;if(!ok)info=default; // Failed-call out data is not owned-handle evidence.
            lower.AssertOwnerUnchanged(); // Also checked on native failure; never auto-repair.
            if(!ok){var failure=new Win32Exception(error,"Create fixed ordinary host GPU reference");failure.Data["Stage"]="HostGpuCreateProcessAsUser";throw failure;}
            processHandle=new(info.Process,true);info.Process=IntPtr.Zero;threadHandle=new(info.Thread,true);info.Thread=IntPtr.Zero;
            created=new(state,version,job,processHandle,threadHandle,info.ProcessId,image,lower.Expected);processHandle=null;threadHandle=null;info=default;
            created.AssertOwner(state,version,job);
            state.WriteNew("gpu-host-created-"+plan.Nonce+".json",JsonSerializer.SerializeToUtf8Bytes(new{SchemaVersion=1,state.InstallationId,plan.Nonce,job.JobId,
                Pid=created.Pid,Scope="OWN_LINKED_NORMAL_TOKEN_FIXED_HOST_CUDA_ONLY",AtomicJob=true,ProcessAndThreadSealed=true,ParentTokenAttributesRestored=true,
                CreatedToken=created.VerifiedToken,ElevatedChild=false,AppContainerChild=false,UntrustedCodeOrInput=false,NetworkGrant=false}));
            return created;
        }
        catch{created?.Dispose();throw;}
        finally
        {
            processHandle?.Dispose();threadHandle?.Dispose();
            if(processCreated && info.Thread!=IntPtr.Zero)new SafeWaitHandle(info.Thread,true).Dispose();if(processCreated && info.Process!=IntPtr.Zero)new SafeProcessHandle(info.Process,true).Dispose();
            if(initialized)DeleteProcThreadAttributeList(attributes);
            foreach(var pointer in new[]{attributes,jobList,handles,environment})if(pointer!=IntPtr.Zero)Marshal.FreeHGlobal(pointer);
            if(held)jobHandle.DangerousRelease();
        }
    }
    [DllImport("advapi32.dll",EntryPoint="CreateProcessAsUserW",CharSet=CharSet.Unicode,SetLastError=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CreateHostAsUser(SafeAccessTokenHandle token,string image,StringBuilder command,
        ref KernelJobSeal.SecurityAttributes processSecurity,ref KernelJobSeal.SecurityAttributes threadSecurity,[MarshalAs(UnmanagedType.Bool)]bool inherit,
        uint flags,IntPtr environment,string directory,ref StartupInfoEx startup,out ProcessInfo info);
}
