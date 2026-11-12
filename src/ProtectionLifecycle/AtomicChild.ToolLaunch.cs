using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

internal sealed partial class AtomicChild
{
    // The restricted worker requests only the compiled fixed tool operations.
    // Its original Broker performs Windows startup bookkeeping, while package,
    // OPT_OUT and the original Job are atomically bound before first execution.
    // There is no elevated tool, arbitrary command endpoint or AC fallback.
    internal static InheritedTool StartInheritedTool(ProcessStartInfo start)
    {
        using var self=new SafeProcessHandle((IntPtr)(-1),false);var token=ReadToken(self,false);
        if(!token.IsAppContainer || token.CapabilityCount!=0 || token.IntegritySid!="S-1-16-4096" || token.PackageSid is null ||
            !IsProcessInJob(self,IntPtr.Zero,out var inJob) || !inJob)
            throw WfpNative.Contract("InheritedToolRequiresConfinedWorker");
        if(start.UseShellExecute || !start.CreateNoWindow || !start.RedirectStandardInput || !start.RedirectStandardOutput || !start.RedirectStandardError ||
            start.UserName.Length!=0 || start.Arguments.Length!=0 || !Path.IsPathFullyQualified(start.FileName) || !Path.IsPathFullyQualified(start.WorkingDirectory))
            throw WfpNative.Contract("InheritedToolStartContractRefused");
        _=InheritedToolCommand(start.FileName,start.ArgumentList.ToArray());
        var evidence=InspectToolCreationPrerequisites(start.FileName);
        return OwnedToolLaunch.Request(start,token.PackageSid,evidence);
    }
    internal static string AssertRestrictedToolSelf()
    {
        using var self=new SafeProcessHandle((IntPtr)(-1),false);var token=ReadToken(self,false);
        if(!token.IsAppContainer || token.CapabilityCount!=0 || token.IntegritySid!="S-1-16-4096" || token.PackageSid is null ||
            !IsProcessInJob(self,IntPtr.Zero,out var inJob) || !inJob)throw WfpNative.Contract("PowerShellRequiresConfinedTool");
        return token.PackageSid;
    }
    internal InheritedTool StartOwnedTool(OwnedKernelJob job,ProtectedSession.ResourceQualification permit,ProcessStartInfo start)
    {
        permit.AuthorizeToolCreation(this,job);
        if(disposed || !resumed || !IsRunning || !job.ContainsProcess(process))throw WfpNative.Contract("OwnedToolOriginalRootRequired");
        var token=ReadToken(process);
        if(!token.IsAppContainer || !token.LpacAccessCheckObserved || token.PackageSid!=packageSid || token.CapabilityCount!=0 || token.IntegritySid!="S-1-16-4096")
            throw WfpNative.Contract("OwnedToolOriginalRootTokenChanged");
        return CreateInheritedTool(start,InheritedToolCommand(start.FileName,start.ArgumentList.ToArray()),token,
            InspectToolCreationPrerequisites(start.FileName),job,permit);
    }
    internal ToolLaunchReply TransferToolHandles(InheritedTool tool,int sequence,string nonce)=>tool.TransferTo(process,checked((int)Pid),sequence,nonce);
    private static ToolCreationEvidence InspectToolCreationPrerequisites(string fixedImage)
    {
        using var self=new SafeProcessHandle((IntPtr)(-1),false);
        var childPolicyKnown=GetProcessMitigationPolicy(self,13,out var childPolicy,sizeof(uint));
        int? childPolicyError=childPolicyKnown?null:Marshal.GetLastWin32Error();
        var imagePolicyKnown=GetProcessMitigationPolicy(self,10,out var imagePolicy,sizeof(uint));
        int? imagePolicyError=imagePolicyKnown?null:Marshal.GetLastWin32Error();
        var evidence=new ToolCreationEvidence(childPolicyKnown?childPolicy:null,childPolicyError,imagePolicyKnown?imagePolicy:null,imagePolicyError,null);
        // Hash/read success does not establish FILE_EXECUTE access. Probe only
        // the already fixed, manager-held tool image, without mapping or running
        // it; do not read another resource or change any security descriptor.
        using var executable=SessionResources.OpenExecutableForProbe(fixedImage);
        if(executable.IsInvalid)
        {
            var code=Marshal.GetLastWin32Error();var failure=new Win32Exception(code);failure.Data["Stage"]="InheritedToolImageExecuteOpen";
            failure.Data["ToolCreationEvidence"]=evidence with{ImageExecuteOpenError=code};throw failure;
        }
        return evidence with{ImageExecuteOpenError=0};
    }
    private static InheritedTool CreateInheritedTool(ProcessStartInfo start,StringBuilder command,AdmissionToken token,ToolCreationEvidence evidence,OwnedKernelJob job,ProtectedSession.ResourceQualification permit)
    {
        if(token.PackageSid is null)throw WfpNative.Contract("InheritedToolPackageMissing");
        var sid=new SecurityIdentifier(token.PackageSid);var sidBytes=new byte[sid.BinaryLength];sid.GetBinaryForm(sidBytes,0);
        IntPtr attributes=IntPtr.Zero,package=IntPtr.Zero,capabilities=IntPtr.Zero,policy=IntPtr.Zero,handles=IntPtr.Zero,environment=IntPtr.Zero,jobList=IntPtr.Zero;
        bool initialized=false;SafeFileHandle? inputRead=null,inputWrite=null,outputRead=null,outputWrite=null,errorRead=null,errorWrite=null;
        SafeProcessHandle? process=null;SafeWaitHandle? thread=null;
        var jobHandle=job.ToolCreationHandle(permit);bool jobHeld=false;
        try
        {
            jobHandle.DangerousAddRef(ref jobHeld);
            var pipeSecurity=new KernelJobSeal.SecurityAttributes{Length=Marshal.SizeOf<KernelJobSeal.SecurityAttributes>(),Inherit=1};
            if(!CreateToolPipe(out inputRead,out inputWrite,ref pipeSecurity,0))throw Error("InheritedToolInputPipe");
            if(!CreateToolPipe(out outputRead,out outputWrite,ref pipeSecurity,0))throw Error("InheritedToolOutputPipe");
            if(!CreateToolPipe(out errorRead,out errorWrite,ref pipeSecurity,0))throw Error("InheritedToolErrorPipe");
            foreach(var parent in new[]{inputWrite,outputRead,errorRead})
                if(!SetToolHandleInformation(parent,1,0))throw Error("InheritedToolParentHandleSeal");
            nuint size=0;_=InitializeProcThreadAttributeList(IntPtr.Zero,4,0,ref size);
            if(size is 0 or >65536)throw Error("InheritedToolAttributeSize");
            attributes=Marshal.AllocHGlobal(checked((int)size));
            if(!InitializeProcThreadAttributeList(attributes,4,0,ref size))throw Error("InheritedToolAttributes");initialized=true;
            package=Marshal.AllocHGlobal(sidBytes.Length);Marshal.Copy(sidBytes,0,package,sidBytes.Length);
            capabilities=Marshal.AllocHGlobal(Marshal.SizeOf<SecurityCapabilities>());
            Marshal.StructureToPtr(new SecurityCapabilities{Sid=package},capabilities,false);
            if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)0x20009,capabilities,(nuint)Marshal.SizeOf<SecurityCapabilities>(),IntPtr.Zero,IntPtr.Zero))throw Error("InheritedToolPackage");
            policy=Marshal.AllocHGlobal(sizeof(uint));Marshal.WriteInt32(policy,1);
            if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)0x2000f,policy,sizeof(uint),IntPtr.Zero,IntPtr.Zero))throw Error("InheritedToolLpac");
            jobList=Marshal.AllocHGlobal(IntPtr.Size);Marshal.WriteIntPtr(jobList,jobHandle.DangerousGetHandle());
            if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)0x2000d,jobList,(nuint)IntPtr.Size,IntPtr.Zero,IntPtr.Zero))throw Error("OwnedToolJobAtCreation");
            handles=Marshal.AllocHGlobal(3*IntPtr.Size);
            var inherited=new[]{inputRead,outputWrite,errorWrite};for(var i=0;i<inherited.Length;i++)Marshal.WriteIntPtr(handles,i*IntPtr.Size,inherited[i].DangerousGetHandle());
            if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)0x20002,handles,(nuint)(3*IntPtr.Size),IntPtr.Zero,IntPtr.Zero))throw Error("InheritedToolHandleList");
            var env=start.Environment.OrderBy(e=>e.Key,StringComparer.OrdinalIgnoreCase).Select(e=>e.Key+"="+e.Value).ToArray();
            if(env.Any(e=>e.Contains('\0')))throw WfpNative.Contract("InheritedToolEnvironmentRefused");
            environment=Marshal.StringToHGlobalUni(string.Join('\0',env)+"\0\0");
            var startup=new StartupInfoEx{Basic=new(){Size=Marshal.SizeOf<StartupInfoEx>(),Flags=0x100,
                Input=inputRead.DangerousGetHandle(),Output=outputWrite.DangerousGetHandle(),Error=errorWrite.DangerousGetHandle()},Attributes=attributes};
            using var descriptor=new KernelJobSeal.SessionObjectDescriptor();var processSecurity=descriptor.Attributes;var threadSecurity=descriptor.Attributes;
            permit.AssertCurrent();
            ProcessInfo info;
            using(var faultMode=ToolFaultMode.Enter())
                if(!CreateSealedProcess(start.FileName,command,ref processSecurity,ref threadSecurity,true,0x08080404,environment,start.WorkingDirectory,ref startup,out info))
                {var failure=Error("OwnedToolCreateProcess");failure.Data["ToolCreationEvidence"]=evidence;throw failure;}
            process=new SafeProcessHandle(info.Process,true);thread=new SafeWaitHandle(info.Thread,true);
            KernelJobSeal.SessionObjectDescriptor.AssertSeal(process);KernelJobSeal.SessionObjectDescriptor.AssertSeal(thread);
            var child=ReadToken(process);
            var actualImage=new StringBuilder(32768);uint actualSize=(uint)actualImage.Capacity;
            if(!QueryFullProcessImageName(process,0,actualImage,ref actualSize))throw Error("OwnedToolHeldImage");
            if(!child.IsAppContainer || !child.LpacAccessCheckObserved || child.PackageSid!=token.PackageSid || child.CapabilityCount!=0 || child.IntegritySid!="S-1-16-4096" ||
                !job.ContainsProcess(process) || !string.Equals(WindowsPathSeal.Canonical(actualImage.ToString()),WindowsPathSeal.Canonical(start.FileName),StringComparison.OrdinalIgnoreCase))
                throw WfpNative.Contract("OwnedToolSuspendedIdentityRefused");
            if(start.ArgumentList.FirstOrDefault()=="resource-powershell")
            {
                var descriptors=SessionEtwProviderAccess.RegistrationCheckDescriptors(token.PackageSid);
                permit.RecordEtwTokenAccess(checked((int)GetProcessId(process)),
                    ObserveTokenRegisterAccess(process,descriptors.Readback),ObserveTokenRegisterAccess(process,descriptors.InMemoryPackageAce));
            }
            // The trusted owner still independently checks actual Job members,
            // image and LPAC AccessCheck mask before releasing the tool gate.
            if(ResumeThread(thread)!=1)throw Error("InheritedToolResume");
            var result=new InheritedTool(process,inputWrite,outputRead,errorRead,evidence);process=null;inputWrite=null;outputRead=null;errorRead=null;return result;
        }
        finally
        {
            // Any admitted descendant remains owned by the enclosing original
            // Job even if setup/reporting fails; its supervisor closes that Job.
            thread?.Dispose();process?.Dispose();inputRead?.Dispose();inputWrite?.Dispose();outputRead?.Dispose();outputWrite?.Dispose();errorRead?.Dispose();errorWrite?.Dispose();
            if(initialized)DeleteProcThreadAttributeList(attributes);
            foreach(var pointer in new[]{attributes,package,capabilities,policy,handles,environment,jobList})if(pointer!=IntPtr.Zero)Marshal.FreeHGlobal(pointer);
            if(jobHeld)jobHandle.DangerousRelease();
        }
    }
    private static StringBuilder InheritedToolCommand(string image,string[] arguments)
    {
        var command=new StringBuilder();
        foreach(var arg in new[]{image}.Concat(arguments))
        {
            if(arg.Contains('\0'))throw WfpNative.Contract("InheritedToolArgumentRefused");
            if(command.Length>0)command.Append(' ');command.Append('"');var slashes=0;
            foreach(var c in arg)
            {
                if(c=='\\'){slashes++;continue;}
                command.Append('\\',c=='"'?2*slashes+1:slashes);command.Append(c);slashes=0;
            }
            command.Append('\\',2*slashes);command.Append('"');
        }
        if(command.Length>=32767)throw WfpNative.Contract("InheritedToolCommandTooLong");return command;
    }
    internal sealed class InheritedTool : IDisposable
    {
        private readonly SafeProcessHandle process;
        internal StreamWriter StandardInput {get;}
        internal StreamReader StandardOutput {get;}
        internal StreamReader StandardError {get;}
        internal ToolCreationEvidence CreationEvidence {get;}
        internal InheritedTool(SafeProcessHandle process,SafeFileHandle input,SafeFileHandle output,SafeFileHandle error,ToolCreationEvidence evidence)
        {
            this.process=process;CreationEvidence=evidence;StandardInput=new StreamWriter(new FileStream(input,FileAccess.Write),new UTF8Encoding(false)){AutoFlush=true};
            StandardOutput=new StreamReader(new FileStream(output,FileAccess.Read),Encoding.UTF8,true);
            StandardError=new StreamReader(new FileStream(error,FileAccess.Read),Encoding.UTF8,true);
        }
        internal bool HasExited=>WaitForExit(0);
        internal bool WaitForExit(int milliseconds)
        {
            if(milliseconds<0)throw new ArgumentOutOfRangeException(nameof(milliseconds));var result=WaitForSingleObject(process,(uint)milliseconds);
            if(result==0)return true;if(result==258)return false;throw Error("InheritedToolWait");
        }
        internal int ExitCode=>GetExitCodeProcess(process,out var code)?unchecked((int)code):throw Error("InheritedToolExitCode");
        internal ToolLaunchReply TransferTo(SafeProcessHandle root,int rootPid,int sequence,string nonce)
        {
            // No Job/token/thread/manager handle crosses into the worker.
            // Partial transfers are bounded to this exact original root and
            // close when the same owning Job stops after a setup failure.
            long Copy(SafeHandle source,uint access,uint options)
            {
                if(!DuplicateToolHandle((IntPtr)(-1),source,root,out var transferred,access,false,options))throw Error("OwnedToolHandleTransfer");
                return transferred.ToInt64();
            }
            var limitedProcess=Copy(process,0x101000,0); // SYNCHRONIZE + QUERY_LIMITED_INFORMATION.
            var input=Copy(((FileStream)StandardInput.BaseStream).SafeFileHandle,0,2);
            var output=Copy(((FileStream)StandardOutput.BaseStream).SafeFileHandle,0,2);
            var error=Copy(((FileStream)StandardError.BaseStream).SafeFileHandle,0,2);
            return new(1,nonce,rootPid,sequence,limitedProcess,input,output,error,null,null);
        }
        public void Dispose(){StandardInput.Dispose();StandardOutput.Dispose();StandardError.Dispose();process.Dispose();}
    }
}
