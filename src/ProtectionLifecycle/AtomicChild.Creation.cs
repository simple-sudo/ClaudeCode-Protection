using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionLifecycle;

// All fixed AtomicChild process factories. The returned AtomicChild remains
// the sole owner of its process/thread handles; this factory does not transfer
// or duplicate their lifetime ownership.
internal sealed partial class AtomicChild
{
    internal static AtomicChild AdoptSessionZeroOfflineConsole(FixedLayout layout,ProtectedState state,VerifiedVersion version,
        OwnedKernelJob job,SessionZeroCreatorChannel.SuspendedRoot root,bool startupWitness,SessionGitToolchain.Operation gitOperation,bool cuda)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();version.AssertHeld(state);
        _=job.SessionZeroCreatorSid;
        job.AssertCreatorSealedBeforeResume();
        var image=gitOperation!=SessionGitToolchain.Operation.None?SessionGitToolchain.ToolPath:startupWitness?SessionZeroStartupWitness.ReviewedImage(layout,version):
            WindowsPathSeal.Child(layout.Version(version.Package.Release),"bin/admin/ProtectionBroker.exe");
        using var package=new InstallationPackageSid(state);
        return new(state,version,job,root,image,package.Value,startupWitness,gitOperation,cuda);
    }
    internal static AtomicChild CreateCanary(FixedLayout layout,ProtectedState state,VerifiedVersion version,OwnedKernelJob job,InstallationProfileLease profile,
        NetworkProbePlan? network=null,IntPtr output=default,GpuProbePlan? gpu=null)
        =>CreateCore(layout,state,version,job,profile,network,output,gpu,null,null);
    internal static AtomicChild CreateOfflineTlsQualification(FixedLayout layout,ProtectedState state,VerifiedVersion version,
        OwnedKernelJob job,InstallationProfileLease profile,string sessionId,IntPtr output,OfflineTlsProbe probe)
        =>CreateCore(layout,state,version,job,profile,null,output,null,null,null,(probe,Identifiers.Hex32(sessionId)));
    internal static AtomicChild CreateOfflineConsoleQualification(FixedLayout layout,ProtectedState state,VerifiedVersion version,
        OwnedKernelJob job,InstallationProfileLease profile,string sessionId,PathLease workspace,OfflineConsoleStorage storage,OfflineConsoleStreams streams)
        =>CreateCore(layout,state,version,job,profile,null,IntPtr.Zero,null,null,null,console:(streams,Identifiers.Hex32(sessionId),workspace,storage));
    internal static (SafeProcessHandle Process,SafeWaitHandle Thread) CreateSessionZeroOfflineConsole(SessionZeroCreatorClient client,
        SessionZeroCreatorProfile profile,OfflineConsoleStreams streams)
    {
        if(!Environment.Is64BitProcess || Marshal.SizeOf<StartupInfoEx>()!=112 || Marshal.SizeOf<SecurityCapabilities>()!=24)
            throw new PlatformNotSupportedException("Creator startup requires the declared x64 layout");
        var brokerImage=ResolveSessionZeroImage(FixedLayout.FromWindows(),Environment.ProcessPath);
        using var git=client.Request.GitOperation!=SessionGitToolchain.Operation.None?SessionGitToolchain.Open():null;
        var image=git is not null?SessionGitToolchain.ToolPath:client.Request.StartupWitness?
            WindowsPathSeal.Child(Path.GetDirectoryName(brokerImage)!,Path.GetFileName(PackageAssetCatalog.SessionZeroStartupWitnessPath)):brokerImage;
        using var imageParent=git is null?WindowsPathSeal.LockDirectory(Path.GetDirectoryName(image)!,PathPolicy.Protected):null;
        using var heldImage=git is null?WindowsPathSeal.Open(image,false,true):null;
        if(heldImage is not null)WindowsPathSeal.AssertAcl(heldImage,true);
        var session=client.Request.JobId;
        using var workspace=WindowsPathSeal.LockDirectory(SessionTaskWorkspace.PathFor(session),PathPolicy.Source);
        var gitStart=client.Request.GitOperation switch
        {
            SessionGitToolchain.Operation.Init=>SessionGitToolchain.StartIndependentInit(workspace.Path),
            SessionGitToolchain.Operation.TrackedCommit=>SessionGitToolchain.StartIndependentCommit(workspace.Path),
            _=>null
        };
        var env=new SortedDictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        if(gitStart is not null)
        {
            foreach(var entry in gitStart.Environment)
                if(entry.Value is { } value)env.Add(entry.Key,value);
        }
        else
        {
            var windows=Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if(string.IsNullOrEmpty(windows))throw WfpNative.Contract("CreatorWindowsPathMissing");
            env["SystemRoot"]=env["windir"]=WindowsPathSeal.Canonical(windows);
            env["PATH"]=WindowsPathSeal.Child(windows,"System32")+";"+windows;
            env["DOTNET_ROOT"]=WindowsPathSeal.Child(Path.GetDirectoryName(workspace.Path)!,"dotnet");
            env["DOTNET_ROLL_FORWARD"]="LatestPatch";
            OfflineConsoleQualification.BindEnvironment(env,workspace.Path,profile.Package.Name,session);
            if(client.Request.Cuda)env[IndependentGpuWorkload.PreloadVariable]="0";
        }
        using var channels=streams.PrepareCreationAttributes();
        using var seal=new KernelJobSeal.SessionObjectDescriptor(localService:true);
        var processSecurity=seal.Attributes;var threadSecurity=seal.Attributes;
        var attributes=IntPtr.Zero;var values=IntPtr.Zero;var environment=IntPtr.Zero;
        var initialized=false;var assignmentHeld=false;
        try
        {
            client.Assignment.DangerousAddRef(ref assignmentHeld);
            nuint size=0;_=InitializeProcThreadAttributeList(IntPtr.Zero,5,0,ref size);
            if(size is 0 or >65536)throw Error("CreatorAttributeListSize");
            attributes=Marshal.AllocHGlobal(checked((int)size));
            if(!InitializeProcThreadAttributeList(attributes,5,0,ref size))throw Error("CreatorInitializeAttributes");
            initialized=true;
            var capabilitySize=Marshal.SizeOf<SecurityCapabilities>();
            values=Marshal.AllocHGlobal(capabilitySize+IntPtr.Size+sizeof(uint));
            Marshal.StructureToPtr(new SecurityCapabilities{Sid=profile.Package.Pointer},values,false);
            var jobList=IntPtr.Add(values,capabilitySize);Marshal.WriteIntPtr(jobList,client.Assignment.DangerousGetHandle());
            var policy=IntPtr.Add(jobList,IntPtr.Size);Marshal.WriteInt32(policy,1);
            Bind(0x20009,values,(nuint)capabilitySize);
            Bind(0x2000d,jobList,(nuint)IntPtr.Size);
            Bind(0x2000f,policy,sizeof(uint));
            channels.Bind(attributes);
            var std=channels.Channels;
            var desktop=client.Request.UsePrivateWindow?SessionZeroWindowPolicy.DesktopPathForJob(session):null;
            var startup=new StartupInfoEx{Basic=new(){Size=Marshal.SizeOf<StartupInfoEx>(),Desktop=desktop,Flags=0x100,
                Input=std.Input,Output=std.Output,Error=std.Error},Attributes=attributes};
            environment=Marshal.StringToHGlobalUni(string.Join('\0',env.Select(p=>p.Key+"="+p.Value))+"\0\0");
            var command=gitStart is not null?InheritedToolCommand(image,gitStart.ArgumentList.ToArray()):new StringBuilder("\""+image+"\"");
            if(gitStart is null && !client.Request.StartupWitness)command.Append(' ').Append(client.Request switch {
                {CudaDeviceIdentity:true}=>IndependentGpuWorkload.DeviceIdentityChildCommand,
                {CudaRegistryPrivacy:true}=>IndependentGpuWorkload.RegistryPrivacyChildCommand,
                {Cuda:true}=>IndependentGpuWorkload.ChildCommand,
                {NetworkSurvey:true}=>OfflineConsoleQualification.NetworkSurveyChildCommand,
                {IdentitySurvey:true}=>OfflineConsoleQualification.IdentitySurveyChildCommand,
                {UsePrivateWindow:true}=>OfflineConsoleQualification.PrivateWindowChildCommand,
                _=>OfflineConsoleQualification.ChildCommand
            });
            git?.AssertHeld();
            if(!CreateSealedProcess(image,command,ref processSecurity,ref threadSecurity,true,0x00080404u|OfflineConsoleStreams.DetachedCreationFlag,
                environment,workspace.Path,ref startup,out var created))throw Error("CreatorAtomicCreateSuspendedOfflineConsole");
            return(new(created.Process,true),new(created.Thread,true));
        }
        finally
        {
            if(initialized)DeleteProcThreadAttributeList(attributes);
            Marshal.FreeHGlobal(attributes);Marshal.FreeHGlobal(values);Marshal.FreeHGlobal(environment);
            if(assignmentHeld)client.Assignment.DangerousRelease();
        }
        void Bind(int attribute,IntPtr value,nuint length)
        {
            if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)attribute,value,length,IntPtr.Zero,IntPtr.Zero))throw Error("CreatorBindAtomicAttribute");
        }
    }
    internal static string ResolveSessionZeroImage(FixedLayout layout,string? processImage)
    {
        if(processImage is null)throw WfpNative.Contract("CreatorImageMissing");
        var actual=WindowsPathSeal.Canonical(processImage);
        var release=Path.GetFileName(Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(actual))))??"";
        var expected=WindowsPathSeal.Child(layout.Version(Identifiers.Hex32(release)),"bin/admin/ProtectionBroker.exe");
        if(!string.Equals(actual,expected,StringComparison.OrdinalIgnoreCase))throw WfpNative.Contract("CreatorImageMustBeInstalledBroker");
        return expected;
    }
    internal static AtomicChild CreateResourceQualification(FixedLayout layout,ProtectedState state,VerifiedVersion version,OwnedKernelJob job,
        InstallationProfileLease profile,ProtectedSession.ResourceQualification permit,IntPtr output)
    {
        var child=CreateCore(layout,state,version,job,profile,null,output,null,null,permit);
        try{permit.BindCreated(child);return child;}catch{child.Dispose();throw;}
    }
    internal static AtomicChild CreateSession(FixedLayout layout,ProtectedState state,VerifiedVersion version,OwnedKernelJob job,InstallationProfileLease profile,
        ProtectedSession.Preparation preparation,IntPtr report=default)
    {
        if(preparation.IsGatewayQualification!=(report!=IntPtr.Zero))throw WfpNative.Contract("FixedGatewayReportHandleRequiredExactly");
        var child=CreateCore(layout,state,version,job,profile,null,report,null,preparation,null);
        try{preparation.BindCreated(child);return child;}catch{child.Dispose();throw;}
    }
    private static AtomicChild CreateCore(FixedLayout layout,ProtectedState state,VerifiedVersion version,OwnedKernelJob job,InstallationProfileLease profile,
        NetworkProbePlan? network,IntPtr output,GpuProbePlan? gpu,ProtectedSession.Preparation? preparation,ProtectedSession.ResourceQualification? resources,
        (OfflineTlsProbe Probe,string Session)? tls=null,(OfflineConsoleStreams Streams,string Session,PathLease Workspace,OfflineConsoleStorage Storage)? console=null)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();version.AssertHeld(state);
        preparation?.BeforeCreate(job,version);
        resources?.BeforeCreate(job,version);
        if(resources is not null && (preparation is not null || network is not null || gpu is not null))throw WfpNative.Contract("ResourceQualificationCannotBorrowOtherAuthority");
        if(preparation is not null && (network is not null || gpu is not null))throw WfpNative.Contract("SuspendedSessionCannotBorrowQualificationPlan");
        if(!Environment.Is64BitProcess || Marshal.SizeOf<StartupInfo>()!=104 || Marshal.SizeOf<StartupInfoEx>()!=112 || Marshal.SizeOf<SecurityCapabilities>()!=24)
            throw new PlatformNotSupportedException("Atomic admission requires the declared x64 layout");
        var tlsCommand=tls is { } fixedTls?OfflineTlsQualification.ChildCommand(fixedTls.Probe):null;
        if(tls is not null && (preparation is not null || resources is not null || network is not null || gpu is not null))
            throw WfpNative.Contract("OfflineTlsQualificationCannotBorrowOtherAuthority");
        if(tls?.Probe==OfflineTlsProbe.OpenSsl)OpenSslModuleLease.AssertOwnedPackage(version.Package);
        if(console is { } fixedConsole)
        {
            if(tls is not null || preparation is not null || resources is not null || network is not null || gpu is not null || output!=IntPtr.Zero)
                throw WfpNative.Contract("OfflineConsoleCannotBorrowOtherAuthority");
            fixedConsole.Workspace.AssertHeld();
            fixedConsole.Storage.AssertHeld(fixedConsole.Workspace);
            if(fixedConsole.Workspace.Path!=SessionTaskWorkspace.PathFor(fixedConsole.Session))
                throw WfpNative.Contract("OfflineConsoleWorkspaceMismatch");
        }
        var requireLpac=preparation is not null || resources is not null || gpu is not null || tls is not null || console is not null;
        if(requireLpac && Marshal.SizeOf<KernelJobSeal.SecurityAttributes>()!=24)
            throw new PlatformNotSupportedException("Suspended session security attributes require the declared x64 layout");
        var image=WindowsPathSeal.Child(layout.Version(version.Package.Release),"bin/admin/ProtectionBroker.exe");
        network?.Validate();gpu?.Validate();if(network is not null && gpu is not null)throw WfpNative.Contract("OneFixedQualificationWorkloadRequired");
        var report=network is not null || gpu is not null || resources is not null || preparation?.IsGatewayQualification==true || tls is not null;if(report!=(output!=IntPtr.Zero))throw WfpNative.Contract("ReportHandleRequiredExactlyForQualificationWorkload");
        var inherit=report || console is not null;
        using var package=network?.Kind==NetworkProbeKind.Control?InstallationPackageSid.ForNetworkControl(state):new InstallationPackageSid(state);
        profile.AssertPackage(package);
        var originalJobHandle=job.ReserveAtomicAdmission(version);
        using var consoleAssignment=console is null?null:originalJobHandle.DuplicateAssignment();
        var jobHandle=consoleAssignment??originalJobHandle;
        using var capabilityAttributes=(preparation?.CapabilityProfile??FixedCapabilities(tls is not null)).AllocateAttributes();
        IntPtr attributes=IntPtr.Zero,capabilities=IntPtr.Zero,jobList=IntPtr.Zero,environment=IntPtr.Zero,handles=IntPtr.Zero,packagesPolicy=IntPtr.Zero;
        OfflineConsoleStreams.CreationAttributes? consoleAttributes=null;
        bool initialized=false,handleHeld=false;
        try
        {
            jobHandle.DangerousAddRef(ref handleHeld);
            var count=(inherit?3:2)+(requireLpac?1:0)+(console is not null?1:0);
            nuint size=0;_=InitializeProcThreadAttributeList(IntPtr.Zero,count,0,ref size);
            if(size is 0 or >65536)throw Error("AtomicAttributeListSize");
            attributes=Marshal.AllocHGlobal(checked((int)size));
            if(!InitializeProcThreadAttributeList(attributes,count,0,ref size))throw Error("AtomicInitializeAttributes");initialized=true;
            capabilities=Marshal.AllocHGlobal(Marshal.SizeOf<SecurityCapabilities>());
            Marshal.StructureToPtr(new SecurityCapabilities{Sid=package.Pointer,Capabilities=capabilityAttributes.Pointer,Count=capabilityAttributes.Count},capabilities,false);
            if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)0x20009,capabilities,(nuint)Marshal.SizeOf<SecurityCapabilities>(),IntPtr.Zero,IntPtr.Zero))throw Error("AtomicSetPackageAtCreation");
            if(requireLpac)
            {
                // PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY.
                // OPT_OUT is set at creation, while Job and package are bound.
                // No regular-AppContainer retry or caller override.
                packagesPolicy=Marshal.AllocHGlobal(sizeof(uint));Marshal.WriteInt32(packagesPolicy,1);
                if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)0x2000f,packagesPolicy,sizeof(uint),IntPtr.Zero,IntPtr.Zero))throw Error("AtomicRequireLpacAtCreation");
            }
            jobList=Marshal.AllocHGlobal(IntPtr.Size);Marshal.WriteIntPtr(jobList,jobHandle.DangerousGetHandle());
            if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)0x2000d,jobList,(nuint)IntPtr.Size,IntPtr.Zero,IntPtr.Zero))throw Error("AtomicSetJobListAtCreation");
            var startup=new StartupInfoEx{Basic=new(){Size=Marshal.SizeOf<StartupInfoEx>()},Attributes=attributes};
            if(console is { } consoleSetup)
            {
                consoleAttributes=consoleSetup.Streams.PrepareCreationAttributes();
                consoleAttributes.Bind(attributes);
                var channels=consoleAttributes.Channels;
                startup.Basic.Flags=0x100;
                startup.Basic.Input=channels.Input;startup.Basic.Output=channels.Output;startup.Basic.Error=channels.Error;
            }
            else if(report)
            {
                handles=Marshal.AllocHGlobal(IntPtr.Size);Marshal.WriteIntPtr(handles,output);
                if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)0x20002,handles,(nuint)IntPtr.Size,IntPtr.Zero,IntPtr.Zero))throw Error("AtomicSetOnlyReportHandleInheritance");
                startup.Basic.Flags=0x100;startup.Basic.Output=output;startup.Basic.Error=output;
            }
            var env=new SortedDictionary<string,string>(StringComparer.OrdinalIgnoreCase);
            var inherited=!requireLpac?new[]{"SystemRoot","windir","SystemDrive","ProgramFiles","ProgramFiles(x86)","ProgramW6432","PROCESSOR_ARCHITECTURE","LOCALAPPDATA","USERPROFILE","TEMP","TMP"}:
                new[]{"SystemRoot","windir","SystemDrive","ProgramFiles","ProgramFiles(x86)","ProgramW6432","PROCESSOR_ARCHITECTURE"};
            foreach(var name in inherited)
            {var value=Environment.GetEnvironmentVariable(name);if(value is not null)env[name]=value;}
            env["PATH"]="C:\\Program Files\\dotnet;C:\\Windows\\System32;C:\\Windows";
            env["DOTNET_ROOT"]="C:\\Program Files\\dotnet";env["DOTNET_ROLL_FORWARD"]="LatestPatch";
            if(network is not null)env["CPC_NETWORK_PLAN"]=JsonSerializer.Serialize(network);
            if(gpu is not null)
            {
                SetPrivateRuntimeDirectories(env,profile.WorkspaceRoot());
                env["CPC_GPU_PLAN"]=JsonSerializer.Serialize(gpu);env["CUDA_CACHE_DISABLE"]="1";
            }
            if(resources is not null)
            {
                env["CPC_RESOURCE_PLAN"]=JsonSerializer.Serialize(resources.Plan);
                SetPrivateRuntimeDirectories(env,resources.Workspace);
            }
            if(tls is { } offline)
            {
                SetPrivateRuntimeDirectories(env,profile.WorkspaceRoot());
                env[OfflineTlsQualification.SessionVariable(offline.Probe)]=offline.Session;
                if(offline.Probe==OfflineTlsProbe.OpenSsl)env[OpenSslModuleLease.ReleaseVariable]=version.Package.Release;
            }
            if(console is { } offlineConsoleSetup)
                OfflineConsoleQualification.BindEnvironment(env,offlineConsoleSetup.Workspace.Path,package.Name,offlineConsoleSetup.Session);
            if(preparation is not null)
            {
                // Creation requires LOCALAPPDATA; use the original freshly
                // owned profile, never the host user profile or inherited temp.
                SetPrivateRuntimeDirectories(env,profile.WorkspaceRoot());
                env["CPC_SESSION_ID"]=preparation.SessionId;env["CPC_SESSION_SECRET"]=preparation.Gateway.Secret;
                if(preparation.UsesFixedOpenSslHead)env[OpenSslModuleLease.ReleaseVariable]=version.Package.Release;
                if(preparation.IsGatewayQualification)
                {
                    // The fixed qualifier may resolve only the public definition
                    // selected by its original owner, not enumerate other zones.
                    var zone=preparation.PublicTimeZoneId??throw WfpNative.Contract("FixedPublicTimeZoneSelectionMissing");
                    env["CPC_PUBLIC_TIMEZONE_ID"]=zone;
                    var snapshot=preparation.PublicTimeZone??throw WfpNative.Contract("FixedPublicTimeZoneSnapshotMissing");
                    env["CPC_PUBLIC_TIMEZONE_SNAPSHOT"]=snapshot.Payload;
                    env["CPC_PUBLIC_TIMEZONE_SHA256"]=snapshot.SHA256;
                }
                var endpoint="http://"+preparation.SessionId+":"+preparation.Gateway.Secret+"@127.0.0.1:"+SessionProxy.Port;
                foreach(var name in new[]{"HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"})env[name]=endpoint;
                env["NO_PROXY"]="";
            }
            var environmentBlock=string.Join('\0',env.Select(p=>p.Key+"="+p.Value))+"\0\0";
            if(preparation?.IsGatewayQualification==true && environmentBlock.Length>32760)throw WfpNative.Contract("FixedGatewayEnvironmentBounds");
            environment=Marshal.StringToHGlobalUni(environmentBlock);
            var command=new StringBuilder("\""+image+"\" "+(console is not null?OfflineConsoleQualification.ChildCommand:tlsCommand??preparation?.ChildCommand??"admission-child"));
            // The OS binds BOTH identity and Job before returning a suspended
            // initial thread. Inherit only the selected report or console
            // handles; no breakaway permission is enabled.
            profile.BeforeProcessCreation(job.JobId);
            ProcessInfo info;
            if(requireLpac)
            {
                using var descriptor=new KernelJobSeal.SessionObjectDescriptor();
                var processAttributes=descriptor.Attributes;var threadAttributes=descriptor.Attributes;
                var flags=console is not null?0x00080404u|OfflineConsoleStreams.DetachedCreationFlag:0x08080404u;
                if(!CreateSealedProcess(image,command,ref processAttributes,ref threadAttributes,inherit,flags,environment,console?.Workspace.Path??resources?.Workspace??Path.GetDirectoryName(image)!,ref startup,out info))
                    throw Error("AtomicCreateSealedSuspendedSession");
            }
            else if(!CreateProcess(image,command,IntPtr.Zero,IntPtr.Zero,report,0x08080404,environment,Path.GetDirectoryName(image)!,ref startup,out info))
                throw Error("AtomicCreateSuspendedWithPackageAndJob");
            var child=new AtomicChild(state,version,job,info,image,package.Value,network,gpu is not null,preparation,resources,tls?.Probe,console is not null);
            try
            {
                if(requireLpac){KernelJobSeal.SessionObjectDescriptor.AssertSeal(child.process);KernelJobSeal.SessionObjectDescriptor.AssertSeal(child.thread);}
                return child;
            }
            catch{child.Dispose();throw;}
        }
        finally
        {
            if(initialized)DeleteProcThreadAttributeList(attributes);
            consoleAttributes?.Dispose();
            if(attributes!=IntPtr.Zero)Marshal.FreeHGlobal(attributes);
            if(capabilities!=IntPtr.Zero)Marshal.FreeHGlobal(capabilities);
            if(jobList!=IntPtr.Zero)Marshal.FreeHGlobal(jobList);
            if(environment!=IntPtr.Zero)Marshal.FreeHGlobal(environment);
            if(handles!=IntPtr.Zero)Marshal.FreeHGlobal(handles);
            if(packagesPolicy!=IntPtr.Zero)Marshal.FreeHGlobal(packagesPolicy);
            if(handleHeld)jobHandle.DangerousRelease();
        }
    }
}
