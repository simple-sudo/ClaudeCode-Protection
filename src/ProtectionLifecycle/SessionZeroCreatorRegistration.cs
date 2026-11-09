using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

// Original SCM owner for the fixed offline creator. Never opens an existing
// service for adoption, never force-stops, and never retries a failed mutation.
internal sealed class SessionZeroCreatorRegistration : IDisposable
{
    internal const string IntentPrefix="creator-service-intent-";
    private const string LocalService=@"NT AUTHORITY\LocalService",Traverse="SeChangeNotifyPrivilege";
    private const string Closed="PROFILE_AND_SERVICE_CLOSED",Unstarted="SERVICE_REMOVED_BEFORE_START";
    private const string StartupFailed="SERVICE_REMOVED_AFTER_STARTUP_FAILURE_WITHOUT_JOB";
    private readonly ProtectedState state;
    private readonly VerifiedVersion version;
    private readonly ServiceHandle manager,service;
    private readonly string image,name,command,intentHash;
    private bool startAttempted,deleteAttempted;
    private uint? startupFailure;
    private SafeProcessHandle? process;
    private SessionZeroCreatorChannel? channel;
    internal string JobId {get;}
    internal SecurityIdentifier Sid {get;}

    private SessionZeroCreatorRegistration(ProtectedState state,VerifiedVersion version,ServiceHandle manager,ServiceHandle service,
        string id,string image,string name,string command,string intentHash,SecurityIdentifier sid)
    {
        this.state=state;this.version=version;this.manager=manager;this.service=service;JobId=id;this.image=image;
        this.name=name;this.command=command;this.intentHash=intentHash;Sid=sid;
    }

    internal static SessionZeroCreatorRegistration Create(FixedLayout layout,ProtectedState state,VerifiedVersion version)
    {
        ProtectedState.RequireAdministrator();state.AssertHeld();version.AssertHeld(state);
        LifecycleRecovery.AssertNoPending(state);
        var current=CurrentPointer.Parse(state.Read("current.json",4096),state.InstallationId);
        if(current.Release!=version.Package.Release || current.ManifestSHA256!=version.Package.ManifestHash)
            throw WfpNative.Contract("CreatorRegistrationRequiresCurrentVersion");
        var id=Guid.NewGuid().ToString("N");
        var name=SessionZeroCreatorChannel.NameForJob(id);
        var image=WindowsPathSeal.Child(layout.Version(version.Package.Release),"bin/admin/ProtectionBroker.exe");
        var command=BuildCommand(image);
        var manager=OpenSCManager(null,null,3); // CONNECT | CREATE_SERVICE.
        ServiceHandle? service=null;
        try
        {
            if(manager.IsInvalid)throw Error("OpenLocalCreatorServiceManager");
            using(var prior=OpenService(manager,name,4))
            {
                if(!prior.IsInvalid || Marshal.GetLastWin32Error()!=1060)throw WfpNative.Contract("CreatorServiceNameNotConfirmedFresh");
            }
            var leaf=IntentLeaf(id);
            state.WriteNew(leaf,JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,state.InstallationId,JobId=id,
                version.Package.Release,version.Package.ManifestHash}));
            var intentHash=state.Read(leaf,4096).SHA256;
            // No SERVICE_STOP or arbitrary service control rights.
            service=CreateService(manager,name,name,0x000f0017,0x10,3,1,command,null,IntPtr.Zero,null,LocalService,null);
            if(service.IsInvalid)throw Error("RegisterFreshCreatorService");
            SealRegistration(service);
            AssertConfiguration(service,name,command);
            var sid=(SecurityIdentifier)new NTAccount("NT SERVICE",name).Translate(typeof(SecurityIdentifier));
            return new(state,version,manager,service,id,image,name,command,intentHash,sid);
        }
        catch{service?.Dispose();manager.Dispose();throw;} // A durable pending intent survives an uncertain operation.
    }

    internal static string BuildCommand(string image)
    {
        if(image.Contains('"') || !string.Equals(Path.GetFileName(image),"ProtectionBroker.exe",StringComparison.OrdinalIgnoreCase))
            throw WfpNative.Contract("CreatorServiceCommandImageInvalid");
        return "\""+WindowsPathSeal.Canonical(image)+"\" session-zero-offline-creator";
    }

    internal SafeProcessHandle AssertReadyForPipe(ProtectedState exactState,VerifiedVersion exactVersion,
        SessionZeroCreatorChannel? expectedChannel=null)
    {
        AssertOriginal();
        if(!ReferenceEquals(state,exactState) || !ReferenceEquals(version,exactVersion) || !startAttempted ||
            channel is null || (expectedChannel is not null && !ReferenceEquals(channel,expectedChannel)) ||
            !channel.IsPreparedFor(this) || process is null || WaitForSingleObject(process,0)!=258)
            throw WfpNative.Contract("CreatorServicePipePreparationBindingMismatch");
        return process;
    }

    internal SafeProcessHandle AssertReadyForJob(ProtectedState exactState,VerifiedVersion exactVersion,
        SessionZeroCreatorChannel? expectedChannel=null)
    {
        var held=AssertReadyForPipe(exactState,exactVersion,expectedChannel);
        channel!.AssertBoundPeer(held,image);
        return held;
    }

    internal void StartAndHold(SessionZeroCreatorChannel preparedChannel)
    {
        AssertOriginal();
        if(startAttempted || !preparedChannel.IsPreparedFor(this))throw WfpNative.Contract("CreatorServiceStartNeedsOriginalPipe");
        AssertNoJobOrWorkspace(state,JobId);
        var before=ReadStatus(service);
        if(before.State!=1)throw WfpNative.Contract("FreshCreatorServiceNotStopped");
        state.WriteNew(StartLeaf(JobId),JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,IntentSHA256=intentHash}));
        startAttempted=true;
        if(!StartService(service,0,IntPtr.Zero))throw Error("StartFixedCreatorService");
        var watch=Stopwatch.StartNew();
        while(watch.ElapsedMilliseconds<10000)
        {
            var status=ReadStatus(service);
            if(status.State==1)
            {
                if(SessionZeroCreatorService.IsReportedStartupFailure(status.Win32Code,status.ServiceCode))
                    startupFailure=status.ServiceCode;
                throw SessionZeroCreatorService.DescribeStopped(status.Win32Code,status.ServiceCode);
            }
            if(status.State==4 && status.Pid!=0)
            {
                var held=OpenProcess(0x101000,false,status.Pid);
                try
                {
                    if(held.IsInvalid)throw Error("HoldOriginalCreatorProcess");
                    SessionZeroCreatorChannel.AssertImage(held,image);
                    var after=ReadStatus(service);
                    if(after.State!=4 || after.Pid!=status.Pid || WaitForSingleObject(held,0)!=258)
                        throw WfpNative.Contract("CreatorServiceProcessChanged");
                    process=held;channel=preparedChannel;return;
                }
                catch{held.Dispose();throw;}
            }
            Thread.Sleep(25);
        }
        throw new TimeoutException("Original creator service did not become ready");
    }

    internal bool TryRemoveAfterStartupFailure(SessionZeroCreatorChannel preparedChannel)
    {
        if(startupFailure is not uint failure)return false;
        AssertOriginal();
        if(!startAttempted || process is not null || channel is not null || !preparedChannel.IsPreparedFor(this))
            throw WfpNative.Contract("CreatorServiceStartupFailureBindingMismatch");
        AssertNoJobOrWorkspace(state,JobId);
        var status=ReadStatus(service);
        if(status.State!=1 || status.Win32Code!=1066 || status.ServiceCode!=failure)
            throw WfpNative.Contract("CreatorServiceStartupFailureChanged");
        var start=state.Read(StartLeaf(JobId),4096);
        ValidateStartProof(start.Bytes,intentHash);
        state.WriteNew(StartupFailureLeaf(JobId),JsonSerializer.SerializeToUtf8Bytes(new {
            SchemaVersion=1,IntentSHA256=intentHash,StartSHA256=start.SHA256,ServiceCode=failure
        }));
        RemoveVerified(StartupFailed);
        return true;
    }

    internal void RemoveNeverStarted()
    {
        AssertOriginal();
        if(startAttempted || state.ReadOptional(StartLeaf(JobId)) is not null)
            throw WfpNative.Contract("CreatorServiceMayHaveStarted");
        AssertNoJobOrWorkspace(state,JobId);
        RemoveVerified(Unstarted);
    }

    internal void RemoveAfterProfileCleanup(SessionZeroOfflineWorkspace workspace)
    {
        AssertOriginal();
        workspace.AssertClosedFor(state,JobId);
        if(!startAttempted || channel?.ProfileCleanupConfirmed!=true || process is null || WaitForSingleObject(process,5000)!=0)
            throw WfpNative.Contract("CreatorServiceTerminalProofMissing");
        if(!GetExitCodeProcess(process,out var exitCode))throw Error("ReadOriginalCreatorExitCode");
        var status=ReadStatus(service);
        if(exitCode!=0 || status.State!=1 || status.Win32Code!=0 || status.ServiceCode!=0)
            throw WfpNative.Contract("CreatorServiceSuccessfulExitNotConfirmed");
        RemoveVerified(Closed);
    }

    private void RemoveVerified(string disposition)
    {
        var status=ReadStatus(service);
        if(status.State!=1)throw WfpNative.Contract("CreatorServiceMustBeStoppedBeforeRemoval");
        deleteAttempted=true;
        if(!DeleteService(service))throw Error("RemoveOriginalCreatorRegistration");
        service.Dispose();
        WaitForAbsence(manager,name);
        state.WriteNew(DoneLeaf(JobId),JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,IntentSHA256=intentHash,Disposition=disposition}));
    }

    internal static void WaitForAbsence(ServiceHandle manager,string name)
    {
        var watch=Stopwatch.StartNew();
        while(watch.ElapsedMilliseconds<5000)
        {
            using(var observation=OpenService(manager,name,4))
            {
                if(observation.IsInvalid)
                {
                    var code=Marshal.GetLastWin32Error();
                    if(code==1060)return;
                    if(code!=1072)throw new WfpFailure("CreatorServiceNameRemovalReadback",unchecked((uint)code));
                }
                // A still-visible name is not closure. Release this query
                // handle before waiting. Never delete or adopt it here.
            }
            Thread.Sleep(25);
        }
        throw new TimeoutException("Original creator service deletion is pending");
    }

    internal static void AssertRecoveryRegistrationAbsent(string id)
    {
        using var manager=OpenSCManager(null,null,1);
        if(manager.IsInvalid)throw Error("OpenLocalCreatorServiceManager");
        using var observation=OpenService(manager,SessionZeroCreatorChannel.NameForJob(id),4);
        var code=Marshal.GetLastWin32Error();
        if(!observation.IsInvalid || code!=1060)throw WfpNative.Contract("LegacyCreatorServiceAbsenceUnconfirmed");
    }

    internal static RecoveryRegistration HoldForRecovery(OwnedJobIntent job,string image,uint stoppedProtocolCode=0)
    {
        var manager=OpenSCManager(null,null,1);
        ServiceHandle? service=null;
        try
        {
            if(manager.IsInvalid)throw Error("OpenLocalCreatorServiceManager");
            var name=SessionZeroCreatorChannel.NameForJob(job.JobId);
            service=OpenService(manager,name,0x30005); // Delete, read control, query config/status only.
            if(service.IsInvalid)throw Error("HoldLegacyCreatorRegistration");
            var recovery=new RecoveryRegistration(manager,service,name,BuildCommand(image),stoppedProtocolCode);
            if(((SecurityIdentifier)new NTAccount("NT SERVICE",name).Translate(typeof(SecurityIdentifier))).Value!=job.CreatorServiceSid)
                throw WfpNative.Contract("LegacyCreatorServiceSidMismatch");
            recovery.AssertStoppedWithoutStart();
            return recovery;
        }
        catch{service?.Dispose();manager.Dispose();throw;}
    }

    internal sealed class RecoveryRegistration : IDisposable
    {
        private readonly ServiceHandle manager,service;
        private readonly string name,command;
        private readonly uint stoppedProtocolCode;
        private bool attempted;
        internal RecoveryRegistration(ServiceHandle manager,ServiceHandle service,string name,string command,uint stoppedProtocolCode)
        {this.manager=manager;this.service=service;this.name=name;this.command=command;this.stoppedProtocolCode=stoppedProtocolCode;}
        internal void AssertStoppedWithoutStart()
        {
            if(attempted)throw WfpNative.Contract("LegacyCreatorServiceRecoveryAlreadyAttempted");
            AssertConfiguration(service,name,command);
            var status=ReadStatus(service);
            if(!MatchesRecoveryStop(status.State,status.Pid,status.Win32Code,status.ServiceCode,stoppedProtocolCode))
                throw WfpNative.Contract("LegacyCreatorServiceMayHaveStartedSinceBoot");
        }
        internal void Remove()
        {
            AssertStoppedWithoutStart();
            attempted=true;
            if(!DeleteService(service))throw Error("RemoveLegacyCreatorRegistration");
            service.Dispose();
            WaitForAbsence(manager,name);
        }
        public void Dispose(){service.Dispose();manager.Dispose();}
    }

    internal static bool MatchesRecoveryStop(uint state,uint pid,uint win32,uint specific,uint approvedCode)=>
        state==1 && pid==0 && ((win32==1077 && specific==0) || (approvedCode!=0 && win32==1066 && specific==approvedCode));

    internal sealed class ProfileRecoveryWorker : IDisposable
    {
        private readonly ServiceHandle manager,service;
        private readonly string name,image,command;
        private SafeProcessHandle? process;
        private bool started,removed;

        private ProfileRecoveryWorker(ServiceHandle manager,ServiceHandle service,string name,string image,string command)
        {this.manager=manager;this.service=service;this.name=name;this.image=image;this.command=command;}

        internal static ProfileRecoveryWorker Register(string id,string image)
        {
            ProtectedState.RequireAdministrator();
            var name=SessionZeroCreatorChannel.NameForJob(id);
            if(image.Contains('"') || Path.GetFileName(image)!="ProtectionBootstrap.exe")
                throw WfpNative.Contract("ProfileRecoveryWorkerImageInvalid");
            var command="\""+WindowsPathSeal.Canonical(image)+"\" "+SessionZeroClosedCreatorRecovery.ServiceVerb;
            var manager=OpenSCManager(null,null,3);
            ServiceHandle? service=null;
            try
            {
                if(manager.IsInvalid)throw Error("OpenProfileRecoveryServiceManager");
                AssertRecoveryRegistrationAbsent(id);
                service=CreateService(manager,name,name,0x000f0017,0x10,3,1,command,null,IntPtr.Zero,null,LocalService,null);
                if(service.IsInvalid)throw Error("RegisterFreshProfileRecoveryWorker");
                SealRegistration(service);
                AssertConfiguration(service,name,command);
                return new(manager,service,name,image,command);
            }
            catch{service?.Dispose();manager.Dispose();throw;}
        }

        internal SafeProcessHandle StartAndHold()
        {
            if(started || removed)throw WfpNative.Contract("ProfileRecoveryWorkerAlreadyUsed");
            AssertConfiguration(service,name,command);
            var before=ReadStatus(service);
            if(!MatchesRecoveryStop(before.State,before.Pid,before.Win32Code,before.ServiceCode,0))
                throw WfpNative.Contract("ProfileRecoveryWorkerNotFresh");
            started=true;
            if(!StartService(service,0,IntPtr.Zero))throw Error("StartProfileRecoveryWorker");
            var watch=Stopwatch.StartNew();
            while(watch.ElapsedMilliseconds<10000)
            {
                var status=ReadStatus(service);
                if(status.State==1)throw SessionZeroCreatorService.DescribeStopped(status.Win32Code,status.ServiceCode);
                if(status.State==4 && status.Pid!=0)
                {
                    var held=OpenProcess(0x101000,false,status.Pid);
                    try
                    {
                        if(held.IsInvalid)throw Error("HoldProfileRecoveryWorker");
                        SessionZeroCreatorChannel.AssertImage(held,image);
                        var after=ReadStatus(service);
                        if(after.State!=4 || after.Pid!=status.Pid || WaitForSingleObject(held,0)!=258)
                            throw WfpNative.Contract("ProfileRecoveryWorkerChanged");
                        process=held;
                        return held;
                    }
                    catch{held.Dispose();throw;}
                }
                Thread.Sleep(25);
            }
            throw new TimeoutException("Profile recovery worker did not become ready");
        }

        internal void RemoveAfterSuccess()
        {
            if(removed || process is null || WaitForSingleObject(process,5000)!=0 ||
                !GetExitCodeProcess(process,out var exit) || exit!=0)
                throw WfpNative.Contract("ProfileRecoveryWorkerExitUnconfirmed");
            AssertConfiguration(service,name,command);
            var status=ReadStatus(service);
            if(status.State!=1 || status.Pid!=0 || status.Win32Code!=0 || status.ServiceCode!=0)
                throw WfpNative.Contract("ProfileRecoveryWorkerStopUnconfirmed");
            removed=true;
            if(!DeleteService(service))throw Error("RemoveProfileRecoveryWorker");
            service.Dispose();
            WaitForAbsence(manager,name);
        }

        public void Dispose(){process?.Dispose();service.Dispose();manager.Dispose();}
    }

    private void AssertOriginal()
    {
        state.AssertHeld();version.AssertHeld(state);
        if(deleteAttempted || manager.IsClosed || service.IsClosed || state.Read(IntentLeaf(JobId),4096).SHA256!=intentHash)
            throw WfpNative.Contract("CreatorServiceOriginalRegistrationUnavailable");
        AssertConfiguration(service,name,command);
    }

    private static string IntentLeaf(string id)=>IntentPrefix+Identifiers.Hex32(id)+".json";
    private static string StartLeaf(string id)=>"creator-service-start-"+Identifiers.Hex32(id)+".json";
    private static string StartupFailureLeaf(string id)=>"creator-service-startup-failed-"+Identifiers.Hex32(id)+".json";
    private static string DoneLeaf(string id)=>"creator-service-removed-"+Identifiers.Hex32(id)+".json";
    private static void AssertNoJobOrWorkspace(ProtectedState state,string id)
    {
        if(state.ReadOptional(OwnedJobIntent.Leaf(id)) is not null || state.ReadOptional("creator-workspace-intent-"+id+".json") is not null)
            throw WfpNative.Contract("CreatorServiceStartupRecoveryRequiresNoJobOrWorkspace");
    }
    internal static void AssertNoPending(ProtectedState state,SessionZeroCreatorRegistration? preparing,OwnedJobIntent? recovering=null)
    {
        var entries=state.ListLeaves(IntentPrefix);
        if(entries.Length>1024)throw WfpNative.Contract("CreatorServiceInventoryLimit");
        foreach(var leaf in entries)
        {
            if(leaf.Length!=IntentPrefix.Length+37 || !leaf.EndsWith(".json",StringComparison.Ordinal))
                throw WfpNative.Contract("CreatorServiceIntentNameInvalid");
            var id=Identifiers.Hex32(leaf.Substring(IntentPrefix.Length,32));
            var raw=state.Read(leaf,4096);
            using var intent=JsonDocument.Parse(raw.Bytes,new JsonDocumentOptions{MaxDepth=2});
            ValidateIntent(intent.RootElement,state.InstallationId,id);
            if(recovering?.JobId==id)continue; // The dedicated recovery owner separately binds this exact ledger.
            if(preparing is not null && ReferenceEquals(preparing.state,state) && preparing.JobId==id && preparing.intentHash==raw.SHA256)
            {
                _=preparing.AssertReadyForJob(state,preparing.version);
                continue;
            }
            if(state.ReadOptional(SessionZeroCreatorRecovery.ReceiptLeaf(id)) is not null)
            {
                _=SessionZeroCreatorRecovery.ReadRetired(state,OwnedJobIntent.Read(state,id));
                continue;
            }
            if(state.ReadOptional(SessionZeroClosedCreatorRecovery.ReceiptLeaf(id)) is not null)
            {
                _=SessionZeroClosedCreatorRecovery.ReadRecovered(state,OwnedJobIntent.Read(state,id));
                continue;
            }
            var done=state.ReadOptional(DoneLeaf(id))??throw WfpNative.Contract("CreatorServiceRegistrationRequiresRecovery");
            using var receipt=JsonDocument.Parse(done.Bytes,new JsonDocumentOptions{MaxDepth=2});
            var start=state.ReadOptional(StartLeaf(id));
            if(start is not null)ValidateStartProof(start.Bytes,raw.SHA256);
            var failure=state.ReadOptional(StartupFailureLeaf(id));
            if(start is null || failure is not null)AssertNoJobOrWorkspace(state,id);
            if(failure is not null)
            {
                if(start is null)throw WfpNative.Contract("CreatorServiceStartupFailureMissingStart");
                ValidateStartupFailure(failure.Bytes,raw.SHA256,start.SHA256);
            }
            ValidateRemoval(receipt.RootElement,raw.SHA256,start is not null,failure is not null);
        }
    }
    internal static void ValidateStartProof(byte[] bytes,string intentHash)
    {
        using var started=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=2});
        var record=started.RootElement;
        StrictJson.Fields(record,"SchemaVersion","IntentSHA256");
        if(record.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(record,"IntentSHA256")!=intentHash)
            throw WfpNative.Contract("CreatorServiceStartProofMismatch");
    }
    internal static void ValidateStartupFailure(byte[] bytes,string intentHash,string startHash)
    {
        using var failed=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=2});
        var record=failed.RootElement;
        StrictJson.Fields(record,"SchemaVersion","IntentSHA256","StartSHA256","ServiceCode");
        if(record.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(record,"IntentSHA256")!=intentHash ||
            StrictJson.Text(record,"StartSHA256")!=startHash ||
            !SessionZeroCreatorService.IsReportedStartupFailure(1066,record.GetProperty("ServiceCode").GetUInt32()))
            throw WfpNative.Contract("CreatorServiceStartupFailureProofMismatch");
    }
    internal static void ValidateIntent(JsonElement record,string install,string id)
    {
        StrictJson.Fields(record,"SchemaVersion","InstallationId","JobId","Release","ManifestHash");
        if(record.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(record,"InstallationId")!=install || StrictJson.Text(record,"JobId")!=id)
            throw WfpNative.Contract("CreatorServiceIntentBindingMismatch");
        _=Identifiers.Hex32(StrictJson.Text(record,"Release"));_=Identifiers.Hash(StrictJson.Text(record,"ManifestHash"));
    }
    internal static void ValidateRemoval(JsonElement record,string intentHash,bool started,bool startupFailed)
    {
        StrictJson.Fields(record,"SchemaVersion","IntentSHA256","Disposition");
        var expected=startupFailed?StartupFailed:started?Closed:Unstarted;
        if(record.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(record,"IntentSHA256")!=intentHash ||
            (startupFailed && !started) || StrictJson.Text(record,"Disposition")!=expected)
            throw WfpNative.Contract("CreatorServiceRemovalProofMismatch");
    }

    internal static void SealRegistration(ServiceHandle service)
    {
        var descriptor=new RawSecurityDescriptor("O:BAD:P(A;;0x000f01ff;;;SY)(A;;0x000f01ff;;;BA)");
        var bytes=new byte[descriptor.BinaryLength];descriptor.GetBinaryForm(bytes,0);
        if(!SetServiceObjectSecurity(service,5,bytes))throw Error("SealCreatorServiceRegistration");
        ConfigureIdentity(service);
    }

    private static void ConfigureIdentity(ServiceHandle service)
    {
        var info=Marshal.AllocHGlobal(IntPtr.Size);
        var privileges=Marshal.StringToHGlobalUni(Traverse+"\0");
        try
        {
            Marshal.WriteInt32(info,1); // Service SID enabled without the write restriction.
            if(!ChangeServiceConfig2(service,5,info))throw Error("ConfigureCreatorServiceSid");
            Marshal.WriteIntPtr(info,privileges);
            if(!ChangeServiceConfig2(service,6,info))throw Error("ConfigureCreatorTraversePrivilege");
        }
        finally{Marshal.FreeHGlobal(privileges);Marshal.FreeHGlobal(info);}
    }

    private static void AssertConfiguration(ServiceHandle service,string name,string command)
        =>AssertServiceConfiguration(service,name,command,LocalService);

    internal static void AssertServiceConfiguration(ServiceHandle service,string name,string command,string account)
    {
        Inspect((IntPtr buffer,int size,out int needed)=>QueryServiceConfig(service,buffer,size,out needed),
            (buffer,size)=>
            {
                if(size<Marshal.SizeOf<Config>())throw WfpNative.Contract("CreatorServiceConfigTooShort");
                var config=Marshal.PtrToStructure<Config>(buffer);
                if(config.Type!=0x10 || config.Start!=3 || config.Error!=1 || config.Tag!=0)throw WfpNative.Contract("CreatorServiceConfigMismatch");
                AssertString(buffer,size,config.Image,command);
                AssertString(buffer,size,config.Account,account);
                AssertString(buffer,size,config.Display,name);
                if(config.Group!=IntPtr.Zero)AssertString(buffer,size,config.Group,"");
                if(config.Dependencies!=IntPtr.Zero)AssertString(buffer,size,config.Dependencies,"");
            });
        Inspect((IntPtr buffer,int size,out int needed)=>QueryServiceConfig2(service,5,buffer,size,out needed),
            (buffer,_)=>{if(Marshal.ReadInt32(buffer)!=1)throw WfpNative.Contract("CreatorServiceSidModeMismatch");});
        Inspect((IntPtr buffer,int size,out int needed)=>QueryServiceConfig2(service,6,buffer,size,out needed),
            (buffer,size)=>
            {
                if(size<IntPtr.Size)throw WfpNative.Contract("CreatorServicePrivilegesTooShort");
                AssertString(buffer,size,Marshal.ReadIntPtr(buffer),Traverse+"\0");
            });
        Inspect((IntPtr buffer,int size,out int needed)=>QueryServiceConfig2(service,2,buffer,size,out needed),
            (buffer,size)=>
            {
                if(size<Marshal.SizeOf<FailureActions>() || Marshal.PtrToStructure<FailureActions>(buffer).Count!=0)
                    throw WfpNative.Contract("CreatorServiceRecoveryActionsForbidden");
            });
        Inspect((IntPtr buffer,int size,out int needed)=>QueryServiceObjectSecurity(service,5,buffer,size,out needed),
            (buffer,size)=>
            {
                var bytes=new byte[size];Marshal.Copy(buffer,bytes,0,size);
                AssertServiceDescriptor(new RawSecurityDescriptor(bytes,0));
            });
    }
    internal static void AssertServiceDescriptor(RawSecurityDescriptor descriptor)
    {
        var owners=new HashSet<string>(StringComparer.Ordinal){"S-1-5-18","S-1-5-32-544"};
        if(descriptor.Owner?.Value!="S-1-5-32-544" || descriptor.DiscretionaryAcl is not {Count:2} acl)
            throw WfpNative.Contract("CreatorServiceRegistrationDaclMismatch");
        foreach(GenericAce entry in acl)
            if(entry is not CommonAce ace || ace.IsCallback || ace.AceFlags!=AceFlags.None || ace.AceQualifier!=AceQualifier.AccessAllowed ||
                ace.AccessMask!=0x000f01ff || !owners.Remove(ace.SecurityIdentifier.Value))
                throw WfpNative.Contract("CreatorServiceRegistrationUnexpectedGrant");
    }
    private delegate bool Query(IntPtr buffer,int capacity,out int needed);
    private static void Inspect(Query query,Action<IntPtr,int> use)
    {
        if(query(IntPtr.Zero,0,out var size) || Marshal.GetLastWin32Error()!=122 || size is <4 or >8192)
            throw WfpNative.Contract("CreatorServiceConfigSizeUnconfirmed");
        var buffer=Marshal.AllocHGlobal(size);
        try
        {
            if(!query(buffer,size,out _))throw Error("ReadCreatorServiceConfiguration");
            use(buffer,size);
        }
        finally{Marshal.FreeHGlobal(buffer);}
    }
    private static void AssertString(IntPtr buffer,int size,IntPtr address,string expected)
    {
        var offset=address.ToInt64()-buffer.ToInt64();
        var exact=expected+"\0";
        if(offset<0 || offset%2!=0 || offset>size-exact.Length*sizeof(char) ||
            !string.Equals(Marshal.PtrToStringUni(address,exact.Length),exact,StringComparison.OrdinalIgnoreCase))
            throw WfpNative.Contract("CreatorServiceConfigurationStringMismatch");
    }
    internal static Status ReadStatus(ServiceHandle service)
    {
        if(!QueryServiceStatusEx(service,0,out var status,Marshal.SizeOf<Status>(),out _))throw Error("ReadCreatorServiceStatus");
        if(status.Type!=0x10)throw WfpNative.Contract("CreatorServiceTypeMismatch");
        return status;
    }
    private static Win32Exception Error(string stage)
    {
        var result=new Win32Exception(Marshal.GetLastWin32Error(),stage);
        result.Data["Stage"]=stage;
        return result;
    }
    public void Dispose(){process?.Dispose();service.Dispose();manager.Dispose();}

    internal sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public ServiceHandle():base(true){}
        protected override bool ReleaseHandle()=>CloseServiceHandle(handle);
    }
    [StructLayout(LayoutKind.Sequential)] internal struct Status {internal uint Type,State,Controls,Win32Code,ServiceCode,CheckPoint,WaitHint,Pid,Flags;}
    [StructLayout(LayoutKind.Sequential)] private struct Config {internal uint Type,Start,Error;internal IntPtr Image,Group;internal uint Tag;internal IntPtr Dependencies,Account,Display;}
    [StructLayout(LayoutKind.Sequential)] private struct FailureActions {internal uint Reset;internal IntPtr Reboot,Command;internal uint Count;internal IntPtr Actions;}
    [DllImport("advapi32.dll",EntryPoint="OpenSCManagerW",CharSet=CharSet.Unicode,SetLastError=true)] internal static extern ServiceHandle OpenSCManager(string? machine,string? database,uint access);
    [DllImport("advapi32.dll",EntryPoint="OpenServiceW",CharSet=CharSet.Unicode,SetLastError=true)] internal static extern ServiceHandle OpenService(ServiceHandle manager,string name,uint access);
    [DllImport("advapi32.dll",EntryPoint="CreateServiceW",CharSet=CharSet.Unicode,SetLastError=true)]
    internal static extern ServiceHandle CreateService(ServiceHandle manager,string name,string display,uint access,uint type,uint start,uint error,string command,
        string? group,IntPtr tag,string? dependencies,string account,string? password);
    [DllImport("advapi32.dll",EntryPoint="ChangeServiceConfig2W",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool ChangeServiceConfig2(ServiceHandle service,uint kind,IntPtr data);
    [DllImport("advapi32.dll",EntryPoint="QueryServiceConfigW",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryServiceConfig(ServiceHandle service,IntPtr data,int size,out int needed);
    [DllImport("advapi32.dll",EntryPoint="QueryServiceConfig2W",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryServiceConfig2(ServiceHandle service,uint kind,IntPtr data,int size,out int needed);
    [DllImport("advapi32.dll",EntryPoint="StartServiceW",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool StartService(ServiceHandle service,uint argc,IntPtr argv);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryServiceStatusEx(ServiceHandle service,int kind,out Status status,int size,out int needed);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool SetServiceObjectSecurity(ServiceHandle service,uint info,byte[] descriptor);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryServiceObjectSecurity(ServiceHandle service,uint info,IntPtr descriptor,int size,out int needed);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] internal static extern bool DeleteService(ServiceHandle service);
    [DllImport("advapi32.dll")] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CloseServiceHandle(IntPtr service);
    [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)] private static extern SafeProcessHandle OpenProcess(uint access,[MarshalAs(UnmanagedType.Bool)]bool inherit,uint pid);
    [DllImport("kernel32.dll",ExactSpelling=true)] private static extern uint WaitForSingleObject(SafeProcessHandle process,uint milliseconds);
    [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetExitCodeProcess(SafeProcessHandle process,out uint exitCode);
}
