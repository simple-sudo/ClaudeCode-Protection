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
    private readonly ProtectedState state;
    private readonly VerifiedVersion version;
    private readonly ServiceHandle manager,service;
    private readonly string image,name,command,intentHash;
    private bool startAttempted,deleteAttempted;
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
            var descriptor=new RawSecurityDescriptor("O:BAD:P(A;;0x000f01ff;;;SY)(A;;0x000f01ff;;;BA)");
            var bytes=new byte[descriptor.BinaryLength];descriptor.GetBinaryForm(bytes,0);
            if(!SetServiceObjectSecurity(service,5,bytes))throw Error("SealCreatorServiceRegistration");
            ConfigureIdentity(service);
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

    internal void AssertJobPreparation(ProtectedState exactState,VerifiedVersion exactVersion)
    {
        AssertOriginal();
        if(!ReferenceEquals(state,exactState) || !ReferenceEquals(version,exactVersion) || startAttempted)
            throw WfpNative.Contract("CreatorServiceJobPreparationBindingMismatch");
    }

    internal SafeProcessHandle StartAndHold(OwnedKernelJob job,SessionZeroCreatorChannel preparedChannel)
    {
        AssertJobPreparation(state,version);
        if(job.JobId!=JobId || job.SessionZeroCreatorSid!=Sid.Value || !preparedChannel.IsPreparedFor(job))
            throw WfpNative.Contract("CreatorServiceStartNeedsExactJobAndPipe");
        var before=ReadStatus(service);
        if(before.State!=1)throw WfpNative.Contract("FreshCreatorServiceNotStopped");
        state.WriteNew("creator-service-start-"+JobId+".json",JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,IntentSHA256=intentHash}));
        startAttempted=true;
        if(!StartService(service,0,IntPtr.Zero))throw Error("StartFixedCreatorService");
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
                    if(held.IsInvalid)throw Error("HoldOriginalCreatorProcess");
                    SessionZeroCreatorChannel.AssertImage(held,image);
                    var after=ReadStatus(service);
                    if(after.State!=4 || after.Pid!=status.Pid || WaitForSingleObject(held,0)!=258)
                        throw WfpNative.Contract("CreatorServiceProcessChanged");
                    process=held;channel=preparedChannel;return held;
                }
                catch{held.Dispose();throw;}
            }
            Thread.Sleep(25);
        }
        throw new TimeoutException("Original creator service did not become ready");
    }

    internal void RemoveNeverStarted()
    {
        AssertOriginal();
        if(startAttempted || state.ReadOptional("creator-service-start-"+JobId+".json") is not null)
            throw WfpNative.Contract("CreatorServiceMayHaveStarted");
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
        var watch=Stopwatch.StartNew();
        while(watch.ElapsedMilliseconds<5000)
        {
            using var observation=OpenService(manager,name,4);
            var code=Marshal.GetLastWin32Error();
            if(observation.IsInvalid && code==1060)
            {
                state.WriteNew(DoneLeaf(JobId),JsonSerializer.SerializeToUtf8Bytes(new {SchemaVersion=1,IntentSHA256=intentHash,Disposition=disposition}));
                return;
            }
            if(!observation.IsInvalid || code!=1072)throw WfpNative.Contract("CreatorServiceNameRemovalUnconfirmed");
            Thread.Sleep(25);
        }
        throw new TimeoutException("Original creator service deletion is pending");
    }

    private void AssertOriginal()
    {
        state.AssertHeld();version.AssertHeld(state);
        if(deleteAttempted || manager.IsClosed || service.IsClosed || state.Read(IntentLeaf(JobId),4096).SHA256!=intentHash)
            throw WfpNative.Contract("CreatorServiceOriginalRegistrationUnavailable");
        AssertConfiguration(service,name,command);
    }

    private static string IntentLeaf(string id)=>IntentPrefix+Identifiers.Hex32(id)+".json";
    private static string DoneLeaf(string id)=>"creator-service-removed-"+Identifiers.Hex32(id)+".json";
    internal static void AssertNoPending(ProtectedState state,SessionZeroCreatorRegistration? preparing)
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
            if(preparing is not null && ReferenceEquals(preparing.state,state) && preparing.JobId==id &&
                preparing.intentHash==raw.SHA256 && !preparing.startAttempted && !preparing.deleteAttempted && !preparing.service.IsClosed)
                continue;
            var done=state.ReadOptional(DoneLeaf(id))??throw WfpNative.Contract("CreatorServiceRegistrationRequiresRecovery");
            using var receipt=JsonDocument.Parse(done.Bytes,new JsonDocumentOptions{MaxDepth=2});
            var start=state.ReadOptional("creator-service-start-"+id+".json");
            if(start is not null)
            {
                using var started=JsonDocument.Parse(start.Bytes,new JsonDocumentOptions{MaxDepth=2});
                StrictJson.Fields(started.RootElement,"SchemaVersion","IntentSHA256");
                if(started.RootElement.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(started.RootElement,"IntentSHA256")!=raw.SHA256)
                    throw WfpNative.Contract("CreatorServiceStartProofMismatch");
            }
            ValidateRemoval(receipt.RootElement,raw.SHA256,start is not null);
        }
    }
    internal static void ValidateIntent(JsonElement record,string install,string id)
    {
        StrictJson.Fields(record,"SchemaVersion","InstallationId","JobId","Release","ManifestHash");
        if(record.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(record,"InstallationId")!=install || StrictJson.Text(record,"JobId")!=id)
            throw WfpNative.Contract("CreatorServiceIntentBindingMismatch");
        _=Identifiers.Hex32(StrictJson.Text(record,"Release"));_=Identifiers.Hash(StrictJson.Text(record,"ManifestHash"));
    }
    internal static void ValidateRemoval(JsonElement record,string intentHash,bool started)
    {
        StrictJson.Fields(record,"SchemaVersion","IntentSHA256","Disposition");
        if(record.GetProperty("SchemaVersion").GetInt32()!=1 || StrictJson.Text(record,"IntentSHA256")!=intentHash ||
            StrictJson.Text(record,"Disposition")!=(started?Closed:Unstarted))
            throw WfpNative.Contract("CreatorServiceRemovalProofMismatch");
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
    {
        Inspect((IntPtr buffer,int size,out int needed)=>QueryServiceConfig(service,buffer,size,out needed),
            (buffer,size)=>
            {
                if(size<Marshal.SizeOf<Config>())throw WfpNative.Contract("CreatorServiceConfigTooShort");
                var config=Marshal.PtrToStructure<Config>(buffer);
                if(config.Type!=0x10 || config.Start!=3 || config.Error!=1 || config.Tag!=0)throw WfpNative.Contract("CreatorServiceConfigMismatch");
                AssertString(buffer,size,config.Image,command);
                AssertString(buffer,size,config.Account,LocalService);
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
    private static Status ReadStatus(ServiceHandle service)
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

    private sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public ServiceHandle():base(true){}
        protected override bool ReleaseHandle()=>CloseServiceHandle(handle);
    }
    [StructLayout(LayoutKind.Sequential)] private struct Status {internal uint Type,State,Controls,Win32Code,ServiceCode,CheckPoint,WaitHint,Pid,Flags;}
    [StructLayout(LayoutKind.Sequential)] private struct Config {internal uint Type,Start,Error;internal IntPtr Image,Group;internal uint Tag;internal IntPtr Dependencies,Account,Display;}
    [StructLayout(LayoutKind.Sequential)] private struct FailureActions {internal uint Reset;internal IntPtr Reboot,Command;internal uint Count;internal IntPtr Actions;}
    [DllImport("advapi32.dll",EntryPoint="OpenSCManagerW",CharSet=CharSet.Unicode,SetLastError=true)] private static extern ServiceHandle OpenSCManager(string? machine,string? database,uint access);
    [DllImport("advapi32.dll",EntryPoint="OpenServiceW",CharSet=CharSet.Unicode,SetLastError=true)] private static extern ServiceHandle OpenService(ServiceHandle manager,string name,uint access);
    [DllImport("advapi32.dll",EntryPoint="CreateServiceW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern ServiceHandle CreateService(ServiceHandle manager,string name,string display,uint access,uint type,uint start,uint error,string command,
        string? group,IntPtr tag,string? dependencies,string account,string? password);
    [DllImport("advapi32.dll",EntryPoint="ChangeServiceConfig2W",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool ChangeServiceConfig2(ServiceHandle service,uint kind,IntPtr data);
    [DllImport("advapi32.dll",EntryPoint="QueryServiceConfigW",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryServiceConfig(ServiceHandle service,IntPtr data,int size,out int needed);
    [DllImport("advapi32.dll",EntryPoint="QueryServiceConfig2W",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryServiceConfig2(ServiceHandle service,uint kind,IntPtr data,int size,out int needed);
    [DllImport("advapi32.dll",EntryPoint="StartServiceW",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool StartService(ServiceHandle service,uint argc,IntPtr argv);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryServiceStatusEx(ServiceHandle service,int kind,out Status status,int size,out int needed);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool SetServiceObjectSecurity(ServiceHandle service,uint info,byte[] descriptor);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryServiceObjectSecurity(ServiceHandle service,uint info,IntPtr descriptor,int size,out int needed);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool DeleteService(ServiceHandle service);
    [DllImport("advapi32.dll")] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CloseServiceHandle(IntPtr service);
    [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)] private static extern SafeProcessHandle OpenProcess(uint access,[MarshalAs(UnmanagedType.Bool)]bool inherit,uint pid);
    [DllImport("kernel32.dll",ExactSpelling=true)] private static extern uint WaitForSingleObject(SafeProcessHandle process,uint milliseconds);
    [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetExitCodeProcess(SafeProcessHandle process,out uint exitCode);
}
