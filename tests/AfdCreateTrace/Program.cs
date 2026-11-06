using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using AfdObserverProtocol;

[assembly:DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

// Trusted diagnostic observer only. No child creation, arbitrary arguments,
// host ACL updates, WFP setters, capability/Token adjustment or retry API.
internal static class Program
{
    internal const string Root=@"C:\Program Files\ClaudeCodeProtection-AfdObserver-532de42-20261106-02";
    private const string Name="Cpc.AfdCreate.532de42.20261106.02";
    private static string Human=string.Empty;
    private static readonly Guid Provider=new("e53c6823-7bb8-44bb-90dc-3f86090d48a6");
    private static readonly Guid Session=new("3123256e-6993-41b1-b060-d6f057e28088");
    private const string DriverHash="F93639BB027E19DF5460C6D2BC69DB08139AF5D716743AC88BA15E581934DD76";
    private const int DurationSeconds=90;
    private static string Sddl=>"O:BAG:BAD:P(D;OICI;FA;;;S-1-15-2-1)(D;OICI;FA;;;S-1-15-2-2)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;"+Human+")";

    private static int Main(string[] args)
    {
        if(args.Length==1 && args[0]=="--inspect-own-token")
        {
            var scalar=new TokenObservation();string? errorType=null;int? errorCode=null;
            try{using var own=WindowsIdentity.GetCurrent();_=TokenFacts(own,scalar,requireFull:false);}
            catch(Exception error){errorType=error.GetType().Name;errorCode=error.HResult;}
            Console.WriteLine(JsonSerializer.Serialize(new {Scope="OWN_TOKEN_SCALARS_ONLY_NO_CAPTURE_OR_WRITES",Observation=scalar,
                FailureType=errorType,FailureCode=errorCode,TraceStarted=false},new JsonSerializerOptions{IncludeFields=true}));return 0;
        }
        if(args.Length==1 && args[0]=="--inspect")
        {
            Layout();
            Console.WriteLine(JsonSerializer.Serialize(new {Scope="AFD_OBSERVER_LAYOUT_ONLY_NO_CAPTURE",PropertiesBytes=Marshal.SizeOf<Properties>(),
                PropertiesFileOffset=Marshal.OffsetOf<Properties>(nameof(Properties.FileOffset)).ToInt32(),MaximumSeconds=DurationSeconds,
                MaximumFileMiB=16,Keyword=4,Level=4,Provider,EventIdFilterRequested=1000,FilterParametersBytes=Marshal.SizeOf<EventIdFilter.Parameters>(),
                FreshRootExists=Directory.Exists(Root),TraceStarted=false}));return 0;
        }
        if(args.Length!=1 || args[0]!="--run-fixed")return 125;
        using var identity=WindowsIdentity.GetCurrent();
        if(identity.User is null || !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {Console.WriteLine("FIXED_OBSERVER_REQUIRES_REVIEWED_HUMAN_UAC");return ObserverOutcome.Failure(ObserverStage.AdministrativeIdentityRequired);}
        Human=identity.User.Value;
        Layout();
        var stage=ObserverStage.Inputs;ObserverStage? failureStage=null;uint? native=null,stopCode=null;bool created=false,started=false,ownStopped=false,tokenUnchanged=false;
        ulong handle=0;IntPtr memory=IntPtr.Zero;Properties? final=null;
        var beginning=DateTime.UtcNow;string? failure=null;int? failureCode=null;string? before=null;
        FileStream? driver=null;EventIdFilter? eventFilter=null;
        var tokenBefore=new TokenObservation();var tokenAfter=new TokenObservation();
        try
        {
            stage=ObserverStage.FreshRootCheck;RequireFreshRoot();
            stage=ObserverStage.CreateOwnedDirectory;
            var descriptor=new RawSecurityDescriptor(Sddl);var bytes=new byte[descriptor.BinaryLength];descriptor.GetBinaryForm(bytes,0);
            var security=Marshal.AllocHGlobal(bytes.Length);
            try
            {
                Marshal.Copy(bytes,0,security,bytes.Length);var attributes=new SecurityAttributes{Length=24,Descriptor=security};
                if(!CreateDirectory(Root,ref attributes)){native=checked((uint)Marshal.GetLastWin32Error());throw new InvalidOperationException("AtomicFreshDirectoryCreationFailed");}
                created=true;
            }
            finally{Marshal.FreeHGlobal(security);}
            stage=ObserverStage.DirectorySeal;
            var observed=FileSystemAclExtensions.GetAccessControl(new DirectoryInfo(Root),AccessControlSections.Owner|AccessControlSections.Group|AccessControlSections.Access);
            var expected=new RawSecurityDescriptor(Sddl);var actual=new RawSecurityDescriptor(observed.GetSecurityDescriptorBinaryForm(),0);
            if(!observed.AreAccessRulesProtected || actual.Owner?.Value!=expected.Owner?.Value || actual.Group?.Value!=expected.Group?.Value ||
                !AclBytes(actual).AsSpan().SequenceEqual(AclBytes(expected)))throw new InvalidOperationException("FreshDirectorySealDiffers");
            // Seal the evidence sink first, so a pre-capture Token/query failure
            // can leave its bounded actual facts. All original capture gates
            // still run before StartTrace; no failed gate can start a trace.
            stage=ObserverStage.DriverOpen;
            driver=File.Open(@"C:\Windows\System32\drivers\afd.sys",FileMode.Open,FileAccess.Read,FileShare.Read);
            stage=ObserverStage.DriverHash;
            if(Convert.ToHexString(SHA256.HashData(driver))!=DriverHash)throw new InvalidOperationException("DriverChanged");
            stage=ObserverStage.TokenBefore;
            before=TokenFacts(identity,tokenBefore);
            stage=ObserverStage.SafetyBefore;
            Safety(beginning);
            stage=ObserverStage.StartNewTrace;
            memory=Allocate();native=StartTrace(out handle,Name,memory);
            if(native!=0)throw new InvalidOperationException("StartRejectedNoAdoption");started=true;
            stage=ObserverStage.ConfirmOwnTrace;AssertOwn(handle,memory);
            stage=ObserverStage.EnableFixedProvider;
            var provider=Provider;
            // Scope the manifest stream to event1000. This requests ETW event-ID
            // filtering, not PID filtering; actual event inventory remains a
            // decoder qualification and other actor metadata may still occur.
            eventFilter=new EventIdFilter(Session);
            native=EnableTraceEx2(handle,ref provider,1,4,4,0,1000,eventFilter.Pointer);
            if(native!=0)throw new InvalidOperationException("EnableRejected");
            stage=ObserverStage.EvidenceReadback;AssertEvidenceFile(Path.Combine(Root,"afd.etl"));
            stage=ObserverStage.PublishReady;
            WriteNew("ready.json",new {Scope="FIXED_AFD_KEYWORD4_OBSERVER_READY",Session,Provider,Name,StartedUtc=DateTime.UtcNow,
                DurationSeconds,MaxFileMiB=16,EventIdFilterRequested=1000,OwnerSidSHA256=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Human))),NoTargetProcessControl=true,NoPacketCaptureRequested=true});
            stage=ObserverStage.Observe;
            var watch=Stopwatch.StartNew();
            while(watch.ElapsedMilliseconds<DurationSeconds*1000)
            {Safety(beginning);Thread.Sleep(1000);}
        }
        catch(Exception error){failure=error.GetType().Name;failureCode=error.HResult;failureStage=stage;}
        finally
        {
            if(started)
            {
                try
                {
                    AssertOwn(handle,memory);stopCode=ControlTrace(handle,null,memory,1);
                    if(stopCode==0){ownStopped=true;final=Marshal.PtrToStructure<Properties>(memory);}
                    else failureStage??=ObserverStage.StopOwnTrace;
                }
                catch(Exception error){failure??=error.GetType().Name;failureCode??=error.HResult;failureStage??=ObserverStage.StopOwnTrace;}
            }
            if(memory!=IntPtr.Zero)Marshal.FreeHGlobal(memory);
            eventFilter?.Dispose();
            try{using var current=WindowsIdentity.GetCurrent();var after=TokenFacts(current,tokenAfter);tokenUnchanged=before is not null && current.User?.Value==Human && before==after;}
            catch(Exception error){failure??=error.GetType().Name;failureCode??=error.HResult;failureStage??=ObserverStage.TokenAfter;}
            if(!tokenUnchanged)failureStage??=ObserverStage.TokenAfter;
            driver?.Dispose();
            if(created)
            {
                try
                {
                    var file=Path.Combine(Root,"afd.etl");string? hash=null;long? length=null;
                    if(ownStopped && File.Exists(file))
                    {AssertEvidenceFile(file);using var etl=File.Open(file,FileMode.Open,FileAccess.Read,FileShare.Read);length=etl.Length;hash=Convert.ToHexString(SHA256.HashData(etl));}
                    WriteNew("terminal.json",new {Scope="FIXED_AFD_OBSERVER_TERMINAL_NOT_NETWORK_OR_PRIVACY_PASS",Stage=stage.ToString(),FailureStage=failureStage?.ToString(),NativeCode=native,StopCode=stopCode,
                        Failure=failure,FailureCode=failureCode,Started=started,OwnStopped=ownStopped,TokenUnchanged=tokenUnchanged,Session,Provider,
                        TokenBefore=tokenBefore,TokenAfter=tokenAfter,
                        OwnerSidSHA256=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Human))),
                        StartedUtc=beginning,EndedUtc=DateTime.UtcNow,Statistics=final is null ? null : new {final.Value.EventsLost,final.Value.BuffersWritten,final.Value.LogBuffersLost,final.Value.RealTimeBuffersLost},ETLSHA256=hash,ETLBytes=length,
                        CircularMayHaveOverwritten=final is null || (ulong)final.Value.BuffersWritten*64*1024>=16*1024*1024,
                        EventIdFilterRequested=1000,KernelBranchCorrelationVerified=false,TargetJobClosed=false,NetworkAdmission=false,NoAutomaticRetry=true});
                }
                catch(Exception error){failure??=error.GetType().Name;failureCode??=error.HResult;failureStage??=ObserverStage.TerminalPublication;}
            }
        }
        Console.WriteLine(JsonSerializer.Serialize(new {Scope="FIXED_AFD_OBSERVER_RESULT",Stage=stage.ToString(),FailureStage=failureStage?.ToString(),NativeCode=native,StopCode=stopCode,
            Failure=failure,FailureCode=failureCode,Started=started,OwnStopped=ownStopped,TokenUnchanged=tokenUnchanged}));
        if(failure is null && ownStopped && tokenUnchanged && failureStage is null)return 0;
        return ObserverOutcome.Failure(failureStage??stage);
    }
    private static byte[] AclBytes(RawSecurityDescriptor sd)
    {var acl=sd.DiscretionaryAcl??throw new InvalidDataException("DaclMissing");var b=new byte[acl.BinaryLength];acl.GetBinaryForm(b,0);return b;}
    private static void WriteNew(string name,object value)
    {
        var pending=Path.Combine(Root,name+".pending");
        using(var f=new FileStream(pending,FileMode.CreateNew,FileAccess.Write,FileShare.None))
        {f.Write(JsonSerializer.SerializeToUtf8Bytes(value,new JsonSerializerOptions{IncludeFields=true}));f.Flush(true);}
        AssertEvidenceFile(pending);
        File.Move(pending,Path.Combine(Root,name),false);
    }
    private static void AssertEvidenceFile(string path)
    {
        if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new InvalidOperationException("RedirectedEvidenceFile");
        var security=FileSystemAclExtensions.GetAccessControl(new FileInfo(path),AccessControlSections.Access);
        if(!security.AreAccessRulesCanonical)throw new InvalidOperationException("EvidenceDaclOrderUnknown");
        var descriptor=new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(),0);
        if(descriptor.DiscretionaryAcl is null)throw new InvalidOperationException("EvidenceDaclMissing");
        foreach(var sid in new[]{"S-1-15-2-1","S-1-15-2-2"})
        {
            bool denied=false;
            foreach(GenericAce ace in descriptor.DiscretionaryAcl)
                if(ace is CommonAce deny && deny.AceQualifier==AceQualifier.AccessDenied && (deny.AceFlags&AceFlags.InheritOnly)==0 &&
                    deny.SecurityIdentifier.Value==sid && (deny.AccessMask&0x1f01ff)==0x1f01ff)denied=true;
            if(!denied)throw new InvalidOperationException("EvidenceAppContainerDenyMissing");
        }
    }
    private static void RequireFreshRoot()
    {
        try{_ = File.GetAttributes(Root);throw new InvalidOperationException("FreshRootRequired");}
        catch(FileNotFoundException){}
        catch(DirectoryNotFoundException){}
        for(var parent=Directory.GetParent(Root);parent is not null;parent=parent.Parent)
            if((File.GetAttributes(parent.FullName)&FileAttributes.ReparsePoint)!=0)throw new InvalidOperationException("RedirectedParentRejected");
    }
    private sealed class TokenObservation
    {
        public int? QueryKind,RequestedBytes,ReturnedBytes,Win32Error;
        public string? QueryMode;
        public bool? ThreadImpersonationDetected;
        public uint? IsAppContainer,ElevationType,IsElevated;
        public bool Complete;
    }
    private static string TokenFacts(WindowsIdentity identity,TokenObservation observation,bool requireFull=true)
    {
        byte[] Read(int kind)
        {
            observation.QueryKind=kind;
            observation.ReturnedBytes=null;observation.Win32Error=null;int size=4;
            if(kind is 18 or 20 or 29)
            {observation.QueryMode="FIXED_DWORD";observation.RequestedBytes=4;}
            else
            {
                observation.QueryMode="VARIABLE_SIZED";
                var sized=GetTokenInformation(identity.Token,kind,IntPtr.Zero,0,out size);observation.Win32Error=sized?0:Marshal.GetLastWin32Error();observation.RequestedBytes=size;
                if(sized || observation.Win32Error!=122 || size is <4 or >65536)
                    throw new InvalidOperationException("TokenSizeUnavailable");
            }
            var p=Marshal.AllocHGlobal(size);
            try{var read=GetTokenInformation(identity.Token,kind,p,size,out var used);observation.Win32Error=read?0:Marshal.GetLastWin32Error();observation.ReturnedBytes=used;
                if(!read || used!=size)throw new InvalidOperationException("TokenReadUnavailable");
                var b=new byte[size];Marshal.Copy(p,b,0,size);return b;}
            finally{Marshal.FreeHGlobal(p);}
        }
        using var impersonating=WindowsIdentity.GetCurrent(true);
        observation.ThreadImpersonationDetected=impersonating is not null;
        observation.IsAppContainer=BitConverter.ToUInt32(Read(29));observation.ElevationType=BitConverter.ToUInt32(Read(18));observation.IsElevated=BitConverter.ToUInt32(Read(20));
        if(impersonating is not null || observation.IsAppContainer!=0 || requireFull && (observation.ElevationType!=2 || observation.IsElevated!=1))
            throw new InvalidOperationException("FullHumanTokenWithoutImpersonationRequired");
        var result=Convert.ToHexString(SHA256.HashData(Read(3)))+":"+Convert.ToHexString(Read(18))+":"+Convert.ToHexString(Read(20));
        observation.Complete=true;return result;
    }
    private static void Safety(DateTime beginning)
    {
        foreach(var name in new[]{"BFE","AVP21.26"})
        {
            var manager=OpenSCManager(null,null,1);if(manager==IntPtr.Zero)throw new InvalidOperationException("ServiceManagerUnavailable");
            try
            {
                var service=OpenService(manager,name,4);if(service==IntPtr.Zero)throw new InvalidOperationException("ServiceUnavailable");
                try{if(!QueryServiceStatusEx(service,0,out var status,36,out _) || status.State!=4)throw new InvalidOperationException("SafetyServiceNotRunning");}
                finally{CloseServiceHandle(service);}
            }
            finally{CloseServiceHandle(manager);}
        }
        var query="*[System[TimeCreated[@SystemTime >= '"+beginning.ToString("o")+"']]]";
        using var reader=new EventLogReader(new EventLogQuery("Application",PathType.LogName,query){ReverseDirection=true});
        for(int i=0;i<256;i++)
        {
            using var item=reader.ReadEvent();if(item is null)return;
            var provider=item.ProviderName??"";
            if(provider.Contains("kaspersky",StringComparison.OrdinalIgnoreCase) || provider.Contains("avp",StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("NewAvObservationStopCapture");
        }
        throw new InvalidOperationException("PublicAvWindowCoverageUnknown");
    }
    private static void AssertOwn(ulong handle,IntPtr memory)
    {
        Initialize(memory);var code=ControlTrace(handle,null,memory,0);
        if(code!=0 || Marshal.PtrToStructure<Properties>(memory).Wnode.Guid!=Session)throw new InvalidOperationException("OwnTraceNotConfirmedNoStop");
    }
    private static IntPtr Allocate()
    {var p=Marshal.AllocHGlobal(8192);try{Initialize(p);return p;}catch{Marshal.FreeHGlobal(p);throw;}}
    private static void Initialize(IntPtr p)
    {
        Marshal.Copy(new byte[8192],0,p,8192);
        var file=Encoding.Unicode.GetBytes(Path.Combine(Root,"afd.etl")+"\0");var name=Encoding.Unicode.GetBytes(Name+"\0");
        var props=new Properties{Wnode=new(){BufferSize=8192,Guid=Session,ClientContext=1,Flags=0x20000},BufferSize=64,MinimumBuffers=8,MaximumBuffers=16,
            MaximumFileSize=16,LogFileMode=2,FlushTimer=1,LoggerOffset=120,FileOffset=checked((uint)(120+name.Length))};
        Marshal.StructureToPtr(props,p,false);Marshal.Copy(name,0,IntPtr.Add(p,120),name.Length);Marshal.Copy(file,0,IntPtr.Add(p,(int)props.FileOffset),file.Length);
    }
    private static void Layout()
    {EventIdFilter.AssertLayout();if(!Environment.Is64BitProcess || Marshal.SizeOf<SecurityAttributes>()!=24 || Marshal.SizeOf<Wnode>()!=48 || Marshal.SizeOf<Properties>()!=120 || Marshal.OffsetOf<Properties>(nameof(Properties.FileOffset)).ToInt32()!=112 || Marshal.OffsetOf<Properties>(nameof(Properties.LoggerOffset)).ToInt32()!=116)throw new PlatformNotSupportedException("FixedX64EtwAbiRequired");}
    [StructLayout(LayoutKind.Sequential)] private struct SecurityAttributes {public uint Length;public IntPtr Descriptor;public int Inherit;}
    [StructLayout(LayoutKind.Sequential)] internal struct Wnode
    {public uint BufferSize,ProviderId;public ulong HistoricalContext,TimeStamp;public Guid Guid;public uint ClientContext,Flags;}
    [StructLayout(LayoutKind.Sequential)] internal struct Properties
    {public Wnode Wnode;public uint BufferSize,MinimumBuffers,MaximumBuffers,MaximumFileSize,LogFileMode,FlushTimer,EnableFlags;public int AgeLimit;
        public uint NumberOfBuffers,FreeBuffers,EventsLost,BuffersWritten,LogBuffersLost,RealTimeBuffersLost;public IntPtr LoggerThreadId;public uint FileOffset,LoggerOffset;}
    [StructLayout(LayoutKind.Sequential)] private struct ServiceStatus
    {public uint Type,State,Accepted,Win32Exit,ServiceExit,CheckPoint,WaitHint,Pid,Flags;}
    [DllImport("advapi32.dll",EntryPoint="StartTraceW",CharSet=CharSet.Unicode,ExactSpelling=true)] private static extern uint StartTrace(out ulong handle,string name,IntPtr properties);
    [DllImport("advapi32.dll",EntryPoint="ControlTraceW",CharSet=CharSet.Unicode,ExactSpelling=true)] private static extern uint ControlTrace(ulong handle,string? name,IntPtr properties,uint code);
    [DllImport("advapi32.dll",ExactSpelling=true)] private static extern uint EnableTraceEx2(ulong handle,ref Guid provider,uint code,byte level,ulong any,ulong all,uint timeout,IntPtr parameters);
    [DllImport("advapi32.dll",ExactSpelling=true,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr buffer,int length,out int needed);
    [DllImport("advapi32.dll",EntryPoint="OpenSCManagerW",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)] private static extern IntPtr OpenSCManager(string? machine,string? database,uint access);
    [DllImport("advapi32.dll",EntryPoint="OpenServiceW",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)] private static extern IntPtr OpenService(IntPtr manager,string name,uint access);
    [DllImport("advapi32.dll",ExactSpelling=true,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryServiceStatusEx(IntPtr service,int kind,out ServiceStatus status,uint size,out uint needed);
    [DllImport("advapi32.dll",ExactSpelling=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CloseServiceHandle(IntPtr handle);
    [DllImport("kernel32.dll",EntryPoint="CreateDirectoryW",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CreateDirectory(string path,ref SecurityAttributes attributes);
}
