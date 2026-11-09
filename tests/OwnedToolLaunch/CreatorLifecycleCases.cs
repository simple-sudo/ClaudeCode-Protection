using System.Buffers.Binary;
using System.ComponentModel;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

internal static class CreatorLifecycleCases
{
    internal static void Run(Assembly library)
    {
        const BindingFlags methods=BindingFlags.NonPublic|BindingFlags.Static;
        MethodInfo Method(string type,string name)=>library.GetType("ProtectionLifecycle."+type,true)!.GetMethod(name,methods)!;
        var count=0;
        void Check(bool value)
        {
            if(!value)throw new InvalidOperationException($"Creator lifecycle boundary case {count+1} failed");
            count++;
        }
        void Refused(Action action)
        {
            try{action();}
            catch(TargetInvocationException error) when(error.InnerException is InvalidDataException or EndOfStreamException){Check(true);return;}
            Check(false);
        }

        var serviceName=Method("SessionZeroCreatorService","JobIdFromServiceName");
        var jobId=new string('a',32);
        Check((string?)serviceName.Invoke(null,["CpcSessionCreator."+jobId])==jobId);
        Refused(()=>serviceName.Invoke(null,["CpcSessionCreator."+jobId+"x"]));
        Refused(()=>serviceName.Invoke(null,["CpcSessionCreator."+jobId.ToUpperInvariant()]));
        Refused(()=>serviceName.Invoke(null,["OtherService."+jobId]));
        var acl=(RawAcl)Method("SessionZeroCreatorService","CreateObserverDacl").Invoke(null,null)!;
        Check(acl.Count==3);
        Check(acl[0] is CommonAce deny && deny.SecurityIdentifier.Value=="S-1-3-4" && deny.AceQualifier==AceQualifier.AccessDenied && deny.AccessMask==0x000c0000);
        Check(acl[1] is CommonAce system && system.SecurityIdentifier.Value=="S-1-5-18" && system.AccessMask==0x001fffff);
        Check(acl[2] is CommonAce observer && observer.SecurityIdentifier.Value=="S-1-5-32-544" && observer.AccessMask==0x00101000);
        var ownerPolicy=Method("SessionZeroCreatorService","IsTrustedCreatorProcessOwner");
        var serviceSid=new SecurityIdentifier("S-1-5-80-1-2-3-4-5");
        bool Trusted(SecurityIdentifier owner)=>ownerPolicy.Invoke(null,[owner,serviceSid]) is true;
        foreach(var owner in new[]{"S-1-5-19","S-1-5-18","S-1-5-32-544",serviceSid.Value})
            Check(Trusted(new SecurityIdentifier(owner)));
        foreach(var owner in new[]{"S-1-5-20","S-1-5-80-1-2-3-4-6","S-1-5-80-0","S-1-5-32-545","S-1-5-21-1-2-3-1001"})
            Check(!Trusted(new SecurityIdentifier(owner)));
        using(var identity=WindowsIdentity.GetCurrent())
            Check(identity.User is { } host && !Trusted(host));
        var readProcess=Method("KernelJobSeal","ReadCreatorProcessDescriptor");
        var readLegacy=Method("KernelJobSeal","ReadOwnerDacl");
        using(var self=OpenProcess(0x00020000,false,(uint)Environment.ProcessId))
        {
            Check(!self.IsInvalid);
            var old=(RawSecurityDescriptor)readLegacy.Invoke(null,[self,false])!;
            var current=(RawSecurityDescriptor)readProcess.Invoke(null,[self])!;
            static byte[] Dacl(RawSecurityDescriptor descriptor)
            {
                var acl=descriptor.DiscretionaryAcl!;
                var data=new byte[acl.BinaryLength];acl.GetBinaryForm(data,0);return data;
            }
            Check(current.Owner is { } owner && old.Owner is { } original && owner.Equals(original) && Dacl(current).SequenceEqual(Dacl(old)));
        }
        using(var limited=OpenProcess(0x00001000,false,(uint)Environment.ProcessId))
        {
            Check(!limited.IsInvalid);
            var deniedRead=false;
            try{_=readProcess.Invoke(null,[limited]);}
            catch(TargetInvocationException error)when(error.InnerException is Win32Exception {NativeErrorCode:5}){deniedRead=true;}
            Check(deniedRead);
        }
        var encode=Method("SessionZeroCreatorService","EncodeFailure");
        var phaseType=encode.GetParameters()[0].ParameterType;
        var describe=Method("SessionZeroCreatorService","DescribeStopped");
        (string? Stage,uint Code) Stopped(uint win32,uint code)
        {
            var failure=describe.Invoke(null,[win32,code])!;
            return ((string?)failure.GetType().GetProperty("Stage",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(failure),
                (uint)failure.GetType().GetProperty("Status",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(failure)!);
        }
        foreach(var phase in Enum.GetNames(phaseType))
        foreach(var code in new[]{5u,0x80131501u,0x80070005u,0x80004005u})
        {
            var encoded=(uint)encode.Invoke(null,[Enum.Parse(phaseType,phase),code])!;
            Check(Stopped(1066,encoded)==("CreatorService"+phase,code));
        }
        var unknown=(uint)encode.Invoke(null,[Enum.Parse(phaseType,"VerifyToken"),0x81234567u])!;
        Check(Stopped(1066,unknown)==("CreatorServiceVerifyTokenCodeNotEncoded",unknown));
        Check(Stopped(1066,unknown|1u)==("CreatorServiceStoppedBeforeBinding",unknown|1u));
        var reserved=(unknown&~0x00f00000u)|0x00f00000u;
        Check(Stopped(1066,reserved)==("CreatorServiceStoppedBeforeBinding",reserved));
        Check(Stopped(1066,0xc5411501u)==("CreatorServiceSealProcess",0x80131501u)); // Existing receipt encoding.
        Check(Stopped(1066,0x80131501u)==("CreatorServiceStoppedBeforeBinding",0x80131501u));
        Check(Stopped(1053,0)==("CreatorServiceStoppedBeforeBinding",1053));
        var encodeOwner=Method("SessionZeroCreatorService","EncodeOwnerFailure");
        var relationType=encodeOwner.GetParameters()[0].ParameterType;
        var startup=Method("SessionZeroCreatorService","IsReportedStartupFailure");
        foreach(var name in Enum.GetNames(relationType))
        {
            var encoded=(uint)encodeOwner.Invoke(null,[Enum.Parse(relationType,name)])!;
            Check(Stopped(1066,encoded)==("CreatorServiceValidateProcessOwner."+name,1307));
            Check(startup.Invoke(null,[1066u,encoded]) is true);
        }
        Check(startup.Invoke(null,[1066u,0xc5d4ffffu]) is false);
        Check(startup.Invoke(null,[1066u,0xc5940001u]) is false);
        var classify=Method("SessionZeroCreatorService","ClassifyOwner");
        var logonSid=new SecurityIdentifier("S-1-5-5-0-1234");
        var localService=new SecurityIdentifier("S-1-5-19");
        (string,uint)[] ownLogon=[(logonSid.Value,0xc0000004u)];
        string? Classify(SecurityIdentifier owner,SecurityIdentifier? tokenOwner,(string,uint)[] groups)=>
            classify.Invoke(null,[owner,tokenOwner,groups])?.ToString();
        Check(Classify(logonSid,localService,ownLogon)=="TokenLogon");
        Check(Classify(logonSid,logonSid,ownLogon)=="TokenDefaultAndLogon");
        Check(Classify(logonSid,localService,[(logonSid.Value,0xc0000014u)])=="OtherLogonSid");
        Check(Classify(logonSid,localService,[])=="OtherLogonSid");
        Check(Classify(localService,localService,ownLogon)=="TokenDefault");
        Check(Classify(serviceSid,localService,ownLogon)=="OtherOwner");
        var broker=library.GetType("ProtectionLifecycle.InstalledBroker",true)!;
        Check(broker.GetMethod("RunSessionZeroOfflineCreatorService")!.Invoke(null,null) is 124); // Ordinary SCM refusal.
        var layout=Method("FixedLayout","FromWindows").Invoke(null,null)!;
        var versions=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"ClaudeCodeProtection","versions");
        var image=Path.Combine(versions,jobId,"bin","admin","ProtectionBroker.exe");
        var resolve=Method("AtomicChild","ResolveSessionZeroImage");
        Check((string?)resolve.Invoke(null,[layout,image])==image);
        Refused(()=>resolve.Invoke(null,[layout,Path.Combine(versions,jobId,"bin","admin","Other.exe")]));
        Refused(()=>resolve.Invoke(null,[layout,Path.Combine(versions,jobId,"bin","daily","ProtectionBroker.exe")]));
        Refused(()=>resolve.Invoke(null,[layout,null]));
        var matches=Method("SessionZeroCreatorProfile","MatchesStorage");
        var storage=Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,"profile-fixture"));
        Check(matches.Invoke(null,[storage,storage]) is true);
        Check(matches.Invoke(null,[storage,Path.Combine(storage,"AC")]) is true);
        Check(matches.Invoke(null,[storage,Path.Combine(storage,"AC","Temp")]) is false);
        Check(matches.Invoke(null,[storage,storage+"-replacement"]) is false);

        var close=Method("SessionZeroCreatorTerminal","CloseFrame");
        var assertClose=Method("SessionZeroCreatorTerminal","AssertCloseFrame");
        var makeReceipt=Method("SessionZeroCreatorTerminal","CreateReceipt");
        var readReceipt=Method("SessionZeroCreatorTerminal","ReadReceipt");
        var nonce=Enumerable.Repeat((byte)17,16).ToArray();
        var wrong=Enumerable.Repeat((byte)18,16).ToArray();
        var frame=(byte[])close.Invoke(null,[nonce])!;
        Check(frame.Length==20 && frame.AsSpan(0,4).SequenceEqual("CCS1"u8));
        _=assertClose.Invoke(null,[frame,nonce]);Check(true);
        Refused(()=>assertClose.Invoke(null,[frame,wrong]));
        Refused(()=>assertClose.Invoke(null,[frame[..19],nonce]));
        var outputType=library.GetType("ProtectionLifecycle.OfflineConsoleOutput",true)!;
        object Output(byte[] bytes,bool overflow)=>Activator.CreateInstance(outputType,[bytes,overflow])!;
        var frameOutput=new byte[]{1,2,3};
        var frameError=new byte[]{4,5};
        var receipt=(byte[])makeReceipt.Invoke(null,[nonce,Output(frameOutput,false),Output(frameError,false)])!;
        object Read(byte[] payload,byte[] binding)
        {
            using var stream=new MemoryStream(payload,false);
            return readReceipt.Invoke(null,[stream,binding,CancellationToken.None])!;
        }
        var read=Read(receipt,nonce);
        var returnedOutput=read.GetType().GetField("Item1")!.GetValue(read)!;
        var returnedError=read.GetType().GetField("Item2")!.GetValue(read)!;
        var bytesProperty=outputType.GetProperty("Bytes")!;
        Check(((byte[])bytesProperty.GetValue(returnedOutput)!).SequenceEqual(frameOutput) &&
            ((byte[])bytesProperty.GetValue(returnedError)!).SequenceEqual(frameError));
        Refused(()=>Read(receipt,wrong));
        Refused(()=>Read(receipt[..^1],nonce));
        Refused(()=>makeReceipt.Invoke(null,[nonce,Output(new byte[4097],false),Output([],false)]));
        Refused(()=>makeReceipt.Invoke(null,[nonce,Output(frameOutput,true),Output([],false)]));
        var malformed=(byte[])receipt.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(malformed.AsSpan(20),4);
        Refused(()=>Read(malformed,nonce));
        malformed=(byte[])receipt.Clone();
        BinaryPrimitives.WriteUInt16LittleEndian(malformed.AsSpan(24),4097);
        Refused(()=>Read(malformed,nonce));
        Console.WriteLine($"PASS {count} creator lifecycle checks; actual SCM rejection outside service, fixed image and profile paths, observer rights, terminal and bounded output frames. No service registration, profile mutation, process creation or WFP.");
        var previous=count;
        var intent=Method("SessionZeroCreatorRegistration","ValidateIntent");
        var removed=Method("SessionZeroCreatorRegistration","ValidateRemoval");
        var descriptor=Method("SessionZeroCreatorRegistration","AssertServiceDescriptor");
        var command=Method("SessionZeroCreatorRegistration","BuildCommand");
        var installation=new string('b',32);
        var release=new string('c',32);
        var hash=new string('A',64);
        void AssertIntent(object data,string expectedJob)
        {
            using var doc=JsonDocument.Parse(JsonSerializer.SerializeToUtf8Bytes(data));
            _=intent.Invoke(null,[doc.RootElement,installation,expectedJob]);
        }
        var expected=new {SchemaVersion=1,InstallationId=installation,JobId=jobId,Release=release,ManifestHash=hash};
        AssertIntent(expected,jobId);Check(true);
        Refused(()=>AssertIntent(expected,release));
        Refused(()=>AssertIntent(expected with {InstallationId=release},jobId));
        Refused(()=>AssertIntent(expected with {Release="wrong"},jobId));
        Refused(()=>AssertIntent(new{SchemaVersion=1,InstallationId=installation,JobId=jobId,Release=release,ManifestHash=hash,Command=image},jobId));
        void AssertRemoval(string disposition,bool started,string expectedHash,bool startupFailed=false)
        {
            using var doc=JsonDocument.Parse(JsonSerializer.SerializeToUtf8Bytes(new{SchemaVersion=1,IntentSHA256=hash,Disposition=disposition}));
            _=removed.Invoke(null,[doc.RootElement,expectedHash,started,startupFailed]);
        }
        const string closed="PROFILE_AND_SERVICE_CLOSED",unstarted="SERVICE_REMOVED_BEFORE_START";
        const string startupRemoved="SERVICE_REMOVED_AFTER_STARTUP_FAILURE_WITHOUT_JOB";
        AssertRemoval(closed,true,hash);Check(true);
        AssertRemoval(unstarted,false,hash);Check(true);
        Refused(()=>AssertRemoval(closed,false,hash));
        Refused(()=>AssertRemoval(unstarted,true,hash));
        Refused(()=>AssertRemoval(closed,true,new string('B',64)));
        AssertRemoval(startupRemoved,true,hash,startupFailed:true);Check(true);
        Refused(()=>AssertRemoval(startupRemoved,true,hash));
        Refused(()=>AssertRemoval(startupRemoved,false,hash,startupFailed:true));
        Refused(()=>AssertRemoval(closed,true,hash,startupFailed:true));
        var validateFailure=Method("SessionZeroCreatorRegistration","ValidateStartupFailure");
        var startHash=new string('B',64);
        uint ServiceCode(string phase)=>(uint)encode.Invoke(null,[Enum.Parse(phaseType,phase),0x80131501u])!;
        var startupEvidence=new {SchemaVersion=1,IntentSHA256=hash,StartSHA256=startHash,ServiceCode=ServiceCode("SealProcess")};
        void AssertStartupEvidence(object evidence)
            =>_=validateFailure.Invoke(null,[JsonSerializer.SerializeToUtf8Bytes(evidence),hash,startHash]);
        AssertStartupEvidence(startupEvidence);Check(true);
        foreach(var phase in new[]{"VerifyTokenGroups","VerifyTokenPrivileges","ReadProcessSecurity","WriteProcessSecurity","VerifyProcessSecurity",
            "OpenProcessSecurity","ValidateProcessOwner"})
        { AssertStartupEvidence(startupEvidence with {ServiceCode=ServiceCode(phase)});Check(true); }
        Refused(()=>AssertStartupEvidence(startupEvidence with {IntentSHA256=startHash}));
        Refused(()=>AssertStartupEvidence(startupEvidence with {StartSHA256=hash}));
        Refused(()=>AssertStartupEvidence(startupEvidence with {ServiceCode=0x80131501u}));
        Refused(()=>AssertStartupEvidence(startupEvidence with {ServiceCode=ServiceCode("OfflineProtocol")}));
        Check((string?)command.Invoke(null,[image])=="\""+image+"\" session-zero-offline-creator");
        Refused(()=>command.Invoke(null,[image+" arbitrary"]));
        const string sddl="O:BAD:P(A;;0x000f01ff;;;SY)(A;;0x000f01ff;;;BA)";
        _=descriptor.Invoke(null,[new RawSecurityDescriptor(sddl)]);Check(true);
        foreach(var invalid in new[]{sddl+"(A;;0x10;;;AU)",sddl.Replace("O:BA","O:LS",StringComparison.Ordinal),
            sddl.Replace(";;;BA",";;;SY",StringComparison.Ordinal),sddl.Replace("0x000f01ff","0x00020000",StringComparison.Ordinal)})
            Refused(()=>descriptor.Invoke(null,[new RawSecurityDescriptor(invalid)]));
        var inventory=Method("ProtectedState","RequireFixedInventoryPrefix");
        _=inventory.Invoke(null,["creator-service-intent-"]);Check(true);
        Console.WriteLine($"PASS {count-previous} creator registration checks; exact image command, SCM descriptor, protected inventory and start/removal receipt binding. No SCM mutations.");
        previous=count;
        var comparison=Method("OfflineConsoleQualification","IndependentIdentityObserved");
        var summary=library.GetType("ProtectionLifecycle.OfflineConsoleHostIdentitySummary",true)!;
        bool Observed(string token,string logon="DENIED",string profile="DENIED",string machine="DENIED",string computer="DENIED")
        {
            var observation=Activator.CreateInstance(summary,[hash,token,logon,profile,computer,machine]);
            return comparison.Invoke(null,[observation]) is true;
        }
        Check(Observed("DIFFERS_FROM_HOST"));
        Check(Observed("DIFFERS_FROM_HOST",logon:"DIFFERS_FROM_HOST",profile:"DIFFERS_FROM_HOST",computer:"DIFFERS_FROM_HOST",machine:"DIFFERS_FROM_HOST"));
        Check(!Observed("MATCHES_HOST"));
        Check(!Observed("REFERENCE_UNAVAILABLE"));
        Check(!Observed("DIFFERS_FROM_HOST",logon:"MATCHES_HOST"));
        Check(!Observed("DIFFERS_FROM_HOST",profile:"MATCHES_HOST"));
        Check(!Observed("DIFFERS_FROM_HOST",computer:"MATCHES_HOST"));
        Check(!Observed("DIFFERS_FROM_HOST",machine:"MATCHES_HOST"));
        foreach(var missing in new[]{"REFERENCE_UNAVAILABLE","UNAVAILABLE","UNRECOGNIZED"})
        {
            Check(!Observed("DIFFERS_FROM_HOST",logon:missing));
            Check(!Observed("DIFFERS_FROM_HOST",profile:missing));
            Check(!Observed("DIFFERS_FROM_HOST",computer:missing));
            Check(!Observed("DIFFERS_FROM_HOST",machine:missing));
        }
        Check(comparison.Invoke(null,[null]) is false);
        var denied=false;
        try{_=broker.GetMethod("QualifyIndependentOfflineConsole")!.Invoke(null,null);}
        catch(TargetInvocationException error) when(error.InnerException is UnauthorizedAccessException){denied=true;}
        Check(denied);
        Console.WriteLine($"PASS {count-previous} independent offline checks; no success when a host identity matches or TokenUser differs unproven, ordinary caller denied before setup. No service or WFP mutations.");
    }

    [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)]
    private static extern SafeProcessHandle OpenProcess(uint access,[MarshalAs(UnmanagedType.Bool)]bool inherit,uint pid);
}
