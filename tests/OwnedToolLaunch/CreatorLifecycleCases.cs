using System.Buffers.Binary;
using System.ComponentModel;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;
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
        var relationType=ownerPolicy.GetParameters()[2].ParameterType;
        bool Trusted(SecurityIdentifier owner,string relation="OtherOwner")=>
            ownerPolicy.Invoke(null,[owner,serviceSid,Enum.Parse(relationType,relation)]) is true;
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
        string Classify(SecurityIdentifier owner,SecurityIdentifier? tokenOwner,(string,uint)[] groups)=>
            classify.Invoke(null,[owner,tokenOwner,groups])!.ToString()!;
        Check(Classify(logonSid,localService,ownLogon)=="TokenLogon");
        Check(Classify(logonSid,logonSid,ownLogon)=="TokenDefaultAndLogon");
        Check(Classify(logonSid,localService,[(logonSid.Value,0xc0000014u)])=="OtherLogonSid");
        Check(Classify(logonSid,localService,[])=="OtherLogonSid");
        Check(Classify(localService,localService,ownLogon)=="TokenDefault");
        Check(Classify(serviceSid,localService,ownLogon)=="OtherOwner");
        Check(Trusted(logonSid,Classify(logonSid,localService,ownLogon)));
        Check(Trusted(logonSid,Classify(logonSid,logonSid,ownLogon)));
        var foreignLogon=new SecurityIdentifier("S-1-5-5-0-1235");
        Check(!Trusted(foreignLogon,Classify(foreignLogon,localService,ownLogon)));
        Check(!Trusted(logonSid,Classify(logonSid,logonSid,[])));
        Check(!Trusted(logonSid,Classify(logonSid,localService,[(logonSid.Value,0xc0000000u)])));
        Check(!Trusted(logonSid,Classify(logonSid,localService,[(logonSid.Value,0xc0000014u)])));
        Check(!Trusted(logonSid,Classify(logonSid,localService,[..ownLogon,..ownLogon])));
        Check(!Trusted(logonSid,"TokenEvidenceUnavailable"));
        Check(!Trusted(new SecurityIdentifier("S-1-5-21-1-2-3-1001"),"TokenLogon"));
        using(var identity=WindowsIdentity.GetCurrent(TokenAccessLevels.Query))
        {
            var readGroups=Method("RestrictingSidToken","ReadGroups");
            var actualLogon=(IReadOnlyList<(string Sid,uint Attributes)>)readGroups.Invoke(null,[identity.AccessToken,28])!;
            var actualSid=new SecurityIdentifier(actualLogon.Single().Sid);
            Check(Trusted(actualSid,Classify(actualSid,identity.Owner,actualLogon.ToArray())));
            RestrictingSidCases.AssertCreatorObserverAcl(acl,actualSid);Check(true);
        }
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
        var cleaned=Method("SessionZeroCreatorTerminal","CleanedFrame");
        var readCleaned=Method("SessionZeroCreatorTerminal","ReadCleaned");
        var captureFailure=Method("SessionZeroCreatorTerminal","CaptureFailure");
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
        var cleanProof=(byte[])cleaned.Invoke(null,[nonce])!;
        void AssertCleaned(byte[] payload,byte[] binding)
        {
            using var stream=new MemoryStream(payload,false);
            _=readCleaned.Invoke(null,[stream,binding,CancellationToken.None]);
        }
        AssertCleaned(cleanProof,nonce);Check(true);
        Refused(()=>AssertCleaned(cleanProof,wrong));
        Refused(()=>AssertCleaned(cleanProof[..^1],nonce));
        Refused(()=>AssertCleaned(receipt,nonce));
        Refused(()=>AssertCleaned(frame,nonce));
        var legacyReceipt=(byte[])receipt.Clone();
        "CCD1"u8.CopyTo(legacyReceipt);
        Refused(()=>AssertCleaned(legacyReceipt,nonce));
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
        Refused(()=>Read(cleanProof,nonce));
        var captureProof=(byte[])captureFailure.Invoke(null,[nonce,5u])!;
        Refused(()=>AssertCleaned(captureProof,nonce));
        Refused(()=>Read(captureProof,wrong));
        var captureReported=false;
        try{_=Read(captureProof,nonce);}
        catch(TargetInvocationException failure)when(failure.InnerException is { } cause)
        {captureReported=cause.GetType().Name=="WfpFailure" && cause.GetType().GetProperty("Status",BindingFlags.NonPublic|BindingFlags.Instance)!.GetValue(cause) is 5u;}
        Check(captureReported);
        captureProof[24]=1;
        Refused(()=>Read(captureProof,nonce));
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
        previous=count;
        var witness=Method("SessionZeroStartupWitness","Observe");
        var capture=library.GetType("ProtectionLifecycle.OfflineConsoleOutput",true)!;
        object Stream(string value,bool overflow=false)=>Activator.CreateInstance(capture,[System.Text.Encoding.ASCII.GetBytes(value),overflow])!;
        void Witness(uint? exit,string output,string status,string? checkpoint=null,uint? error=null,bool overflow=false,string stderr="",
            int schema=7,(bool? Blocked,uint? MapError)? diagnostics=null)
        {
            var row=witness.Invoke(null,[schema,exit,Stream(output,overflow),Stream(stderr)])!;
            Check(row.GetType().GetProperty("Status")!.GetValue(row) as string==status &&
                row.GetType().GetProperty("LastCheckpoint")!.GetValue(row) as string==checkpoint &&
                (uint?)row.GetType().GetProperty("Win32Error")!.GetValue(row)==error);
            var observed=row.GetType().GetProperty("Diagnostics")!.GetValue(row);
            Check(diagnostics is null?observed is null:observed is not null &&
                (bool?)observed.GetType().GetProperty("Win32kBlocked")!.GetValue(observed)==diagnostics.Value.Blocked &&
                (uint?)observed.GetType().GetProperty("User32MapError")!.GetValue(observed)==diagnostics.Value.MapError);
        }
        const string all="ENTRY\nBEFORE_USER32\nAFTER_USER32\nBEFORE_DESKTOP\nAFTER_DESKTOP\nBEFORE_SHELL32\nAFTER_SHELL32\nBEFORE_UCRT\nAFTER_UCRT\n";
        const uint dllInitFailed=0xc0000142;
        Witness(0,all,"ALL_CHECKPOINTS_OBSERVED","AFTER_UCRT");
        Witness(dllInitFailed,"","NO_ENTRY_CHECKPOINT");
        Witness(dllInitFailed,"ENTRY\nBEFORE_USER32\n","NATIVE_EXIT_AFTER_CHECKPOINT","BEFORE_USER32");
        Witness(65,"ENTRY\nBEFORE_USER32\nWIN32=0x0000045A\n","WIN32_FAILURE_AFTER_CHECKPOINT","BEFORE_USER32",0x45a);
        Witness(68,"ENTRY\nBEFORE_USER32\nWIN32=0x0000045A\n","OUTPUT_REJECTED");
        Witness(0,"ENTRY\n","OUTPUT_REJECTED");
        Witness(dllInitFailed,"ENTRY\nAFTER_USER32\n","OUTPUT_REJECTED");
        Witness(dllInitFailed,"ENTRY\nBEFORE_USER","OUTPUT_REJECTED");
        Witness(0,all,"CAPTURE_UNAVAILABLE",overflow:true);
        Witness(0,all,"CAPTURE_UNAVAILABLE",stderr:"unexpected");
        const string user32Failure="ENTRY\nBEFORE_USER32\nWIN32=0x0000045A\n";
        const string imageDiagnostics="WIN32K_QUERY=0x00000000\nWIN32K_BLOCKED=0x00000000\nUSER32_FILE=0x00000000\nUSER32_MAP=0x00000000\n"+
            "WIN32U_LOAD=0x00000000\nGDI32_LOAD=0x00000000\nGDI32FULL_LOAD=0x00000000\n";
        Witness(0,all+imageDiagnostics,"ALL_CHECKPOINTS_OBSERVED","AFTER_UCRT",schema:8,diagnostics:(false,0));
        Witness(0,all+imageDiagnostics,"OUTPUT_REJECTED");
        Witness(65,user32Failure+imageDiagnostics,"WIN32_FAILURE_AFTER_CHECKPOINT","BEFORE_USER32",0x45a,schema:8,diagnostics:(false,0));
        Witness(65,user32Failure+imageDiagnostics.Replace("WIN32K_BLOCKED=0x00000000","WIN32K_BLOCKED=0x00000001",StringComparison.Ordinal),
            "WIN32_FAILURE_AFTER_CHECKPOINT","BEFORE_USER32",0x45a,schema:8,diagnostics:(true,0));
        Witness(65,user32Failure,"DIAGNOSTICS_REJECTED","BEFORE_USER32",0x45a,schema:8);
        Witness(65,user32Failure+imageDiagnostics.Replace("WIN32K_BLOCKED=0x00000000","WIN32K_BLOCKED=0x00000002",StringComparison.Ordinal),
            "DIAGNOSTICS_REJECTED","BEFORE_USER32",0x45a,schema:8);
        Witness(65,user32Failure+imageDiagnostics.Replace("USER32_FILE=0x00000000","USER32_FILE=0x00000005",StringComparison.Ordinal),
            "DIAGNOSTICS_REJECTED","BEFORE_USER32",0x45a,schema:8);
        Witness(65,user32Failure+imageDiagnostics
            .Replace("USER32_FILE=0x00000000\nUSER32_MAP=0x00000000","USER32_FILE=0x00000005\nUSER32_MAP=0xFFFFFFFF",StringComparison.Ordinal)
            .Replace("WIN32K_QUERY=0x00000000\nWIN32K_BLOCKED=0x00000000","WIN32K_QUERY=0x00000005\nWIN32K_BLOCKED=0xFFFFFFFF",StringComparison.Ordinal),
            "WIN32_FAILURE_AFTER_CHECKPOINT","BEFORE_USER32",0x45a,schema:8,diagnostics:(null,null));
        Witness(65,user32Failure+imageDiagnostics+"EXTRA=0x00000000\n","DIAGNOSTICS_REJECTED","BEFORE_USER32",0x45a,schema:8);
        Witness(0,all+imageDiagnostics+new string('X',384),"OUTPUT_REJECTED",schema:8);
        denied=false;
        try{_=broker.GetMethod("QualifySessionZeroStartupWitness")!.Invoke(null,null);}
        catch(TargetInvocationException error) when(error.InnerException is UnauthorizedAccessException){denied=true;}
        Check(denied);
        Console.WriteLine($"PASS {count-previous} startup witness checks; exact output, failure boundaries and ordinary refusal before setup.");
        previous=count;
        var stop=Method("SessionZeroCreatorRegistration","MatchesRecoveryStop");
        const uint originalStop=0xC5620026;
        bool IsStopped(uint state,uint pid,uint error,uint code,uint approved)=>
            stop.Invoke(null,[state,pid,error,code,approved]) is true;
        Check(IsStopped(1,0,1077,0,0));
        Check(IsStopped(1,0,1066,originalStop,originalStop));
        Check(!IsStopped(1,0,1066,originalStop,0));
        Check(!IsStopped(1,0,1066,originalStop+1,originalStop));
        Check(!IsStopped(4,17,1066,originalStop,originalStop));
        Check(!IsStopped(1,17,1066,originalStop,originalStop));
        Check(!IsStopped(1,0,0,0,originalStop));
        var recovery=library.GetType("ProtectionLifecycle.SessionZeroClosedCreatorRecovery",true)!;
        var readApproval=recovery.GetNestedType("Approval",BindingFlags.NonPublic)!.GetMethod("Read",methods)!;
        var now=DateTimeOffset.UtcNow;
        var approved=new {SchemaVersion=1,InstallationId=installation,JobId=jobId,WorkerId=release,FailedRunSHA256=hash,
            WindowStartUtc=now.AddMinutes(-4),WindowEndUtc=now.AddMinutes(-3),ExpiresUtc=now.AddMinutes(1)};
        object? ParseApproval(object data)
        {
            using var stream=new MemoryStream(JsonSerializer.SerializeToUtf8Bytes(data),false);
            return readApproval.Invoke(null,[stream]);
        }
        Check(ParseApproval(approved) is not null);
        Refused(()=>ParseApproval(approved with {WorkerId=jobId}));
        Refused(()=>ParseApproval(approved with {FailedRunSHA256="wrong"}));
        Refused(()=>ParseApproval(approved with {WindowStartUtc=now.AddMinutes(-6)}));
        Refused(()=>ParseApproval(approved with {WindowEndUtc=now.AddMinutes(1)}));
        Refused(()=>ParseApproval(approved with {WindowEndUtc=approved.WindowStartUtc}));
        Refused(()=>ParseApproval(approved with {ExpiresUtc=now.AddSeconds(-1)}));
        var oldRelease=(string)recovery.GetField("Release",methods)!.GetRawConstantValue()!;
        var oldManifest=(string)recovery.GetField("Manifest",methods)!.GetRawConstantValue()!;
        var originalJob=Method("OwnedJobIntent","ForNewJob").Invoke(null,[installation,oldRelease,oldManifest,serviceSid.Value])!;
        var oldJobId=(string)originalJob.GetType().GetProperty("JobId")!.GetValue(originalJob)!;
        var failureRecord=JsonSerializer.SerializeToNode(new {
            SchemaVersion=1,Scope="INSTALLED_FIXED_INDEPENDENT_OFFLINE_CONSOLE",InstallationId=installation,JobId=oldJobId,
            Release=oldRelease,ManifestHash=oldManifest,Status="INDEPENDENT_OFFLINE_CONSOLE_NOT_CONFIRMED",LastStage="CloseCreatorProfile",
            ProcessResumed=false,ChildExit=(object?)null,OriginalJobClosed=true,ProfileClosed=false,WorkspaceClosed=false,ServiceRemoved=false,
            StartupFailureRegistrationRemoved=false,FilesMatched=false,StreamsMatched=false,HostIdentityObservation=(object?)null,
            HostAccountSidDiffers=false,HostIdentityQualified=false,Output=(object?)null,Error=(object?)null,ChildFailure=(object?)null,
            EnvironmentProjection=(object?)null,StopObservation=(object?)null,GatewayOpened=false,NetworkQualified=false,LaunchAuthorized=false,
            FormalAdmissionIssued=false,ClaudeLaunched=false,Failures=new[]{
                new {Type="Win32Exception",Code=5u,Stage="AtomicOpenCreatedToken"},
                new {Type="InvalidDataException",Code=0x80131501u,Stage="CreatorProfileCleanupChannelUnavailable"}
            }
        })!.AsObject();
        var validateFailed=Method("SessionZeroClosedCreatorRecovery","ValidateFailedRun");
        void AssertFailureRecord(JsonObject value)=>_=validateFailed.Invoke(null,[JsonSerializer.SerializeToUtf8Bytes(value),originalJob]);
        AssertFailureRecord(failureRecord);Check(true);
        foreach(var field in new[]{"OriginalJobClosed","ProcessResumed","ProfileClosed","LaunchAuthorized"})
        {
            var altered=failureRecord.DeepClone().AsObject();
            altered[field]=!altered[field]!.GetValue<bool>();
            Refused(()=>AssertFailureRecord(altered));
        }
        var changedFailure=failureRecord.DeepClone().AsObject();
        changedFailure["Failures"]![0]!["Code"]=6;
        Refused(()=>AssertFailureRecord(changedFailure));
        var bootstrap=library.GetType("ProtectionLifecycle.BootstrapInstaller",true)!;
        foreach(var name in new[]{"RecoverReviewedClosedCreator","FinalizeReviewedClosedCreator"})
        {
            var rejected=bootstrap.GetMethod(name)!.Invoke(null,null)!;
            Check(rejected.GetType().GetField("Item1")!.GetValue(rejected) is 125 &&
                ((string)rejected.GetType().GetField("Item2")!.GetValue(rejected)!).Contains("\"Stage\":\"MAINTENANCE_IDENTITY\"",StringComparison.Ordinal));
        }
        Console.WriteLine($"PASS {count-previous} closed creator recovery checks; original stop, expiry, object scope and ordinary maintenance refusal. No profile or SCM mutations.");
    }

    [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)]
    private static extern SafeProcessHandle OpenProcess(uint access,[MarshalAs(UnmanagedType.Bool)]bool inherit,uint pid);
}
