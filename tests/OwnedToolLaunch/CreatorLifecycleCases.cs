using System.Buffers.Binary;
using System.Reflection;
using System.Security.AccessControl;
using System.Text.Json;

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
        void AssertRemoval(string disposition,bool started,string expectedHash)
        {
            using var doc=JsonDocument.Parse(JsonSerializer.SerializeToUtf8Bytes(new{SchemaVersion=1,IntentSHA256=hash,Disposition=disposition}));
            _=removed.Invoke(null,[doc.RootElement,expectedHash,started]);
        }
        const string closed="PROFILE_AND_SERVICE_CLOSED",unstarted="SERVICE_REMOVED_BEFORE_START";
        AssertRemoval(closed,true,hash);Check(true);
        AssertRemoval(unstarted,false,hash);Check(true);
        Refused(()=>AssertRemoval(closed,false,hash));
        Refused(()=>AssertRemoval(unstarted,true,hash));
        Refused(()=>AssertRemoval(closed,true,new string('B',64)));
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
        Check(!Observed("MATCHES_HOST"));
        Check(!Observed("REFERENCE_UNAVAILABLE"));
        Check(!Observed("DIFFERS_FROM_HOST",logon:"MATCHES_HOST"));
        Check(!Observed("DIFFERS_FROM_HOST",profile:"MATCHES_HOST"));
        Check(!Observed("DIFFERS_FROM_HOST",computer:"MATCHES_HOST"));
        Check(!Observed("DIFFERS_FROM_HOST",machine:"MATCHES_HOST"));
        Check(comparison.Invoke(null,[null]) is false);
        var denied=false;
        try{_=broker.GetMethod("QualifyIndependentOfflineConsole")!.Invoke(null,null);}
        catch(TargetInvocationException error) when(error.InnerException is UnauthorizedAccessException){denied=true;}
        Check(denied);
        Console.WriteLine($"PASS {count-previous} independent offline checks; no success when a host identity matches or TokenUser differs unproven, ordinary caller denied before setup. No service or WFP mutations.");
    }
}
