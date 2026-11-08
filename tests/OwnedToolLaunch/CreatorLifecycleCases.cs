using System.Buffers.Binary;
using System.Reflection;
using System.Security.AccessControl;

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
    }
}
