using System.Buffers.Binary;
using System.Reflection;
using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Win32.SafeHandles;

internal static class CreatorJobCases
{
    internal static void Run(Assembly library)
    {
        const BindingFlags methods=BindingFlags.NonPublic|BindingFlags.Static;
        var intentType=library.GetType("ProtectionLifecycle.OwnedJobIntent",true)!;
        var create=intentType.GetMethod("ForNewJob",methods)!;
        var parse=intentType.GetMethod("Parse",methods)!;
        var seal=library.GetType("ProtectionLifecycle.KernelJobSeal",true)!;
        var validate=seal.GetMethod("AssertJobDescriptor",methods)!;
        var readDescriptor=seal.GetMethod("ReadJobDescriptor",methods)!;
        var changeGrant=seal.GetMethod("ChangeCreatorAce",methods)!;
        var writeDacl=seal.GetMethod("WriteProtectedDacl",methods)!;
        var owner=library.GetType("ProtectionLifecycle.OwnedKernelJob",true)!;
        var proof=owner.GetMethod("ValidateCreatorProof",methods)!;
        var createNative=owner.GetMethod("CreateFreshSessionZeroJob",methods)!;
        var requireSoleHandle=owner.GetMethod("AssertSoleJobHandle",methods)!;
        var parseClosed=library.GetType("ProtectionLifecycle.AtomicJobCompletion",true)!.GetMethod("ParseClosed",methods)!;
        var install=new string('1',32);
        var release=new string('2',32);
        var hash=new string('A',64);
        const string creatorSid="S-1-5-80-8-9-10-11-12";
        var count=0;
        void Check(bool condition)
        {
            if(!condition)throw new InvalidOperationException($"Creator Job boundary case {count+1} failed");
            count++;
        }
        void Refused(Action action)
        {
            try{action();}
            catch(TargetInvocationException error) when(error.InnerException is InvalidDataException){Check(true);return;}
            Check(false);
        }
        object New(string? sid)=>create.Invoke(null,[install,release,hash,sid])!;
        string Name(object intent)=>(string)intentType.GetProperty("Name",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(intent)!;
        object Parse(JsonObject node,string expectedInstall,string job)
        {
            using var doc=JsonDocument.Parse(node.ToJsonString());
            return parse.Invoke(null,[doc.RootElement,expectedInstall,job])!;
        }

        var legacy=New(null);
        var creator=New(creatorSid);
        var legacyJson=JsonSerializer.SerializeToNode(legacy)!.AsObject();
        var creatorJson=JsonSerializer.SerializeToNode(creator)!.AsObject();
        var jobId=creatorJson["JobId"]!.GetValue<string>();
        var legacyId=legacyJson["JobId"]!.GetValue<string>();
        Check(!legacyJson.ContainsKey("CreatorServiceSid") && Parse(legacyJson,install,legacyId).Equals(legacy));
        Check(Name(legacy)==$"CPCJob.{install}.{legacyId}\\Session");
        Check(Parse(creatorJson,install,jobId).Equals(creator));
        Check(Name(creator)==$@"Global\CPCSessionJob.{install}.{jobId}");
        Refused(()=>Parse(creatorJson,release,jobId));
        Refused(()=>Parse(creatorJson,install,legacyId));
        foreach(var (key,value) in new (string,JsonNode?)[]{("SchemaVersion",JsonValue.Create(2)),("Scope",JsonValue.Create("JOB_MEMBERS_ONLY")),
            ("CreatorServiceSid",null),("CreatorServiceSid",JsonValue.Create("S-1-5-19")),("Name",JsonValue.Create("override"))})
        {
            var changed=creatorJson.DeepClone().AsObject();
            changed[key]=value;
            Refused(()=>Parse(changed,install,jobId));
        }
        var tag=intentType.GetProperty("Tag",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(creator)!;
        var tagSid=(string)tag.GetType().GetProperty("Sid",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(tag)!;
        foreach(var invalid in new[]{"S-1-5-80-0","S-1-5-19","S-1-5-80-08-9-10-11-12",tagSid})Refused(()=>New(invalid));

        void AssertProof(object receipt)
        {
            using var doc=JsonDocument.Parse(JsonSerializer.Serialize(receipt));
            _=proof.Invoke(null,[doc.RootElement,hash]);
        }
        AssertProof(new{SchemaVersion=1,IntentSHA256=hash});Check(true);
        Refused(()=>AssertProof(new{SchemaVersion=1,IntentSHA256=new string('B',64)}));
        Refused(()=>AssertProof(new{SchemaVersion=2,IntentSHA256=hash}));
        Refused(()=>AssertProof(new{SchemaVersion=1,IntentSHA256=hash,Name=Name(creator)}));

        JsonObject Closed(string id)=>JsonSerializer.SerializeToNode(new{
            SchemaVersion=1,InstallationId=install,JobId=id,Release=release,ManifestSHA256=hash,AdmissionSHA256=hash,
            Status="ADMISSION_CLOSED_MEMBERS_ZERO_OBSERVED",
            Snapshot=new{JobId=id,LimitFlags=0x2000,ActiveBefore=0,ActiveAfter=0,ProcessIds=Array.Empty<uint>(),AtUtc="2026-11-08T00:00:00Z"}
        })!.AsObject();
        object? ReadClosed(JsonObject receipt,object intent)=>parseClosed.Invoke(null,[JsonSerializer.SerializeToUtf8Bytes(receipt),intent]);
        var oldClosed=Closed(legacyId);
        Check(ReadClosed(oldClosed,legacy) is not null);
        oldClosed["CreatorAccessRevoked"]=true;
        Refused(()=>ReadClosed(oldClosed,legacy));
        var newClosed=Closed(jobId);
        Refused(()=>ReadClosed(newClosed,creator));
        newClosed["CreatorAccessRevoked"]=false;
        Refused(()=>ReadClosed(newClosed,creator));
        newClosed["CreatorAccessRevoked"]=null;
        Refused(()=>ReadClosed(newClosed,creator));
        newClosed["CreatorAccessRevoked"]=true;
        Check(ReadClosed(newClosed,creator) is not null);

        var baseAcl=$"D:P(A;;0x0006000f;;;SY)(A;;0x0006000f;;;BA)(A;;RC;;;{tagSid})";
        var creatorGrant=$"(A;;0x00020001;;;{creatorSid})";
        const string label="S:(ML;;NW;;;ME)";
        var creatorAcl=baseAcl+creatorGrant+label;
        bool AssertCreator(string sddl)=>(bool)validate.Invoke(null,[new RawSecurityDescriptor(sddl),creator])!;
        Check(AssertCreator("O:BAG:SY"+creatorAcl));
        Check(!AssertCreator("O:BAG:SY"+baseAcl+label));
        foreach(var invalid in new[]{baseAcl+creatorGrant,creatorAcl.Replace(";;;ME",";;;LW",StringComparison.Ordinal),
            creatorAcl.Replace("0x00020001","0x00020005",StringComparison.Ordinal),creatorAcl.Replace(creatorSid,"S-1-5-19",StringComparison.Ordinal),
            creatorAcl.Replace(tagSid,creatorSid,StringComparison.Ordinal),creatorAcl.Replace("D:P","D:",StringComparison.Ordinal)})
            Refused(()=>AssertCreator("O:BAG:SY"+invalid));

        // A medium-integrity fixture can create its own empty kernel Job. It
        // uses the ordinary caller as owner to avoid granting admin rights.
        using var identity=WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        var user=identity.User??throw new InvalidOperationException("Missing ordinary token user");
        var fixtureDescriptor=new RawSecurityDescriptor("O:"+user.Value+baseAcl+label);
        var bytes=new byte[fixtureDescriptor.BinaryLength];
        fixtureDescriptor.GetBinaryForm(bytes,0);
        var pointer=GCHandle.Alloc(bytes,GCHandleType.Pinned);
        try
        {
            var attributes=new SecurityAttributes{Length=Marshal.SizeOf<SecurityAttributes>(),Descriptor=pointer.AddrOfPinnedObject()};
            using(var collision=CreateJobObject(ref attributes,Name(creator)))
            {
                Check(!collision.IsInvalid && Marshal.GetLastWin32Error()!=183);
                var refused=false;
                try{using var unexpected=(SafeHandle)createNative.Invoke(null,[creator,attributes.Descriptor])!;}
                catch(TargetInvocationException error) when(error.InnerException is Win32Exception {NativeErrorCode:183}){refused=true;}
                Check(refused);
            }
            using var handle=(SafeHandle)createNative.Invoke(null,[creator,attributes.Descriptor])!;
            Check(!handle.IsInvalid);
            RawSecurityDescriptor Read(SafeHandle target)=>(RawSecurityDescriptor)readDescriptor.Invoke(null,[target,true])!;
            void CheckAssignDenied()
            {
                using var blocked=OpenJobObject(1,false,Name(creator));
                Check(blocked.IsInvalid && Marshal.GetLastWin32Error()==5);
            }
            using(var read=OpenJobObject(0x20000,false,Name(creator)))
            {
                Check(!read.IsInvalid);
                var actual=Read(read);
                Check(actual.Owner is { } actualOwner && user.Equals(actualOwner));
                Refused(()=>validate.Invoke(null,[actual,creator])); // Ordinary-owned replacement refused.
                actual.Owner=new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null);
                Check(validate.Invoke(null,[actual,creator]) is false); // Kernel ACL and label both match.
                Refused(()=>requireSoleHandle.Invoke(null,[handle]));
            }
            _=requireSoleHandle.Invoke(null,[handle]);Check(true);
            CheckAssignDenied();
            var acl=Read(handle).DiscretionaryAcl!;
            _=changeGrant.Invoke(null,[acl,user,true]);
            _=writeDacl.Invoke(null,[handle,acl]);
            using(var assign=OpenJobObject(1,false,Name(creator)))
            {
                Check(!assign.IsInvalid);
                _=changeGrant.Invoke(null,[acl,user,false]);
                _=writeDacl.Invoke(null,[handle,acl]);
                CheckAssignDenied();
                var basic=new uint[14];
                Check(NtQueryObject(assign,0,basic,56,out var returned)==0 && returned==56 && basic[1]==1);
                Refused(()=>requireSoleHandle.Invoke(null,[handle])); // Revocation did not close the existing handle.
                var revoked=Read(handle);
                revoked.Owner=new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null);
                Check(validate.Invoke(null,[revoked,creator]) is false); // Owner-only DACL and label read back.
            }
            _=requireSoleHandle.Invoke(null,[handle]);Check(true);
        }
        finally{pointer.Free();}
        using var closed=OpenJobObject(0x20000,false,Name(creator));
        Check(closed.IsInvalid && Marshal.GetLastWin32Error()==2);
        Console.WriteLine($"PASS {count} creator Job checks; legacy intent, proof binding, fresh creation, collision refusal, exact ACL and label, actual grant/revoke and held-handle refusal. No service, child creation, UAC, installation or WFP.");
        var prior=count;
        var channel=library.GetType("ProtectionLifecycle.SessionZeroCreatorChannel",true)!;
        var request=channel.GetMethod("CreateRequest",methods)!;
        var reply=channel.GetMethod("ParseReply",methods)!;
        var nonce=Enumerable.Range(1,16).Select(n=>(byte)n).ToArray();
        var outgoing=(byte[])request.Invoke(null,[nonce,install,jobId,12u,7u])!;
        Check(outgoing.Length==60 && outgoing.AsSpan(0,4).SequenceEqual("CCP1"u8));
        Check(BinaryPrimitives.ReadUInt32LittleEndian(outgoing.AsSpan(4))==12 && BinaryPrimitives.ReadUInt32LittleEndian(outgoing.AsSpan(8))==7);
        Check(outgoing.AsSpan(12,16).SequenceEqual(nonce) && outgoing.AsSpan(28,16).SequenceEqual(Convert.FromHexString(install)) &&
            outgoing.AsSpan(44,16).SequenceEqual(Convert.FromHexString(jobId)));
        Refused(()=>request.Invoke(null,[nonce,install,jobId,12u,0u]));
        Refused(()=>request.Invoke(null,[nonce[..15],install,jobId,12u,7u]));
        var incoming=new byte[44];
        "CCR1"u8.CopyTo(incoming);
        nonce.CopyTo(incoming,4);
        BinaryPrimitives.WriteUInt32LittleEndian(incoming.AsSpan(20),21);
        BinaryPrimitives.WriteUInt32LittleEndian(incoming.AsSpan(24),31);
        BinaryPrimitives.WriteInt64LittleEndian(incoming.AsSpan(28),41);
        BinaryPrimitives.WriteInt64LittleEndian(incoming.AsSpan(36),51);
        var report=reply.Invoke(null,[incoming,nonce,20u,40L])!;
        Check(report.GetType().GetProperty("Pid")!.GetValue(report) is uint pid && pid==21);
        foreach(var offset in new[]{0,4,20,24,28,36})
        {
            var changed=(byte[])incoming.Clone();
            changed[offset]=0;
            Refused(()=>reply.Invoke(null,[changed,nonce,20u,40L]));
        }
        Refused(()=>reply.Invoke(null,[incoming[..43],nonce,20u,40L]));
        Refused(()=>reply.Invoke(null,[incoming.Concat(new byte[1]).ToArray(),nonce,20u,40L]));
        Refused(()=>reply.Invoke(null,[incoming,nonce,21u,40L]));
        using var self=Process.GetCurrentProcess();
        var serviceClient=library.GetType("ProtectionLifecycle.SessionZeroCreatorClient",true)!;
        var pipeId=Guid.NewGuid().ToString("N");
        var pipeName=(string)channel.GetMethod("NameForJob",methods)!.Invoke(null,[pipeId])!;
        using var server=new NamedPipeServerStream(pipeName,PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous|PipeOptions.CurrentUserOnly);
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(3));
        var connected=server.WaitForConnectionAsync(timeout.Token);
        using var client=(SafePipeHandle)serviceClient.GetMethod("OpenOwnerPipeHandle",methods)!.Invoke(null,[pipeId])!;
        connected.GetAwaiter().GetResult();
        var peer=((uint Pid,uint Session))channel.GetMethod("ReadClientPeer",methods)!.Invoke(null,[server.SafePipeHandle])!;
        Check(peer.Pid==(uint)self.Id && peer.Session==(uint)self.SessionId);
        // The ordinary fixture is outside Session 0 and cannot pass as the
        // creation service even with the exact process handle and PID.
        Check(peer.Session!=0);
        Refused(()=>channel.GetMethod("AssertServicePeer",methods)!.Invoke(null,[server.SafePipeHandle,self.SafeHandle,peer.Session]));
        Console.WriteLine($"PASS {count-prior} creator channel checks; request/reply binding and actual ordinary pipe PID/session refusal. No service, handoff, elevation or WFP.");
        prior=count;
        var serverPeer=((uint Pid,uint Session))serviceClient.GetMethod("ReadServerPeer",methods)!.Invoke(null,[client])!;
        Check(serverPeer==peer);
        var parseRequest=channel.GetMethod("ParseRequest",methods)!;
        var decoded=parseRequest.Invoke(null,[outgoing,jobId,12u,7u])!;
        Check((string?)decoded.GetType().GetProperty("InstallationId")!.GetValue(decoded)==install);
        Check((string?)decoded.GetType().GetProperty("JobId")!.GetValue(decoded)==jobId);
        Check(((byte[])decoded.GetType().GetProperty("Nonce")!.GetValue(decoded)!).SequenceEqual(nonce));
        Check(((byte[])channel.GetMethod("CreateReply",methods)!.Invoke(null,[decoded,report])!).SequenceEqual(incoming));
        Refused(()=>parseRequest.Invoke(null,[outgoing[..59],jobId,12u,7u]));
        Refused(()=>parseRequest.Invoke(null,[outgoing,legacyId,12u,7u]));
        Refused(()=>parseRequest.Invoke(null,[outgoing,jobId,13u,7u]));
        Refused(()=>parseRequest.Invoke(null,[outgoing,jobId,12u,8u]));
        var createFailure=channel.GetMethod("CreateFailure",methods)!;
        var failureStage=channel.GetNestedType("CreationFailure",BindingFlags.NonPublic)!;
        foreach(var (stageName,native) in new[]{("Profile",0x80070005u),("AtomicCreate",5u),("Streams",32u)})
        {
            var fault=(byte[])createFailure.Invoke(null,[decoded,Enum.Parse(failureStage,stageName),native])!;
            Check(fault.Length==44 && fault.AsSpan(0,4).SequenceEqual("CCF1"u8));
            var exact=false;
            try{_=reply.Invoke(null,[fault,nonce,20u,40L]);}
            catch(TargetInvocationException error) when(error.InnerException is IOException remote &&
                remote.GetType().GetProperty("Stage",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(remote) is string observed &&
                observed=="CreatorService"+stageName && unchecked((uint)remote.HResult)==native){exact=true;}
            Check(exact);
            fault[28]=1;
            Refused(()=>reply.Invoke(null,[fault,nonce,20u,40L]));
        }
        Refused(()=>createFailure.Invoke(null,[decoded,Enum.ToObject(failureStage,0u),5u]));
        Refused(()=>createFailure.Invoke(null,[decoded,Enum.ToObject(failureStage,1u),0u]));
        var assertGroups=serviceClient.GetMethod("AssertCreatorGroups",methods)!;
        void ServiceGroups((string,uint)[] groups,(string,uint)[] restricting)=>_=assertGroups.Invoke(null,[groups,restricting,creatorSid]);
        ServiceGroups([(creatorSid,4),("S-1-5-32-544",0x10)],[]);Check(true);
        Refused(()=>ServiceGroups([(creatorSid,0)],[]));
        Refused(()=>ServiceGroups([(creatorSid,0x14)],[]));
        Refused(()=>ServiceGroups([(creatorSid,4),("S-1-5-32-544",4)],[]));
        Refused(()=>ServiceGroups([(creatorSid,4),("S-1-5-21-1-2-3-1001",0x10)],[]));
        Refused(()=>ServiceGroups([(creatorSid,4)],[(creatorSid,4)]));
        var assertPipe=serviceClient.GetMethod("AssertOwnerPipe",methods)!;
        var service=new SecurityIdentifier(creatorSid);
        var expectedPipe=$"O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x00120083;;;{creatorSid})";
        _=assertPipe.Invoke(null,[new RawSecurityDescriptor(expectedPipe),service]);Check(true);
        foreach(var foreign in new[]{expectedPipe.Replace("0x00120083","0x00120087",StringComparison.Ordinal),
            expectedPipe.Replace("D:P","D:",StringComparison.Ordinal),expectedPipe.Replace("O:BA","O:SY",StringComparison.Ordinal)})
            Refused(()=>assertPipe.Invoke(null,[new RawSecurityDescriptor(foreign),service]));
        var actualPipe=(RawSecurityDescriptor)seal.GetMethod("ReadCreatorPipeDescriptor",methods)!.Invoke(null,[client])!;
        Check(actualPipe.Owner is { } pipeOwner && user.Equals(pipeOwner));
        Refused(()=>assertPipe.Invoke(null,[actualPipe,service]));
        Refused(()=>serviceClient.GetMethod("VerifyCurrentService",methods)!.Invoke(null,[pipeName,null]));
        using var wrapped=new NamedPipeClientStream(PipeDirection.InOut,true,true,client);
        using var transferDeadline=new CancellationTokenSource(TimeSpan.FromSeconds(3));
        var transfer=transferDeadline.Token;
        var received=new byte[outgoing.Length];
        Task.WhenAll(wrapped.ReadExactlyAsync(received.AsMemory(),transfer).AsTask(),server.WriteAsync(outgoing.AsMemory(),transfer).AsTask()).GetAwaiter().GetResult();
        Check(received.SequenceEqual(outgoing));
        var receivedReply=new byte[incoming.Length];
        Task.WhenAll(server.ReadExactlyAsync(receivedReply.AsMemory(),transfer).AsTask(),wrapped.WriteAsync(incoming.AsMemory(),transfer).AsTask()).GetAwaiter().GetResult();
        Check(receivedReply.SequenceEqual(incoming));
        Console.WriteLine($"PASS {count-prior} creator client checks; reciprocal actual pipe peer and descriptor, fixed request/reply, account and service group refusals. No service, handoff, elevation or WFP.");
        CreatorLifecycleCases.Run(library);
    }

    [StructLayout(LayoutKind.Sequential)] private struct SecurityAttributes {internal int Length;internal IntPtr Descriptor;internal int Inherit;}
    [DllImport("kernel32.dll",EntryPoint="CreateJobObjectW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern SafeFileHandle CreateJobObject(ref SecurityAttributes attributes,string name);
    [DllImport("kernel32.dll",EntryPoint="OpenJobObjectW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern SafeFileHandle OpenJobObject(uint access,[MarshalAs(UnmanagedType.Bool)]bool inherit,string name);
    [DllImport("ntdll.dll",ExactSpelling=true)] private static extern int NtQueryObject(SafeFileHandle handle,int info,[Out] uint[] buffer,uint size,out uint returned);
}
