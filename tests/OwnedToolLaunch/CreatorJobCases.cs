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
        var requireAbsent=owner.GetMethod("AssertCreatorNameAbsent",methods)!;
        var parseClosed=library.GetType("ProtectionLifecycle.AtomicJobCompletion",true)!.GetMethod("ParseClosed",methods)!;
        var parseRetirement=library.GetType("ProtectionLifecycle.UnadmittedJobRetirement",true)!.GetMethod("Parse",methods)!;
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

        PrivateWindowPolicy(library,creator,legacy,New(creatorSid),jobId,creatorSid);

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

        var retirement=JsonSerializer.SerializeToNode(new{
            SchemaVersion=1,IntentSHA256=hash,Status="NEVER_ADMITTED_ORIGINAL_JOB_ZERO_OBSERVED",TotalProcesses=0,
            Snapshot=Closed(legacyId)["Snapshot"]!.DeepClone()
        })!.AsObject();
        void ReadRetirement(JsonObject receipt,object intent,string expectedHash)=>
            parseRetirement.Invoke(null,[JsonSerializer.SerializeToUtf8Bytes(receipt),intent,expectedHash]);
        ReadRetirement(retirement,legacy,hash);Check(true);
        Refused(()=>ReadRetirement(retirement,creator,hash));
        Refused(()=>ReadRetirement(retirement,legacy,new string('B',64)));
        Refused(()=>ReadClosed(retirement,legacy));
        var priorMember=retirement.DeepClone().AsObject();
        priorMember["TotalProcesses"]=1;
        Refused(()=>ReadRetirement(priorMember,legacy,hash));
        foreach(var (field,value) in new (string,JsonNode?)[]{("JobId",JsonValue.Create(jobId)),("LimitFlags",JsonValue.Create(0)),
            ("ActiveAfter",JsonValue.Create(1)),("ProcessIds",new JsonArray(JsonValue.Create(42))),("ProcessIds",null)})
        {
            var changed=retirement.DeepClone().AsObject();
            changed["Snapshot"]![field]=value;
            Refused(()=>ReadRetirement(changed,legacy,hash));
        }

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
            _=requireAbsent.Invoke(null,[creator]);Check(true);
            Refused(()=>requireAbsent.Invoke(null,[legacy]));
            var attributes=new SecurityAttributes{Length=Marshal.SizeOf<SecurityAttributes>(),Descriptor=pointer.AddrOfPinnedObject()};
            using(var collision=CreateJobObject(ref attributes,Name(creator)))
            {
                Check(!collision.IsInvalid && Marshal.GetLastWin32Error()!=183);
                Refused(()=>requireAbsent.Invoke(null,[creator]));
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
        Check(outgoing.Length==60 && outgoing.AsSpan(0,4).SequenceEqual("CCP2"u8));
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
        var legacyRequest=(byte[])outgoing.Clone();legacyRequest[3]=(byte)'1';
        Refused(()=>parseRequest.Invoke(null,[legacyRequest,jobId,12u,7u]));
        var parseWorkload=channel.GetMethod("ParseWorkloadRequest",methods)!;
        var startup=(byte[])outgoing.Clone();
        "CCW1"u8.CopyTo(startup);
        var mode=decoded.GetType().GetProperty("StartupWitness",BindingFlags.Instance|BindingFlags.NonPublic)!;
        Check(mode.GetValue(parseWorkload.Invoke(null,[outgoing,jobId,12u,7u])) is false);
        Check(mode.GetValue(parseWorkload.Invoke(null,[startup,jobId,12u,7u])) is true);
        Refused(()=>parseRequest.Invoke(null,[startup,jobId,12u,7u]));
        Refused(()=>parseWorkload.Invoke(null,[startup,jobId,13u,7u]));
        Refused(()=>parseWorkload.Invoke(null,[legacyRequest,jobId,12u,7u]));
        var windowRequest=(byte[])outgoing.Clone();
        "CCW2"u8.CopyTo(windowRequest);
        var windowMode=decoded.GetType().GetProperty("ObserveWindowAccess",BindingFlags.Instance|BindingFlags.NonPublic)!;
        var windowDecoded=parseWorkload.Invoke(null,[windowRequest,jobId,12u,7u])!;
        Check(mode.GetValue(windowDecoded) is true && windowMode.GetValue(windowDecoded) is true);
        Check(windowMode.GetValue(parseWorkload.Invoke(null,[startup,jobId,12u,7u])) is false);
        Refused(()=>parseRequest.Invoke(null,[windowRequest,jobId,12u,7u]));
        Refused(()=>parseWorkload.Invoke(null,[windowRequest,jobId,12u,8u]));
        var privateRequest=(byte[])outgoing.Clone();
        "CCW3"u8.CopyTo(privateRequest);
        var privateMode=decoded.GetType().GetProperty("UsePrivateWindow",BindingFlags.Instance|BindingFlags.NonPublic)!;
        var privateDecoded=parseWorkload.Invoke(null,[privateRequest,jobId,12u,7u])!;
        Check(mode.GetValue(privateDecoded) is true && privateMode.GetValue(privateDecoded) is true && windowMode.GetValue(privateDecoded) is false);
        Check(privateMode.GetValue(windowDecoded) is false);
        Refused(()=>parseRequest.Invoke(null,[privateRequest,jobId,12u,7u]));
        Refused(()=>parseWorkload.Invoke(null,[privateRequest,legacyId,12u,7u]));
        var readControlRequest=(byte[])privateRequest.Clone();
        "CCW4"u8.CopyTo(readControlRequest);
        var readControlMode=decoded.GetType().GetProperty("PrivateStationReadControl",BindingFlags.Instance|BindingFlags.NonPublic)!;
        var readControlDecoded=parseWorkload.Invoke(null,[readControlRequest,jobId,12u,7u])!;
        Check(privateMode.GetValue(readControlDecoded) is true && readControlMode.GetValue(readControlDecoded) is true &&
            readControlMode.GetValue(privateDecoded) is false);
        Refused(()=>parseRequest.Invoke(null,[readControlRequest,jobId,12u,7u]));
        var managedRequest=(byte[])readControlRequest.Clone();
        "CCM1"u8.CopyTo(managedRequest);
        var managedDecoded=parseWorkload.Invoke(null,[managedRequest,jobId,12u,7u])!;
        Check(mode.GetValue(managedDecoded) is false && privateMode.GetValue(managedDecoded) is true && readControlMode.GetValue(managedDecoded) is true);
        Refused(()=>parseRequest.Invoke(null,[managedRequest,jobId,12u,7u]));
        Refused(()=>parseWorkload.Invoke(null,[managedRequest,legacyId,12u,7u]));
        var surveyRequest=(byte[])managedRequest.Clone();
        "CCS1"u8.CopyTo(surveyRequest);
        var surveyMode=decoded.GetType().GetProperty("IdentitySurvey",BindingFlags.Instance|BindingFlags.NonPublic)!;
        var surveyDecoded=parseWorkload.Invoke(null,[surveyRequest,jobId,12u,7u])!;
        Check(mode.GetValue(surveyDecoded) is false && privateMode.GetValue(surveyDecoded) is true &&
            readControlMode.GetValue(surveyDecoded) is true && surveyMode.GetValue(surveyDecoded) is true &&
            surveyMode.GetValue(managedDecoded) is false);
        Refused(()=>parseRequest.Invoke(null,[surveyRequest,jobId,12u,7u]));
        Refused(()=>parseWorkload.Invoke(null,[surveyRequest,legacyId,12u,7u]));
        var networkRequest=(byte[])surveyRequest.Clone();
        "CCN1"u8.CopyTo(networkRequest);
        var networkMode=decoded.GetType().GetProperty("NetworkSurvey",BindingFlags.Instance|BindingFlags.NonPublic)!;
        var networkDecoded=parseWorkload.Invoke(null,[networkRequest,jobId,12u,7u])!;
        Check(mode.GetValue(networkDecoded) is false && privateMode.GetValue(networkDecoded) is true &&
            readControlMode.GetValue(networkDecoded) is true && surveyMode.GetValue(networkDecoded) is true &&
            networkMode.GetValue(networkDecoded) is true && networkMode.GetValue(surveyDecoded) is false);
        Refused(()=>parseRequest.Invoke(null,[networkRequest,jobId,12u,7u]));
        Refused(()=>parseWorkload.Invoke(null,[networkRequest,legacyId,12u,7u]));
        var gitRequest=(byte[])networkRequest.Clone();
        "CCG1"u8.CopyTo(gitRequest);
        var gitMode=decoded.GetType().GetProperty("GitInit",BindingFlags.Instance|BindingFlags.NonPublic)!;
        var gitDecoded=parseWorkload.Invoke(null,[gitRequest,jobId,12u,7u])!;
        Check(mode.GetValue(gitDecoded) is false && privateMode.GetValue(gitDecoded) is true &&
            readControlMode.GetValue(gitDecoded) is true && gitMode.GetValue(gitDecoded) is true &&
            networkMode.GetValue(gitDecoded) is false && gitMode.GetValue(networkDecoded) is false);
        Refused(()=>parseRequest.Invoke(null,[gitRequest,jobId,12u,7u]));
        Refused(()=>parseWorkload.Invoke(null,[gitRequest,legacyId,12u,7u]));
        var windowType=library.GetType("ProtectionLifecycle.SessionZeroWindowAccess",true)!;
        var parseWindow=channel.GetMethod("ParseWindowAccess",methods)!;
        var writeWindow=channel.GetMethod("CreateWindowAccess",methods)!;
        var windowFrame=new byte[44];
        "CCD1"u8.CopyTo(windowFrame);
        nonce.CopyTo(windowFrame,4);
        BinaryPrimitives.WriteUInt32LittleEndian(windowFrame.AsSpan(24),0x20103);
        BinaryPrimitives.WriteUInt32LittleEndian(windowFrame.AsSpan(32),5);
        var windowResult=parseWindow.Invoke(null,[windowFrame,nonce])!;
        Check(((byte[])writeWindow.Invoke(null,[windowDecoded,windowResult])!).SequenceEqual(windowFrame));
        Check(((byte[])writeWindow.Invoke(null,[privateDecoded,windowResult])!).SequenceEqual(windowFrame));
        Refused(()=>writeWindow.Invoke(null,[decoded,windowResult]));
        Refused(()=>parseWindow.Invoke(null,[windowFrame[..43],nonce]));
        Refused(()=>parseWindow.Invoke(null,[windowFrame,nonce.Reverse().ToArray()]));
        var foreignRights=(byte[])windowFrame.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(foreignRights.AsSpan(28),0x200);
        Refused(()=>parseWindow.Invoke(null,[foreignRights,nonce]));
        var assertPrivateGrants=library.GetType("ProtectionLifecycle.SessionZeroWindowPolicy",true)!.GetMethod("AssertGrants",methods)!;
        var privateFrame=(byte[])windowFrame.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(privateFrame.AsSpan(24),0x20023);
        BinaryPrimitives.WriteUInt32LittleEndian(privateFrame.AsSpan(28),0x23);
        BinaryPrimitives.WriteUInt32LittleEndian(privateFrame.AsSpan(32),0);
        BinaryPrimitives.WriteUInt32LittleEndian(privateFrame.AsSpan(36),0x200c7);
        BinaryPrimitives.WriteUInt32LittleEndian(privateFrame.AsSpan(40),0xc7);
        var oldGrant=parseWindow.Invoke(null,[privateFrame,nonce]);
        assertPrivateGrants.Invoke(null,[oldGrant,false]);Check(true);
        Refused(()=>assertPrivateGrants.Invoke(null,[oldGrant,true]));
        Refused(()=>assertPrivateGrants.Invoke(null,[windowResult,false]));
        BinaryPrimitives.WriteUInt32LittleEndian(privateFrame.AsSpan(28),0x20023);
        var requiredGrant=parseWindow.Invoke(null,[privateFrame,nonce]);
        assertPrivateGrants.Invoke(null,[requiredGrant,true]);Check(true);
        Refused(()=>assertPrivateGrants.Invoke(null,[requiredGrant,false]));
        BinaryPrimitives.WriteUInt32LittleEndian(privateFrame.AsSpan(40),0x1ff);
        Refused(()=>assertPrivateGrants.Invoke(null,[parseWindow.Invoke(null,[privateFrame,nonce]),true]));
        foreignRights=(byte[])windowFrame.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(foreignRights.AsSpan(40),1);
        Refused(()=>parseWindow.Invoke(null,[foreignRights,nonce]));
        using(var exact=WindowsIdentity.GetCurrent(TokenAccessLevels.Query|TokenAccessLevels.Duplicate))
        {
            var observe=windowType.GetMethod("ObserveTokens",methods)!;
            var comparison=observe.Invoke(null,[exact.AccessToken,exact.AccessToken,false])!;
            uint Field(object item,string property)=> (uint)item.GetType().GetProperty(property)!.GetValue(item)!;
            object Access(object item,string target)=>item.GetType().GetProperty(target)!.GetValue(item)!;
            foreach(var role in new[]{"Station","Desktop"})
            {
                var access=Access(comparison,role);
                Check(Field(access,"Error")==0 && Field(access,"CreatorGranted")!=0 &&
                    Field(access,"CreatorGranted")==Field(access,"ChildGranted"));
            }
            var refused=observe.Invoke(null,[exact.AccessToken,exact.AccessToken,true])!;
            Check(Field(Access(refused,"Station"),"Error")==13 && Field(Access(refused,"Desktop"),"Error")==13);
        }

        var profileType=channel.GetNestedType("CreatedProfile",BindingFlags.NonPublic)!;
        var createProfile=channel.GetMethod("CreateProfileCreated",methods)!;
        var parseProfile=channel.GetMethod("ParseProfileCreated",methods)!;
        const string parentIdentity="89ABCDEF:00000000:01020304",storageIdentity="89ABCDEF:00000001:05060708";
        object Profile(string parent,string storage)=>Activator.CreateInstance(profileType,[parent,storage])!;
        var profile=Profile(parentIdentity,storageIdentity);
        var profileFrame=(byte[])createProfile.Invoke(null,[decoded,profile])!;
        Check(profileFrame.Length==44 && profileFrame.AsSpan(0,4).SequenceEqual("CCJ1"u8));
        Check(profile.Equals(parseProfile.Invoke(null,[profileFrame,nonce])));
        Refused(()=>parseProfile.Invoke(null,[incoming,nonce]));
        Refused(()=>reply.Invoke(null,[profileFrame,nonce,20u,40L]));
        Refused(()=>parseProfile.Invoke(null,[profileFrame[..43],nonce]));
        foreach(var offset in new[]{4,32})
        {
            var changed=(byte[])profileFrame.Clone();changed[offset]^=1;
            Refused(()=>parseProfile.Invoke(null,[changed,nonce]));
        }
        var duplicated=(byte[])profileFrame.Clone();profileFrame.AsSpan(20,12).CopyTo(duplicated.AsSpan(32));
        Refused(()=>parseProfile.Invoke(null,[duplicated,nonce]));
        Refused(()=>createProfile.Invoke(null,[decoded,Profile(parentIdentity,"89ABCDEF:00000000:00000000")]));
        Refused(()=>createProfile.Invoke(null,[decoded,Profile(parentIdentity,storageIdentity.ToLowerInvariant())]));
        var createAcknowledgement=channel.GetMethod("CreateProfileRecorded",methods)!;
        var assertAcknowledgement=channel.GetMethod("AssertProfileRecorded",methods)!;
        var acknowledgement=(byte[])createAcknowledgement.Invoke(null,[nonce])!;
        Check(acknowledgement.Length==20 && acknowledgement.AsSpan(0,4).SequenceEqual("CCA1"u8));
        _=assertAcknowledgement.Invoke(null,[acknowledgement,nonce]);Check(true);
        Refused(()=>assertAcknowledgement.Invoke(null,[acknowledgement[..19],nonce]));
        Refused(()=>assertAcknowledgement.Invoke(null,[acknowledgement,new byte[16]]));
        var wrongPhase=(byte[])acknowledgement.Clone();"CCS1"u8.CopyTo(wrongPhase);
        Refused(()=>assertAcknowledgement.Invoke(null,[wrongPhase,nonce]));

        var makeTokenProof=channel.GetMethod("CreateTokenProof",methods)!;
        var parseTokenProof=channel.GetMethod("ParseTokenProof",methods)!;
        var proofType=channel.GetNestedType("TokenProof",BindingFlags.NonPublic)!;
        var bindingType=proofType.GetProperty("Binding")!.PropertyType;
        object Binding(ulong id,ulong modified)=>Activator.CreateInstance(bindingType,[id,modified])!;
        object Proof(ulong id,ulong modified,uint access)=>Activator.CreateInstance(proofType,[Binding(id,modified),access])!;
        var tokenProof=Proof(31,67,2);
        var tokenFrame=(byte[])makeTokenProof.Invoke(null,[decoded,tokenProof])!;
        Check(tokenFrame.Length==44 && tokenFrame.AsSpan(0,4).SequenceEqual("CCT1"u8));
        Check(tokenProof.Equals(parseTokenProof.Invoke(null,[tokenFrame,nonce])));
        Refused(()=>parseTokenProof.Invoke(null,[profileFrame,nonce]));
        Refused(()=>parseTokenProof.Invoke(null,[tokenFrame[..43],nonce]));
        Refused(()=>parseTokenProof.Invoke(null,[tokenFrame,new byte[16]]));
        var badTokenFrame=(byte[])tokenFrame.Clone();badTokenFrame[40]=1;
        Refused(()=>parseTokenProof.Invoke(null,[badTokenFrame,nonce]));
        Refused(()=>makeTokenProof.Invoke(null,[decoded,Proof(0,67,2)]));
        Refused(()=>makeTokenProof.Invoke(null,[decoded,Proof(31,0,2)]));
        Refused(()=>makeTokenProof.Invoke(null,[decoded,Proof(31,67,4)]));
        var assertTokenBinding=library.GetType("ProtectionLifecycle.AtomicChild",true)!.GetMethod("AssertCreatorLpacBinding",methods)!;
        _=assertTokenBinding.Invoke(null,[tokenProof,Binding(31,67)]);Check(true);
        Refused(()=>assertTokenBinding.Invoke(null,[tokenProof,Binding(32,67)]));
        Refused(()=>assertTokenBinding.Invoke(null,[tokenProof,Binding(31,68)]));
        Refused(()=>assertTokenBinding.Invoke(null,[Proof(31,67,3),Binding(31,67)]));

        var createFailure=channel.GetMethod("CreateFailure",methods)!;
        var failureStage=channel.GetNestedType("CreationFailure",BindingFlags.NonPublic)!;
        foreach(var (stageName,native) in new[]{("Profile",0x80070005u),("AtomicCreate",5u),("Streams",32u),("TokenOpen",5u),("TokenAccessCheck",13u)})
        {
            var fault=(byte[])createFailure.Invoke(null,[decoded,Enum.Parse(failureStage,stageName),native])!;
            Check(fault.Length==44 && fault.AsSpan(0,4).SequenceEqual("CCF1"u8));
            AssertFailure(()=>reply.Invoke(null,[fault,nonce,20u,40L]));
            AssertFailure(()=>parseProfile.Invoke(null,[fault,nonce]));
            AssertFailure(()=>parseTokenProof.Invoke(null,[fault,nonce]));
            fault[28]=1;
            Refused(()=>reply.Invoke(null,[fault,nonce,20u,40L]));

            void AssertFailure(Action decode)
            {
                var exact=false;
                try{decode();}
                catch(TargetInvocationException error) when(error.InnerException is IOException remote &&
                    remote.GetType().GetProperty("Stage",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(remote) is string observed &&
                    observed=="CreatorService"+stageName && unchecked((uint)remote.HResult)==native){exact=true;}
                Check(exact);
            }
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

    private static void PrivateWindowPolicy(Assembly library,object creator,object legacy,object another,string job,string creatorSid)
    {
        const BindingFlags instance=BindingFlags.Instance|BindingFlags.NonPublic;
        const BindingFlags methods=BindingFlags.Static|BindingFlags.NonPublic;
        var policyType=library.GetType("ProtectionLifecycle.SessionZeroWindowPolicy",true)!;
        var leaseType=library.GetType("ProtectionLifecycle.SessionZeroWindowLease",true)!;
        object New(object intent,bool readControl=false)=>Activator.CreateInstance(policyType,instance,null,[intent,readControl],null)!;
        var policy=New(creator);
        var descriptor=policyType.GetMethod("Descriptor",instance)!;
        var validate=policyType.GetMethod("AssertDescriptor",instance)!;
        string PathFor(object target)=>(string)policyType.GetProperty("DesktopPath",instance)!.GetValue(target)!;
        RawSecurityDescriptor Create(bool station)=>(RawSecurityDescriptor)descriptor.Invoke(policy,[station])!;
        void Check(bool value,string reason){if(!value)throw new InvalidOperationException(reason);}
        void Refused(Action action,string reason)
        {
            try{action();}
            catch(TargetInvocationException ex) when(ex.InnerException is InvalidDataException error && error.Message==reason){return;}
            throw new InvalidOperationException("Expected private window refusal: "+reason);
        }
        const string descriptorError="PrivateWindowObjectDescriptorMismatch";
        Check(PathFor(policy)==$@"CpcTask.{job}\Task" && PathFor(New(another))!=PathFor(policy),"Private desktop exposes only the ephemeral Job ID");
        Refused(()=>New(legacy),"PrivateWindowsRequireCreatorJob");
        Refused(()=>leaseType.GetMethod("Create",methods)!.Invoke(null,[creator,false]),"PrivateWindowOwnerMustBeSessionZeroSystem");
        var newPolicy=New(creator,true);
        var newStation=(RawSecurityDescriptor)descriptor.Invoke(newPolicy,[true])!;
        Check(((CommonAce)newStation.DiscretionaryAcl![2]).AccessMask==0x20023,"Station grant includes the native open check without write or owner rights");
        var newDesktop=(RawSecurityDescriptor)descriptor.Invoke(newPolicy,[false])!;
        Check(((CommonAce)newDesktop.DiscretionaryAcl![2]).AccessMask==0xc7,"Desktop grant does not change");
        validate.Invoke(newPolicy,[true,newStation]);
        Refused(()=>validate.Invoke(newPolicy,[true,Create(true)]),descriptorError);
        Refused(()=>validate.Invoke(policy,[true,newStation]),descriptorError);

        foreach(var (station,ownerMask,packageMask) in new[]{(true,0xf016f,0x23),(false,0xf01ff,0xc7)})
        {
            var actual=Create(station);
            var package=(CommonAce)actual.DiscretionaryAcl![2];
            Check(actual.Owner?.Value=="S-1-5-18" && actual.Group?.Value=="S-1-5-18" &&
                ((CommonAce)actual.DiscretionaryAcl[0]).AccessMask==ownerMask &&
                ((CommonAce)actual.DiscretionaryAcl[1]).SecurityIdentifier.Value==creatorSid &&
                ((CommonAce)actual.DiscretionaryAcl[1]).AccessMask==(0x20000|packageMask) &&
                package.AccessMask==packageMask && package.SecurityIdentifier.Value.StartsWith("S-1-15-2-",StringComparison.Ordinal) &&
                package.SecurityIdentifier.Value is not ("S-1-15-2-1" or "S-1-15-2-2"),"Exact private window principals and access masks");
            var binary=new byte[actual.BinaryLength];
            actual.GetBinaryForm(binary,0);
            validate.Invoke(policy,[station,new RawSecurityDescriptor(binary,0)]);
            Refused(()=>validate.Invoke(policy,[station,Create(!station)]),descriptorError);
            var broadened=Create(station);
            ((CommonAce)broadened.DiscretionaryAcl![2]).AccessMask|=0x40000;
            Refused(()=>validate.Invoke(policy,[station,broadened]),descriptorError);
            var shared=Create(station);
            ((CommonAce)shared.DiscretionaryAcl![1]).SecurityIdentifier=new SecurityIdentifier("S-1-5-19");
            Refused(()=>validate.Invoke(policy,[station,shared]),descriptorError);
            var wrongPackage=Create(station);
            ((CommonAce)wrongPackage.DiscretionaryAcl![2]).SecurityIdentifier=new SecurityIdentifier("S-1-15-2-2");
            Refused(()=>validate.Invoke(policy,[station,wrongPackage]),descriptorError);
            var label=Create(station);
            label.SystemAcl!.RemoveAce(0);
            Refused(()=>validate.Invoke(policy,[station,label]),descriptorError);
            var unprotected=Create(station);
            unprotected.SetFlags(unprotected.ControlFlags&~ControlFlags.DiscretionaryAclProtected);
            Refused(()=>validate.Invoke(policy,[station,unprotected]),descriptorError);
        }
        Console.WriteLine("PASS private window policy, broadened descriptor negatives and ordinary Session 0 owner refusal; no private station created");
        var owner=library.GetType("ProtectionLifecycle.SessionZeroWindowOwner",true)!;
        var name=(string)owner.GetMethod("NameForJob",methods)!.Invoke(null,[job])!;
        var parseName=owner.GetMethod("JobIdFromName",methods)!;
        Check((string?)parseName.Invoke(null,[name])==job,"Owner SCM name binds the original Job");
        Refused(()=>parseName.Invoke(null,["CpcSessionCreator."+job]),"PrivateWindowOwnerServiceNameInvalid");
        Refused(()=>owner.GetMethod("VerifyCurrentService",methods)!.Invoke(null,[name]),"PrivateWindowOwnerRequiresSystemServiceToken");
        var message=owner.GetNestedType("Message",BindingFlags.NonPublic)!;
        var send=owner.GetMethod("Frame",methods)!;
        var read=owner.GetMethod("AssertFrame",methods)!;
        var nonce=Enumerable.Range(0,16).Select(value=>(byte)value).ToArray();
        foreach(var kind in Enum.GetValues(message))
        {
            var frame=(byte[])send.Invoke(null,[nonce,kind])!;
            read.Invoke(null,[frame,nonce,kind]);
            Refused(()=>read.Invoke(null,[frame[..19],nonce,kind]),"PrivateWindowOwnerFrameMismatch");
            Refused(()=>read.Invoke(null,[frame,nonce.Reverse().ToArray(),kind]),"PrivateWindowOwnerFrameMismatch");
            foreach(var other in Enum.GetValues(message).Cast<object>().Where(value=>!Equals(value,kind)))
                Refused(()=>read.Invoke(null,[frame,nonce,other]),"PrivateWindowOwnerFrameMismatch");
        }
        Console.WriteLine("PASS fixed private window owner identity and ready/release/closed frames; no service registration");
    }

    [StructLayout(LayoutKind.Sequential)] private struct SecurityAttributes {internal int Length;internal IntPtr Descriptor;internal int Inherit;}
    [DllImport("kernel32.dll",EntryPoint="CreateJobObjectW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern SafeFileHandle CreateJobObject(ref SecurityAttributes attributes,string name);
    [DllImport("kernel32.dll",EntryPoint="OpenJobObjectW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern SafeFileHandle OpenJobObject(uint access,[MarshalAs(UnmanagedType.Bool)]bool inherit,string name);
    [DllImport("ntdll.dll",ExactSpelling=true)] private static extern int NtQueryObject(SafeFileHandle handle,int info,[Out] uint[] buffer,uint size,out uint returned);
}
