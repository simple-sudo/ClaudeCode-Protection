using System.Reflection;
using System.ComponentModel;
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
        var owner=library.GetType("ProtectionLifecycle.OwnedKernelJob",true)!;
        var proof=owner.GetMethod("ValidateCreatorProof",methods)!;
        var createNative=owner.GetMethod("CreateFreshSessionZeroJob",methods)!;
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

        var baseAcl=$"D:P(A;;0x0002000f;;;SY)(A;;0x0002000f;;;BA)(A;;RC;;;{tagSid})";
        var creatorGrant=$"(A;;0x00020001;;;{creatorSid})";
        const string label="S:(ML;;NW;;;ME)";
        var creatorAcl=baseAcl+creatorGrant+label;
        void AssertCreator(string sddl)=>_=validate.Invoke(null,[new RawSecurityDescriptor(sddl),creator]);
        AssertCreator("O:BAG:SY"+creatorAcl);Check(true);
        foreach(var invalid in new[]{baseAcl+label,baseAcl+creatorGrant,creatorAcl.Replace(";;;ME",";;;LW",StringComparison.Ordinal),
            creatorAcl.Replace("0x00020001","0x00020005",StringComparison.Ordinal),creatorAcl.Replace(creatorSid,"S-1-5-19",StringComparison.Ordinal),
            creatorAcl.Replace(tagSid,creatorSid,StringComparison.Ordinal),creatorAcl.Replace("D:P","D:",StringComparison.Ordinal)})
            Refused(()=>AssertCreator("O:BAG:SY"+invalid));

        // A medium-integrity fixture can create its own empty kernel Job. It
        // uses the ordinary caller as owner to avoid granting admin rights.
        using var identity=WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        var user=identity.User??throw new InvalidOperationException("Missing ordinary token user");
        var fixtureDescriptor=new RawSecurityDescriptor("O:"+user.Value+creatorAcl);
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
            using var read=OpenJobObject(0x20000,false,Name(creator));
            Check(!read.IsInvalid);
            var actual=(RawSecurityDescriptor)seal.GetMethod("ReadJobDescriptor",methods)!.Invoke(null,[read,true])!;
            Check(actual.Owner is { } actualOwner && user.Equals(actualOwner));
            Refused(()=>validate.Invoke(null,[actual,creator])); // Ordinary-owned replacement refused.
            actual.Owner=new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null);
            _=validate.Invoke(null,[actual,creator]);Check(true); // Kernel ACL and label both match.
            using var assign=OpenJobObject(1,false,Name(creator));
            Check(assign.IsInvalid && Marshal.GetLastWin32Error()==5);
        }
        finally{pointer.Free();}
        using var closed=OpenJobObject(0x20000,false,Name(creator));
        Check(closed.IsInvalid && Marshal.GetLastWin32Error()==2);
        Console.WriteLine($"PASS {count} creator Job checks; legacy intent, proof binding, actual fresh creation, name collision refusal, ACL and label readback, ordinary assignment denial. No service, child creation, UAC, installation or WFP.");
    }

    [StructLayout(LayoutKind.Sequential)] private struct SecurityAttributes {internal int Length;internal IntPtr Descriptor;internal int Inherit;}
    [DllImport("kernel32.dll",EntryPoint="CreateJobObjectW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern SafeFileHandle CreateJobObject(ref SecurityAttributes attributes,string name);
    [DllImport("kernel32.dll",EntryPoint="OpenJobObjectW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern SafeFileHandle OpenJobObject(uint access,[MarshalAs(UnmanagedType.Bool)]bool inherit,string name);
}
