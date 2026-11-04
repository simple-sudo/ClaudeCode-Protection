using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
internal static class TimeZoneReadCases
{
    internal static void Run(Assembly library,bool metadata)
    {
        var type=library.GetType("ProtectionLifecycle.SessionTimeZoneReadAccess",true)!;
        object? Call(string name,params object?[] args)
        {
            try{return type.GetMethod(name,BindingFlags.Static|BindingFlags.NonPublic)!.Invoke(null,args);}
            catch(TargetInvocationException ex)when(ex.InnerException is not null){ExceptionDispatchInfo.Capture(ex.InnerException).Throw();throw;}
        }
        if(metadata){Console.WriteLine((string)Call("InspectCurrentMetadata")!);return;}
        var count=0;void Check(bool ok){if(!ok)throw new InvalidOperationException("Timezone policy fixture mismatch");count++;}
        var state=library.GetType("ProtectionLifecycle.ProtectedState",true)!;
        var requirePrefix=state.GetMethod("RequireFixedInventoryPrefix",BindingFlags.Static|BindingFlags.NonPublic)!;
        var intentPrefix=(string)type.GetField("IntentPrefix",BindingFlags.Static|BindingFlags.NonPublic)!.GetRawConstantValue()!;
        Check(intentPrefix=="timezone-access-intent-");
        requirePrefix.Invoke(null,new object[]{intentPrefix});
        foreach(var other in new[]{"timezone-access-","timezone-access-closed-",intentPrefix+"extra"})
        {
            var rejected=false;
            try{requirePrefix.Invoke(null,new object[]{other});}
            catch(TargetInvocationException ex)when(ex.InnerException is InvalidOperationException){rejected=true;}
            Check(rejected);
        }
        void Refuse(Action action){var refused=false;try{action();}catch(Exception ex)when(ex is InvalidDataException or ArgumentException){refused=true;}Check(refused);}
        string Canonical(string value)=>new RawSecurityDescriptor(value).GetSddlForm(AccessControlSections.Owner|AccessControlSections.Access);
        const string sid="S-1-15-2-1-2-3-4-5-6-7";
        var manifest=library.GetType("ProtectionLifecycle.SessionManifestReadAccess",true)!;
        object? Decision(string now,string before,string after)=>manifest.GetMethod("RestoreDecision",BindingFlags.Static|BindingFlags.NonPublic)!.Invoke(null,new object[]{now,before,after});
        foreach(var original in new[]{Canonical("O:SYD:AI(A;;KA;;;SY)(A;ID;KR;;;BU)"),Canonical("O:SYD:P(A;;KA;;;SY)(A;;KR;;;BU)")})
        {
            var before=new RawSecurityDescriptor(original);var granted=(string)Call("AddReadAce",original,sid)!;var after=new RawSecurityDescriptor(granted);
            Check(after.Owner==before.Owner && after.ControlFlags==before.ControlFlags);
            Check(after.DiscretionaryAcl!.Count==before.DiscretionaryAcl!.Count+1);
            var added=after.DiscretionaryAcl.Cast<GenericAce>().OfType<CommonAce>().Single(a=>a.SecurityIdentifier.Value==sid);
            Check(added.AccessMask==0x20019 && added.AceFlags==AceFlags.None && added.AceQualifier==AceQualifier.AccessAllowed);
            var old=before.DiscretionaryAcl.Cast<GenericAce>().Select(a=>Convert.ToHexString(Bytes(a))).ToArray();
            var kept=after.DiscretionaryAcl.Cast<GenericAce>().Where(a=>a is not CommonAce c || c.SecurityIdentifier.Value!=sid).Select(a=>Convert.ToHexString(Bytes(a))).ToArray();
            Check(old.SequenceEqual(kept));Check((string)Decision(original,original,granted)! =="ALREADY_ORIGINAL");
            Check((string)Decision(granted,original,granted)! =="REMOVE_EXACT_OWN_READ_GRANT");
            if((after.ControlFlags&ControlFlags.DiscretionaryAclAutoInherited)!=0)
            {
                after.SetFlags(after.ControlFlags&~ControlFlags.DiscretionaryAclAutoInherited);
                var normalized=after.GetSddlForm(AccessControlSections.Owner|AccessControlSections.Access);
                Check((string)Call("RestoreDecision",normalized,original,granted,true)! =="REMOVE_EXACT_OWN_READ_GRANT");
                Refuse(()=>Call("RestoreDecision",normalized,original,granted,false));
                after.DiscretionaryAcl.RemoveAce(0);
                Refuse(()=>Call("RestoreDecision",after.GetSddlForm(AccessControlSections.Owner|AccessControlSections.Access),original,granted,true));
            }
            Refuse(()=>Call("AddReadAce",granted,sid));
        }
        var valid=Canonical("O:SYD:P(A;;KA;;;SY)(A;;KR;;;BU)");
        foreach(var bad in new[]{"S-1-15-2-1","S-1-15-2-2","S-1-15-3-1","S-1-5-18"})Refuse(()=>Call("AddReadAce",valid,bad));
        Refuse(()=>Call("AddReadAce",Canonical("O:BUD:P(A;;KA;;;SY)"),sid));
        Refuse(()=>Call("AddReadAce",Canonical("O:SYD:P(A;;KA;;;BU)"),sid));
        Refuse(()=>Call("AddReadAce","",sid));
        Check((string)Call("PathFor","Sample Standard Time","ZONE_DEFINITION")! ==@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones\Sample Standard Time");
        Check(((string)Call("PathFor","Sample Standard Time","DYNAMIC_DST")!).EndsWith(@"\Dynamic DST",StringComparison.Ordinal));
        foreach(var bad in new[]{"",@"..\Secrets",@"UTC\..\Secrets","UTC/Secrets","UTC:Secrets"," UTC","UTC ","UTC\0Extra"})
            Refuse(()=>Call("PathFor",bad,"ZONE_DEFINITION"));
        foreach(var role in new[]{"PARENT_HIVE","CURRENT_USER","ZONE_DEFINITION\\Secrets"})Refuse(()=>Call("PathFor","UTC",role));
        var denied=false;
        try{Call("Prepare",null,null,null,new string('a',32));}catch(UnauthorizedAccessException){denied=true;}Check(denied);
        Console.WriteLine($"PASS {count} public timezone descriptor and role checks; exact non-inherited KEY_READ, original ACL order/protection preserved, unsupported/foreign/writer/path refusal, ordinary administrator gate. No registry access or mutation, UAC, protected state, process, network, Job or WFP.");
    }
    private static byte[] Bytes(GenericAce ace){var b=new byte[ace.BinaryLength];ace.GetBinaryForm(b,0);return b;}
}
