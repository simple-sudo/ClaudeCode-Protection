using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

if(args.Length!=1 || args[0] is not ("policy" or "owned-fixture"))return 125;
using var identity=WindowsIdentity.GetCurrent();
if(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))throw new InvalidOperationException("Ordinary qualification only");
var library=Assembly.LoadFrom(Path.Combine(AppContext.BaseDirectory,"ProtectionLifecycle.dll"));
var type=library.GetType("ProtectionLifecycle.SessionManifestReadAccess",true)!;
const BindingFlags flags=BindingFlags.Static|BindingFlags.NonPublic;
object Invoke(string name,params object[] values)
{
    try{return type.GetMethod(name,flags)!.Invoke(null,values)!;}
    catch(TargetInvocationException ex)when(ex.InnerException is not null){ExceptionDispatchInfo.Capture(ex.InnerException).Throw();throw;}
}
void Require(bool value,string reason){if(!value)throw new InvalidOperationException(reason);}
void Refused(Action action,string expected)
{
    try{action();}catch(InvalidDataException ex)when(ex.Message==expected){return;}
    throw new InvalidOperationException("Expected refusal: "+expected);
}
const string package="S-1-15-2-11-22-33-44-55-66-77";
string Canonical(string sddl)=>new RawSecurityDescriptor(sddl).GetSddlForm(AccessControlSections.Owner|AccessControlSections.Access);
if(args[0]=="policy")
{
    var original=Canonical("O:BAD:P(A;CIIO;KA;;;CO)(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)(A;CI;KR;;;AC)");
    var granted=(string)Invoke("AddReadAce",original,package);
    var before=new RawSecurityDescriptor(original);var after=new RawSecurityDescriptor(granted);
    Require(after.Owner==before.Owner && after.ControlFlags==before.ControlFlags,"owner and protected DACL controls preserved");
    var a=after.DiscretionaryAcl!;var b=before.DiscretionaryAcl!;
    Require(a.Count==b.Count+1,"exactly one new ACE");
    byte[] Bytes(GenericAce ace){var bytes=new byte[ace.BinaryLength];ace.GetBinaryForm(bytes,0);return bytes;}
    for(var i=0;i<b.Count;i++)Require(Bytes(a[i]).SequenceEqual(Bytes(b[i])),"all existing ACE bytes retained in order");
    var added=(CommonAce)a[a.Count-1];
    Require(added.SecurityIdentifier.Value==package && added.AccessMask==0x20019 && added.AceFlags==AceFlags.None &&
        added.AceQualifier==AceQualifier.AccessAllowed && !added.IsCallback,"exact package KEY_READ, no inheritance or write");
    foreach(var sid in new[]{"S-1-15-2-1","S-1-15-2-2","S-1-1-0","S-1-15-3-1"})
        Refused(()=>Invoke("AddReadAce",original,sid),"ManifestExactPackageSidRequired");
    Refused(()=>Invoke("AddReadAce",granted,package),"ManifestExistingOrUnsupportedPackageAce");
    Refused(()=>Invoke("AddReadAce",Canonical("O:BAD:(A;;KA;;;BA)"),package),"ManifestSystemKeySecurityUntrusted");
    foreach(var rights in new[]{"0x40000","0x80000","0x2","0x4","0x20","KA","GW","GA"})
        Refused(()=>Invoke("AddReadAce",Canonical("O:BAD:P(A;;KA;;;BA)(A;;"+rights+";;;BU)"),package),"ManifestUntrustedKeyWriter");
    Require((string)Invoke("RestoreDecision",original,original,granted)=="ALREADY_ORIGINAL","interrupted-before-write restoration is a no-op");
    Require((string)Invoke("RestoreDecision",granted,original,granted)=="REMOVE_EXACT_OWN_READ_GRANT","exact own grant eligible");
    var drift=Canonical(granted+"(A;;KR;;;WD)");
    Refused(()=>Invoke("RestoreDecision",drift,original,granted),"ManifestSecurityDriftRequiresHumanResolution");
    var inherited=Canonical("O:BAD:P(A;;KA;;;BA)(A;ID;KR;;;BU)");
    var expanded=new RawSecurityDescriptor((string)Invoke("AddReadAce",inherited,package)).DiscretionaryAcl!;
    Require(((CommonAce)expanded[1]).SecurityIdentifier.Value==package && expanded[2].AceFlags==AceFlags.Inherited,"explicit grant before inherited ACEs");
    Console.WriteLine("PASS exact package read-only DACL policy, original ACE preservation, broad principal/write/inheritance refusal and drift refusal; no registry access");return 0;
}

// The native fixture is one fresh, empty, non-secret key under this ordinary
// user's HKCU. It never opens the production HKLM key or private product state.
// Exercise the REAL production security read/write functions on this handle.
var fixture="Software\\ClaudeCodeProtection-ManifestReadFixture-"+Guid.NewGuid().ToString("N");
var user=identity.User!.Value;
var descriptor=new RawSecurityDescriptor(Canonical("O:"+user+"D:P(A;;KA;;;"+user+")"));
var initial=new byte[descriptor.BinaryLength];descriptor.GetBinaryForm(initial,0);
var memory=Marshal.AllocHGlobal(initial.Length);Marshal.Copy(initial,0,memory,initial.Length);
var attributes=new Attributes{Length=Marshal.SizeOf<Attributes>(),Descriptor=memory};
SafeRegistryHandle? key=null;var created=false;
try
{
    var status=RegCreateKeyEx((IntPtr)unchecked((int)0x80000001),fixture,0,null,0,0xf003f|0x100,ref attributes,out key,out var disposition);
    if(status!=0)throw new System.ComponentModel.Win32Exception(status);
    Require(disposition==1,"new fixture only");created=true;
    var original=(string)Invoke("ReadSecurity",key);
    var grant=Canonical(original+"(A;;KR;;;"+package+")");
    Invoke("WriteSecurity",key,grant);
    Require((string)Invoke("ReadSecurity",key)==grant,"native exact added DACL observed");
    var observed=new RawSecurityDescriptor((string)Invoke("ReadSecurity",key)).DiscretionaryAcl!;
    Require(observed.Count==2 && ((CommonAce)observed[1]).AceFlags==AceFlags.None,"native package grant has no inheritance");
    Invoke("WriteSecurity",key,original);
    Require((string)Invoke("ReadSecurity",key)==original,"native exact original security restored");
    Console.WriteLine("PASS production RegGet/RegSet security on one new ordinary HKCU fixture, exact grant and original restoration; no HKLM/product/LPAC evidence");return 0;
}
finally
{
    key?.Dispose();Marshal.FreeHGlobal(memory);
    if(created){var status=RegDeleteKeyEx((IntPtr)unchecked((int)0x80000001),fixture,0x100,0);if(status!=0)throw new System.ComponentModel.Win32Exception(status);}
}

[DllImport("advapi32.dll",EntryPoint="RegCreateKeyExW",CharSet=CharSet.Unicode)] static extern int RegCreateKeyEx(IntPtr root,string path,int reserved,string? keyClass,int options,int access,ref Attributes attributes,out SafeRegistryHandle key,out int disposition);
[DllImport("advapi32.dll",EntryPoint="RegDeleteKeyExW",CharSet=CharSet.Unicode)] static extern int RegDeleteKeyEx(IntPtr root,string path,int access,int reserved);
[StructLayout(LayoutKind.Sequential)] struct Attributes{internal int Length;internal IntPtr Descriptor;internal int Inherit;}
