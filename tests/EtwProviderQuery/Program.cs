using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

if(args.Length!=1 || args[0]!="fixed-powershell-provider-read-only")return 125;
try
{
    using var identity=WindowsIdentity.GetCurrent();
    var elevated=new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    var provider=new Guid("F90714A8-5509-434A-BF6D-B1624C8A19A2");uint size=0;
    var sizing=EventAccessQuery(ref provider,null,ref size);
    if(sizing is not (0 or 122 or 234) || size is <20 or >65536)throw new InvalidDataException("Fixed query size: "+sizing+"/"+size);
    var bytes=new byte[size];var status=EventAccessQuery(ref provider,bytes,ref size);
    if(status!=0 || size>bytes.Length)throw new InvalidDataException("Fixed query read: "+status);
    var security=new RawSecurityDescriptor(bytes,0);string? registryFailure=null;bool? explicitValue=null;
    try
    {
        using var key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\WMI\Security",false);
        explicitValue=key?.GetValue(provider.ToString("B"),null,RegistryValueOptions.DoNotExpandEnvironmentNames) is not null;
    }
    catch(Exception error){registryFailure=error.GetType().Name;}
    Console.WriteLine(JsonSerializer.Serialize(new{Status="FIXED_ETW_PROVIDER_SECURITY_READ_ONLY",Provider=provider,QueryCode=status,Bytes=size,
        EffectiveSecurity=security.GetSddlForm(AccessControlSections.All),ExplicitRegistryValueObserved=explicitValue,RegistryReadFailure=registryFailure,
        DescriptorModified=false,ProviderRegistered=false,TraceSessionCreated=false,EventDataRead=false,Elevated=elevated}));return 0;
}
catch(Exception error){Console.Error.WriteLine(error);return 3;}

[DllImport("advapi32.dll",ExactSpelling=true)] static extern uint EventAccessQuery(ref Guid provider,[Out] byte[]? buffer,ref uint length);
