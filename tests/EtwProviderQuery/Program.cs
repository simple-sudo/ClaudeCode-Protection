using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

if(args.Length!=1 || args[0] is not ("fixed-powershell-provider-read-only" or "fixed-powershell-provider-registrations-read-only" or "registration-parser-policy"))return 125;
try
{
    using var identity=WindowsIdentity.GetCurrent();
    var elevated=new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    var provider=new Guid("F90714A8-5509-434A-BF6D-B1624C8A19A2");uint size=0;
    if(args[0]=="registration-parser-policy")
    {
        if(elevated)return 125;
        ProviderRegistrationInfo.QualifyParser();
        Console.WriteLine("PASS bounded TRACE_GUID_INFO parser, relative instance offsets, pre-enable entries, malformed counts, flags, padding and truncation refusal; no ETW API called");return 0;
    }
    if(args[0]=="fixed-powershell-provider-registrations-read-only")
    {
        // This new scope is ordinary-only and cannot query another GUID or
        // enumerate provider lists, sessions, controllers or event payloads.
        if(elevated)return 125;
        var registrationSizing=EnumerateTraceGuidsEx(1,ref provider,16,null,0,out size);
        if(registrationSizing==4200)
        {
            Console.WriteLine(JsonSerializer.Serialize(new{Status="FIXED_ETW_PROVIDER_REGISTRATION_QUERY_NOT_FOUND",Provider=provider,QueryCode=registrationSizing,
                ProviderRegisteredByThisQuery=false,DescriptorModified=false,EventDataRead=false,KernelDescriptorObserved=false,Elevated=false}));return 0;
        }
        if(registrationSizing!=122 || size is <8 or >65536)throw new InvalidDataException("Fixed registration query size: "+registrationSizing+"/"+size);
        for(var attempt=0;attempt<3;attempt++)
        {
            var buffer=new byte[size];var registrationStatus=EnumerateTraceGuidsEx(1,ref provider,16,buffer,checked((uint)buffer.Length),out size);
            if(registrationStatus==122){if(size<=buffer.Length || size>65536)throw new InvalidDataException("Fixed registration query growth");continue;}
            if(registrationStatus!=0 || size<8 || size>buffer.Length)throw new InvalidDataException("Fixed registration query read: "+registrationStatus+"/"+size);
            var entries=ProviderRegistrationInfo.Parse(buffer.AsSpan(0,checked((int)size)));
            Console.WriteLine(JsonSerializer.Serialize(new{Status="FIXED_ETW_PROVIDER_REGISTRATIONS_READ_ONLY",Provider=provider,QueryCode=registrationStatus,Bytes=size,
                Instances=entries,RegisteredInstances=entries.Count(e=>(e.Flags&2)==0),PreEnabledInstances=entries.Count(e=>(e.Flags&2)!=0),
                CallerRegistered=entries.Any(e=>e.Pid==Environment.ProcessId && (e.Flags&2)==0),
                ProviderRegisteredByThisQuery=false,DescriptorModified=false,EventDataRead=false,KernelDescriptorObserved=false,Elevated=false}));return 0;
        }
        throw new InvalidDataException("Fixed registration query changed repeatedly");
    }
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
[DllImport("advapi32.dll",ExactSpelling=true)] static extern uint EnumerateTraceGuidsEx(int infoClass,ref Guid provider,uint inputBytes,[Out]byte[]? buffer,uint capacity,out uint required);
