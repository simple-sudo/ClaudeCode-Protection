using System.Security.Principal;
using System.Text.Json;
using ProtectionLifecycle;

if(args.Length!=1)return 125;
using var identity=WindowsIdentity.GetCurrent();
if(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))throw new InvalidOperationException("Ordinary metadata reference only");
if(File.Exists(args[0]))throw new IOException("Fresh evidence path required");
var report=new {Scope="TRUSTED_ORDINARY_DEVICE_METADATA_REFERENCE_NOT_LPAC",AtUtc=DateTime.UtcNow,Identity=identity.User?.Value,
    Afd=NativeBoundary.Read(),Gpu=GpuIdentityObservation.Read(),NoTokenOrHostSecurityWrite=true,NoAfdIoctlOrNetworkConnectionRequested=true,ComputeRequested=false};
using(var output=new FileStream(args[0],FileMode.CreateNew,FileAccess.Write,FileShare.None))
{output.Write(JsonSerializer.SerializeToUtf8Bytes(report,new JsonSerializerOptions{WriteIndented=true}));output.Flush(true);}
Console.WriteLine("Ordinary fixed AFD access and CUDA identity reference saved locally. No LPAC/network/compute qualification.");return 0;
