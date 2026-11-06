using System.Security.Principal;
using System.Text.Json;

if(args.Length!=1 || !Path.IsPathFullyQualified(args[0]))return 125;
using var identity=WindowsIdentity.GetCurrent();
if(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))throw new InvalidOperationException("Ordinary reference only");
using var output=new FileStream(args[0],FileMode.CreateNew,FileAccess.Write,FileShare.None);
var rows=NativeBoundary.ReadDispatchMarkers();
var report=new {Scope="ORDINARY_FIXED_AFD_PARSER_MARKERS_NOT_LPAC_OR_KERNEL_TRACE",AtUtc=DateTime.UtcNow,
    Afd=rows,NoTokenOrSecurityWrite=true,NoIoctlBindConnect=true,ProtectedIdentityTested=false};
output.Write(JsonSerializer.SerializeToUtf8Bytes(report,new JsonSerializerOptions{WriteIndented=true}));output.Flush(true);
Console.WriteLine(JsonSerializer.Serialize(rows));
return rows.Length==3 && rows[0].Status=="0x00000000" && rows.Skip(1).All(r=>r.Status=="0xC000000D") &&
    rows.All(r=>r.HandleClosed && r.ManagedError is null) && rows[0].Inheritable==false ? 0 : 125;
