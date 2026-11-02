using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text.Json;
var reviews=new List<object>();
foreach(var path in args){
 using var file=File.OpenRead(path);using var pe=new PEReader(file);
 if(!pe.HasMetadata || pe.PEHeaders.CoffHeader.Machine!=Machine.Amd64)throw new InvalidDataException("Managed x64 required");
 var md=pe.GetMetadataReader();var imports=new List<string>();
 foreach(var th in md.TypeDefinitions){var type=md.GetTypeDefinition(th);var typeName=md.GetString(type.Name);
  foreach(var mh in type.GetMethods()){var method=md.GetMethodDefinition(mh);var name=md.GetString(method.Name);
   if(typeName=="<Module>" && name==".cctor")throw new InvalidDataException("Module initializer refused");
   if((method.Attributes&MethodAttributes.PinvokeImpl)!=0){var i=method.GetImport();imports.Add(typeName+"|"+md.GetString(md.GetModuleReference(i.Module).Name)+"|"+md.GetString(i.Name));}
  }
 }
 string? approvedPackageSHA256=null;
 foreach(var rh in md.ManifestResources){var resource=md.GetManifestResource(rh);
  if(md.GetString(resource.Name)!="ProtectionBootstrap.ApprovedPackage.json")continue;
  if(approvedPackageSHA256 is not null || !resource.Implementation.IsNil)throw new InvalidDataException("Embedded approval identity refused");
  var block=pe.GetSectionData(pe.PEHeaders.CorHeader!.ResourcesDirectory.RelativeVirtualAddress);
  var length=block.GetReader(checked((int)resource.Offset),4).ReadInt32();
  if(length is <1 or >65536)throw new InvalidDataException("Embedded approval bounds");
  approvedPackageSHA256=Convert.ToHexString(SHA256.HashData(block.GetContent(checked((int)resource.Offset+4),length).ToArray()));
 }
 file.Position=0;reviews.Add(new{Path=path,SHA256=Convert.ToHexString(SHA256.HashData(file)),Imports=imports.OrderBy(x=>x,StringComparer.Ordinal).ToArray(),ModuleInitializer=false,LoadedDuringReview=false,ApprovedPackageSHA256=approvedPackageSHA256});
}
Console.WriteLine(JsonSerializer.Serialize(reviews));
