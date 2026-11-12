using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;

internal sealed record ProfileStorageReceipt(int SchemaVersion,string InstallationId,string ProfileId,bool Control,string OwnerSid,
    string Name,string Sid,string StorageRoot,string StorageIdentity,string ParentIdentity,string Status);
