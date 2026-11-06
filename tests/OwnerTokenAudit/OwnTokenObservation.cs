using System.Buffers.Binary;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;

namespace OwnerTokenAudit;

internal sealed record Privilege(ulong Luid,uint Attributes);
internal sealed record Query(int Kind,int Required,int Returned,bool Completed,int? Win32Error);
internal sealed record Observation(string Stage,bool Complete,string? Failure,int? FailureCode,
    string? UserSid,bool? ThreadImpersonating,uint? ElevationType,uint? Elevated,uint? AppContainer,
    string? RawPrivilegesSHA256,Privilege[]? Privileges,Query[] Queries);
internal sealed record Difference(string Status,bool? RawEqual,bool? IdentityEqual,Privilege[] Added,Privilege[] Removed,
    PrivilegeChange[] Changed);
internal sealed record PrivilegeChange(ulong Luid,uint Before,uint After);

// Diagnostics for a future fixed operation owner. This reads ONLY this
// process/effective thread identity. No supplied handle, linked token, target
// PID, token setter, privilege enable, launch, retry or admission decision.
internal static class OwnTokenObservation
{
    internal static Privilege[] Parse(byte[] bytes)
    {
        if(bytes.Length is <4 or >65536)throw new InvalidDataException("PrivilegeBufferBounds");
        uint count=BinaryPrimitives.ReadUInt32LittleEndian(bytes);
        if(count>1024 || bytes.Length!=4+12L*count)throw new InvalidDataException("PrivilegeCountOrLength");
        var result=new Privilege[count];var seen=new HashSet<ulong>();
        for(int i=0;i<result.Length;i++)
        {
            int offset=4+12*i;var luid=BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(offset,8));
            var attributes=BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset+8,4));
            if(!seen.Add(luid))throw new InvalidDataException("PrivilegeDuplicateLuid");
            // Preserve all attribute bits; diagnostics must not silently mask
            // a future flag or turn a byte difference into an accepted gate.
            result[i]=new(luid,attributes);
        }
        return result;
    }
    internal static Observation Capture(byte fill=0)
    {
        var queries=new List<Query>();string stage="PLATFORM";string? sid=null,hash=null;
        bool? impersonating=null;uint? elevationType=null,elevated=null,appContainer=null;Privilege[]? entries=null;
        try
        {
            if(!OperatingSystem.IsWindows() || !Environment.Is64BitProcess || RuntimeInformation.ProcessArchitecture!=Architecture.X64)
                throw new PlatformNotSupportedException("OwnTokenX64Required");
            stage="IDENTITY";
            using var identity=WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
            using var thread=WindowsIdentity.GetCurrent(true);
            sid=identity.User?.Value??throw new InvalidDataException("OwnTokenUserMissing");impersonating=thread is not null;
            byte[] Read(int kind)
            {
                int size=4;stage="QUERY_"+kind+"_SIZE";
                if(kind==3)
                {
                    bool sized=GetTokenInformation(identity.Token,kind,IntPtr.Zero,0,out size);int native=Marshal.GetLastWin32Error();
                    queries.Add(new(kind,size,0,false,sized?null:native));
                    if(sized || native!=122 || size is <4 or >65536)throw new InvalidDataException("OwnPrivilegeSizeUnconfirmed");
                }
                var buffer=Marshal.AllocHGlobal(size);
                try
                {
                    var initial=Enumerable.Repeat(fill,size).ToArray();Marshal.Copy(initial,0,buffer,size);
                    stage="QUERY_"+kind+"_READ";
                    bool completed=GetTokenInformation(identity.Token,kind,buffer,size,out var used);int native=Marshal.GetLastWin32Error();
                    queries.Add(new(kind,size,used,completed,completed?null:native));
                    if(!completed)throw new Win32Exception(native);
                    if(used!=size)throw new InvalidDataException("OwnTokenReturnedLengthChanged");
                    var bytes=new byte[used];Marshal.Copy(buffer,bytes,0,used);return bytes;
                }
                finally{Marshal.FreeHGlobal(buffer);}
            }
            elevationType=BinaryPrimitives.ReadUInt32LittleEndian(Read(18));
            elevated=BinaryPrimitives.ReadUInt32LittleEndian(Read(20));
            appContainer=BinaryPrimitives.ReadUInt32LittleEndian(Read(29));
            var privileges=Read(3);hash=Convert.ToHexString(SHA256.HashData(privileges));stage="PRIVILEGE_PARSE";entries=Parse(privileges);
            return new("COMPLETE",true,null,null,sid,impersonating,elevationType,elevated,appContainer,hash,entries,queries.ToArray());
        }
        catch(Exception error)when(error is not OutOfMemoryException)
        {return new(stage,false,error.GetType().Name,error.HResult,sid,impersonating,elevationType,elevated,appContainer,hash,entries,queries.ToArray());}
    }
    internal static Difference Compare(Observation? before,Observation? after)
    {
        if(before is not {Complete:true,Privileges:not null,RawPrivilegesSHA256:not null} ||
            after is not {Complete:true,Privileges:not null,RawPrivilegesSHA256:not null})
            return new("UNKNOWN_INCOMPLETE_OBSERVATION",null,null,Array.Empty<Privilege>(),Array.Empty<Privilege>(),Array.Empty<PrivilegeChange>());
        var first=before.Privileges.ToDictionary(p=>p.Luid);var last=after.Privileges.ToDictionary(p=>p.Luid);
        var added=last.Values.Where(p=>!first.ContainsKey(p.Luid)).OrderBy(p=>p.Luid).ToArray();
        var removed=first.Values.Where(p=>!last.ContainsKey(p.Luid)).OrderBy(p=>p.Luid).ToArray();
        var changed=first.Values.Where(p=>last.TryGetValue(p.Luid,out var final) && final.Attributes!=p.Attributes)
            .Select(p=>new PrivilegeChange(p.Luid,p.Attributes,last[p.Luid].Attributes)).OrderBy(p=>p.Luid).ToArray();
        bool raw=before.RawPrivilegesSHA256==after.RawPrivilegesSHA256;
        bool identity=before.UserSid==after.UserSid && before.ThreadImpersonating==after.ThreadImpersonating &&
            before.ElevationType==after.ElevationType && before.Elevated==after.Elevated && before.AppContainer==after.AppContainer;
        return new(!identity?"IDENTITY_FACTS_CHANGED":added.Length+removed.Length+changed.Length!=0?"PRIVILEGE_ENTRIES_CHANGED":
            !raw?"RAW_BYTES_CHANGED_ENTRIES_EQUAL":"OBSERVED_FIELDS_EQUAL",raw,identity,added,removed,changed);
    }
    [DllImport("advapi32.dll",SetLastError=true),DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return:MarshalAs(UnmanagedType.Bool)]private static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr data,int size,out int used);
}
