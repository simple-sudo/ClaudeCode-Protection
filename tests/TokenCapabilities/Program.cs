using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using ProtectionLifecycle;

int checks=0;
void Check(bool ok){if(!ok)throw new InvalidDataException("CapabilityFixtureFailed");checks++;}
void Reject(Action action){var rejected=false;try{action();}catch(InvalidDataException){rejected=true;}Check(rejected);}
TokenCapabilitySnapshot Fixture((string Sid,uint Attributes)[] entries,Action<IntPtr,int>? mutate=null,int? used=null)
{
    var sids=entries.Select(e=>new SecurityIdentifier(e.Sid)).ToArray();
    int size=entries.Length==0?4:8+16*entries.Length+sids.Sum(s=>s.BinaryLength);
    var p=Marshal.AllocHGlobal(size);
    try
    {
        Marshal.Copy(new byte[size],0,p,size);Marshal.WriteInt32(p,entries.Length);int cursor=8+16*entries.Length;
        for(int i=0;i<entries.Length;i++)
        {
            var bytes=new byte[sids[i].BinaryLength];sids[i].GetBinaryForm(bytes,0);Marshal.Copy(bytes,0,IntPtr.Add(p,cursor),bytes.Length);
            Marshal.WriteIntPtr(p,8+16*i,IntPtr.Add(p,cursor));Marshal.WriteInt32(p,16+16*i,unchecked((int)entries[i].Attributes));cursor+=bytes.Length;
        }
        mutate?.Invoke(p,size);return TokenCapabilitySnapshot.Parse(p,used??size);
    }
    finally{Marshal.FreeHGlobal(p);}
}
var empty=Fixture(Array.Empty<(string,uint)>());Check(empty.IsEmpty && empty.Count==0 && !empty.IsExactInternetClient);
var zero=Marshal.AllocHGlobal(8);
try{Marshal.Copy(new byte[8],0,zero,8);Check(TokenCapabilitySnapshot.Parse(zero,8).IsEmpty);Reject(()=>TokenCapabilitySnapshot.Parse(zero,3));Reject(()=>TokenCapabilitySnapshot.Parse(zero,65537));}
finally{Marshal.FreeHGlobal(zero);}
Reject(()=>TokenCapabilitySnapshot.Parse(IntPtr.Zero,4));
var internet=new[]{(TokenCapabilitySnapshot.InternetClientSid,4u)};
var exact=Fixture(internet);Check(exact.Count==1 && exact.IsExactInternetClient && !exact.IsEmpty);
var copy=exact.CopyEntries();copy[0]=new("S-1-15-3-2",4);Check(exact.IsExactInternetClient);
Check(!Fixture(new[]{("S-1-15-3-2",4u)}).IsExactInternetClient);
Check(!Fixture(new[]{("S-1-15-3-3",4u)}).IsExactInternetClient);
foreach(uint flags in new uint[]{0,1,2,3,5,7,0x10,0xffffffff})Check(!Fixture(new[]{(TokenCapabilitySnapshot.InternetClientSid,flags)}).IsExactInternetClient);
Check(!Fixture(new[]{("S-1-15-3-1",4u),("S-1-15-3-3",4u)}).IsExactInternetClient);
Reject(()=>Fixture(new[]{("S-1-15-3-1",4u),("S-1-15-3-1",4u)}));
Reject(()=>Fixture(new[]{("S-1-5-18",4u)}));
Reject(()=>Fixture(internet,(p,_)=>Marshal.WriteInt32(p,65)));
Reject(()=>Fixture(internet,used:4));
Reject(()=>Fixture(internet,(p,_)=>Marshal.WriteIntPtr(p,8,IntPtr.Zero)));
Reject(()=>Fixture(internet,(p,n)=>Marshal.WriteIntPtr(p,8,IntPtr.Add(p,n))));
Reject(()=>Fixture(internet,(p,_)=>Marshal.WriteIntPtr(p,8,p)));
Reject(()=>Fixture(internet,(p,_)=>Marshal.WriteIntPtr(p,8,IntPtr.Subtract(p,1))));
Reject(()=>Fixture(internet,(p,_)=>Marshal.WriteByte(Marshal.ReadIntPtr(p,8),0,2)));
Reject(()=>Fixture(internet,(p,_)=>Marshal.WriteByte(Marshal.ReadIntPtr(p,8),1,16)));
Reject(()=>Fixture(internet,(p,_)=>Marshal.WriteByte(Marshal.ReadIntPtr(p,8),1,0)));
Reject(()=>Fixture(internet,(p,n)=>Marshal.WriteIntPtr(p,8,IntPtr.Add(p,n-8))));
var maximum=Enumerable.Range(1,64).Select(i=>("S-1-15-3-"+i,4u)).ToArray();Check(Fixture(maximum).Count==64);
Reject(()=>Fixture(maximum.Append(("S-1-15-3-65",4u)).ToArray()));
using var own=WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
var actual=TokenCapabilitySnapshot.Read(own.Token);Check(actual.IsEmpty);
Console.WriteLine(JsonSerializer.Serialize(new{Scope="ORDINARY_CAPABILITY_BUFFER_FIXTURES_AND_OWN_QUERY_ONLY",Passed=checks,
    OwnCapabilityCount=actual.Count,OwnTokenModified=false,ProtectedProcessStarted=false,NetworkAdmission=false}));
