using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using OwnerTokenAudit;

if(args.Length==1 && args[0]=="--fixed-child-259")return 259;
if(args.Length==1 && args[0]=="--fixed-child-blocked")
{
    Console.WriteLine("ready");Console.Out.Flush();
    try{return Console.In.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult()=="release"?7:125;}
    catch(TimeoutException){return 125;}
}
if(args.Length!=1 || args[0]!="selftest")return 125;
int checks=0;
void Check(bool ok){if(!ok)throw new InvalidDataException("OwnerTokenAuditAssertion");checks++;}
void Reject(byte[] bytes){try{OwnTokenObservation.Parse(bytes);}catch(InvalidDataException){checks++;return;}throw new InvalidDataException("MalformedPrivilegesAccepted");}
byte[] Buffer(params Privilege[] values)
{
    var bytes=new byte[4+12*values.Length];BinaryPrimitives.WriteUInt32LittleEndian(bytes,(uint)values.Length);
    for(int i=0;i<values.Length;i++){BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(4+12*i),values[i].Luid);BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(12+12*i),values[i].Attributes);}
    return bytes;
}
Observation Fixture(byte[] bytes)=>new("COMPLETE",true,null,null,"S-1-5-21-1-2-3-1001",false,3,0,0,
    Convert.ToHexString(SHA256.HashData(bytes)),OwnTokenObservation.Parse(bytes),Array.Empty<Query>());
Check(OwnTokenObservation.Parse(new byte[4]).Length==0);
var bytes=Buffer(new(23,3),new(7,0x80000000));var parsed=OwnTokenObservation.Parse(bytes);
Check(parsed.Length==2 && parsed[0]==new Privilege(23,3) && parsed[1]==new Privilege(7,0x80000000));
Reject(new byte[3]);Reject(new byte[65537]);Reject(bytes[..^1]);Reject(bytes.Concat(new byte[1]).ToArray());
Reject(Buffer(new(7,0),new(7,2)));var overCount=new byte[4];BinaryPrimitives.WriteUInt32LittleEndian(overCount,uint.MaxValue);Reject(overCount);
var original=Fixture(bytes);
Check(OwnTokenObservation.Compare(original,original).Status=="OBSERVED_FIELDS_EQUAL");
var reordered=Fixture(Buffer(new(7,0x80000000),new(23,3)));var diff=OwnTokenObservation.Compare(original,reordered);
Check(diff.Status=="RAW_BYTES_CHANGED_ENTRIES_EQUAL" && diff.RawEqual==false && diff.Changed.Length==0);
diff=OwnTokenObservation.Compare(original,Fixture(Buffer(new(23,2),new(9,4))));
Check(diff.Status=="PRIVILEGE_ENTRIES_CHANGED" && diff.Added.Single().Luid==9 && diff.Removed.Single().Luid==7 && diff.Changed.Single()==new PrivilegeChange(23,3,2));
Check(OwnTokenObservation.Compare(original,original with{UserSid="S-1-5-18"}).Status=="IDENTITY_FACTS_CHANGED");
foreach(var incomplete in new Observation?[]{null,original with{Complete=false},original with{Privileges=null},original with{RawPrivilegesSHA256=null}})
{diff=OwnTokenObservation.Compare(original,incomplete);Check(diff.Status=="UNKNOWN_INCOMPLETE_OBSERVATION" && diff.RawEqual is null && diff.IdentityEqual is null);}
// Consecutive same-process read-only positive controls with different buffer
// prefill bytes. Neither operation queries another process or adjusts a token.
var zero=OwnTokenObservation.Capture(0);var a5=OwnTokenObservation.Capture(0xa5);var fiveA=OwnTokenObservation.Capture(0x5a);
Check(zero.Complete && a5.Complete && fiveA.Complete);
Check(zero.ThreadImpersonating==false && zero.Elevated==0 && zero.AppContainer==0);
var zeroA5=OwnTokenObservation.Compare(zero,a5);var a5FiveA=OwnTokenObservation.Compare(a5,fiveA);
var startedProcessCases=StartedProcessCases.Run(Check);
Console.WriteLine(JsonSerializer.Serialize(new{Scope="ORDINARY_OWN_TOKEN_FIXTURES_AND_FIXED_CHILD_HANDLE_OBSERVATIONS_ONLY",Passed=checks,StartedProcesses=startedProcessCases,
    Zero=zero,A5=a5,FiveA=fiveA,ZeroA5=zeroA5,A5FiveA=a5FiveA,TokenAdjusted=false,NativeOperationRetried=false,AdmissionGranted=false}));
// Differences remain observable evidence, not an ignored pass. They do not
// overwrite the earlier elevated helper's failed final audit.
return zeroA5.Status=="OBSERVED_FIELDS_EQUAL" && a5FiveA.Status=="OBSERVED_FIELDS_EQUAL"?0:3;
