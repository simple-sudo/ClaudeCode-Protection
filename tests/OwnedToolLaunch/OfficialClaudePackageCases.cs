using System.Collections;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

internal static class OfficialClaudePackageCases
{
    private const BindingFlags Static=BindingFlags.Static|BindingFlags.NonPublic;
    private const BindingFlags Instance=BindingFlags.Instance|BindingFlags.NonPublic|BindingFlags.Public;
    private const string Official="official-claude-offline-exe";
    private const string StartupWitness="broker-session-zero-startup-witness";
    private const long ImageLength=344807072;
    private const string ImageSHA256="2E055732C9D03D22700D9046251A8370B673607BFCC9E4D16A1B0E8FB1345CBD";

    internal static void Run(Assembly library)
    {
        Type TypeFor(string name)=>library.GetType("ProtectionLifecycle."+name,true)!;
        var catalog=TypeFor("PackageAssetCatalog");
        var policy=TypeFor("PackagePolicy");
        var creation=TypeFor("CreationTag");
        var removal=TypeFor("RemovalInventory");
        var acl=TypeFor("WindowsPathSeal").GetMethod("AssertOfficialStagingAudience",Static)!;
        var schema=catalog.GetMethod("ForSchema",Static)!;
        var read=policy.GetMethod("ParsePinned",Static)!;
        var inventory=policy.GetMethod("ParseInventory",Static)!;
        var release=new string('a',32);
        var genericHash=new string('B',64);
        int checks=0;

        void Check(bool condition)
        {
            if(!condition)throw new InvalidDataException("Official staging fixture mismatch");
            checks++;
        }
        void Reject(Action action)
        {
            try{action();}
            catch(InvalidDataException){checks++;return;}
            throw new InvalidDataException("Invalid official staging fixture accepted");
        }
        object? Field(object row,string name)=>row.GetType().GetProperty(name,Instance)!.GetValue(row);
        JsonArray Rows(int version,string role)
        {
            var rows=new JsonArray();
            foreach(var asset in (IEnumerable)Call(schema,version)!)
                rows.Add(new JsonObject{[role]=(string)Field(asset,"Id")!,["Length"]=(long?)Field(asset,"FixedLength")??1L,
                    ["SHA256"]=(string?)Field(asset,"FixedSHA256")??genericHash});
            return rows;
        }
        void Manifest(int version,JsonArray rows)
        {
            var bytes=JsonSerializer.SerializeToUtf8Bytes(new JsonObject{["SchemaVersion"]=version,["Scope"]="UNACTIVATED_PRODUCT",
                ["Release"]=release,["Files"]=rows.DeepClone()});
            _=Call(read,new ReadOnlyMemory<byte>(bytes),Convert.ToHexString(SHA256.HashData(bytes)));
        }
        void Stage(int version,JsonArray rows)
        {
            using var doc=JsonDocument.Parse(rows.ToJsonString());
            _=Call(inventory,doc.RootElement,version,"Id");
        }
        JsonArray Changed(JsonArray original,string role,string field,JsonNode replacement)
        {
            var rows=original.DeepClone().AsArray();
            rows.Single(row=>row!["Asset"]!.GetValue<string>()==role)![field]=replacement;
            return rows;
        }

        var v5=Rows(5,"Asset");var v6=Rows(6,"Asset");var v7=Rows(7,"Asset");var v8=Rows(8,"Asset");var v9=Rows(9,"Asset");
        Check(v5.Count==23 && v6.Count==24 && v7.Count==25 && v8.Count==25 && v9.Count==25);
        Check(JsonNode.DeepEquals(v5,new JsonArray(v6.Take(23).Select(row=>row!.DeepClone()).ToArray())));
        Check(JsonNode.DeepEquals(v6,new JsonArray(v7.Take(24).Select(row=>row!.DeepClone()).ToArray())));
        var fixedImage=v6.Single(row=>row!["Asset"]!.GetValue<string>()==Official)!;
        Check(fixedImage["Length"]!.GetValue<long>()==ImageLength && fixedImage["SHA256"]!.GetValue<string>()==ImageSHA256);
        Manifest(5,v5);Manifest(6,v6);Stage(6,Rows(6,"Id"));checks+=3;
        Manifest(7,v7);Stage(7,Rows(7,"Id"));checks+=2;
        Manifest(8,v8);Stage(8,Rows(8,"Id"));checks+=2;
        Manifest(9,v9);Stage(9,Rows(9,"Id"));checks+=2;
        Manifest(10,v9);Stage(10,Rows(10,"Id"));checks+=2;
        Check(JsonNode.DeepEquals(v9,Rows(10,"Asset")));
        Check(JsonNode.DeepEquals(v6,new JsonArray(v8.Take(24).Select(row=>row!.DeepClone()).ToArray())));
        Check(JsonNode.DeepEquals(v6,new JsonArray(v9.Take(24).Select(row=>row!.DeepClone()).ToArray())));
        Reject(()=>Manifest(5,v6));
        Reject(()=>Manifest(6,v5));
        Reject(()=>Manifest(7,v6));
        Reject(()=>Manifest(6,v7));
        Reject(()=>Manifest(7,v8));
        Reject(()=>Manifest(8,v7));
        Reject(()=>Manifest(8,v9));
        Reject(()=>Manifest(9,v8));
        Reject(()=>Manifest(7,Changed(v7,StartupWitness,"SHA256",genericHash)));
        Reject(()=>Manifest(7,Changed(v7,StartupWitness,"Length",4097L)));
        Reject(()=>Stage(5,Rows(6,"Id")));
        Reject(()=>Stage(6,Rows(5,"Id")));
        Reject(()=>Manifest(6,Changed(v6,Official,"Length",ImageLength-1)));
        Reject(()=>Manifest(6,Changed(v6,Official,"SHA256",genericHash)));
        Reject(()=>Manifest(6,Changed(v6,"daily-exe","Length",ImageLength)));
        Reject(()=>Manifest(6,Changed(v6,"daily-exe","Asset",Official)));

        const long legacyLimit=128L*1024*1024;
        var large=Changed(v6,"daily-exe","Length",legacyLimit);
        Manifest(6,large);checks++;
        Reject(()=>Manifest(6,Changed(large,"daily-dll","Length",legacyLimit)));
        Reject(()=>Manifest(6,Changed(large,"daily-exe","Length",legacyLimit+1)));
        Check((string?)Call(removal.GetMethod("FileRelative",Static)!,Official)=="bin/official/claude.exe");
        Check((string?)Call(removal.GetMethod("FileRelative",Static)!,StartupWitness)=="bin/admin/SessionZeroStartupWitness.exe");
        Check(Call(creation.GetMethod("AssetRole",Static)!,StartupWitness)?.ToString()=="SessionZeroStartupWitness");
        Check((string?)Call(removal.GetMethod("DirRelative",Static)!,"official")=="bin/official");
        var fileRole=Call(creation.GetMethod("AssetRole",Static)!,Official);
        var dirRole=Call(creation.GetMethod("DirectoryRole",Static)!,"official");
        Check(fileRole?.ToString()=="OfficialClaudeExe" && dirRole?.ToString()=="OfficialClaudeDirectory");
        var tag=Call(creation.GetMethod("For",Static)!,fileRole,release)!;
        var sid=(string)Field(tag,"Sid")!;
        void Audience(string extra)
        {
            var descriptor=new RawSecurityDescriptor("O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;RC;;;"+sid+")"+extra);
            _=Call(acl,descriptor.DiscretionaryAcl,sid);
        }
        Audience("");checks++;
        foreach(var broad in new[]{"BU","WD","S-1-15-2-1","S-1-15-2-2","S-1-15-2-123"})
            Reject(()=>Audience("(A;;GRGX;;;"+broad+")"));
        Reject(()=>Audience("(A;;GRGX;;;"+sid+")"));
        Console.WriteLine($"PASS {checks} official image inventory, compatibility, recovery role and staging audience checks. No image execution.");
    }

    private static object? Call(MethodInfo method,params object?[] values)
    {
        try{return method.Invoke(null,values);}
        catch(TargetInvocationException ex)when(ex.InnerException is not null){ExceptionDispatchInfo.Capture(ex.InnerException).Throw();throw;}
    }
}
