using System.Collections;
using System.Net.Security;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;

internal static class OpenSslMemoryCases
{
    private const BindingFlags Static=BindingFlags.Static|BindingFlags.NonPublic;
    private const BindingFlags Instance=BindingFlags.Instance|BindingFlags.NonPublic|BindingFlags.Public;
    internal static Task Run(Assembly library)
    {
        var type=library.GetType("ProtectionLifecycle.OpenSslOfflineWitness",true)!;
        var installed=library.GetType("ProtectionLifecycle.InstalledBroker",true)!;
        var id=new string('a',32);var before=DateTime.UtcNow.ToFileTimeUtc();
        int checks=0;
        void Check(bool value){if(!value)throw new InvalidDataException("Offline OpenSSL check failed");checks++;}
        void Reject<T>(Action action) where T:Exception
        {
            try{action();}
            catch(T){checks++;return;}
            throw new InvalidDataException("Invalid offline TLS input accepted");
        }
        var observe=type.GetMethod("Observe",Static)!;
        var observed=Call(observe,id,true,Type.Missing)!;
        var raw=JsonSerializer.Serialize(observed,type);
        Console.WriteLine(raw);
        var parse=type.GetMethod("Parse",Static)!;
        object Read(string data,uint exit)=>Call(parse,data,id,(uint)Environment.ProcessId,before,exit)!;
        bool Complete(object result)=>(bool)type.GetProperty("Complete",Instance)!.GetValue(result)!;
        Check(Complete(Read(raw,0)));
        Reject<InvalidDataException>(()=>Read(raw,3));
        Reject<InvalidDataException>(()=>Read(raw.Insert(1,"\"SchemaVersion\":1,"),0));
        var valid=JsonNode.Parse(raw)!.AsObject();
        foreach(var (field,value) in new (string,JsonNode?)[]{
            ("Pid",Environment.ProcessId+1),("SchemaVersion",4),("SessionId",new string('b',32)),("StartedFileTime",before-1),
            ("WrongNameError",0),("UnknownRootError",null),("EofDenied",false),("FailureStage","WRONG_NAME"),("Unreviewed",true)})
        {
            var invalid=valid.DeepClone().AsObject();invalid[field]=value;
            Reject<InvalidDataException>(()=>Read(invalid.ToJsonString(),0));
        }
        var failure=valid.DeepClone().AsObject();
        failure["FailureStage"]="UNKNOWN_ROOT";failure["ErrorCode"]=31;failure["UnknownRootError"]=null;failure["EofDenied"]=false;
        Check(!Complete(Read(failure.ToJsonString(),3)));
        Reject<InvalidDataException>(()=>Read(failure.ToJsonString(),0));
        var wrongImage=JsonNode.Parse(JsonSerializer.Serialize(Call(observe,id,false,id),type))!.AsObject();
        Check(wrongImage["SchemaVersion"]!.GetValue<int>()==3 &&
            wrongImage["FailureStage"]!.GetValue<string>()=="MODULE_IMAGE" && !Complete(Read(wrongImage.ToJsonString(),3)));
        var historical=wrongImage.DeepClone().AsObject();historical["SchemaVersion"]=1;
        Reject<InvalidDataException>(()=>Read(historical.ToJsonString(),3));
        historical["FailureStage"]="MODULES";
        Check(!Complete(Read(historical.ToJsonString(),3)));
        wrongImage["FailureStage"]="MODULE_SSL_LOAD";
        Check(!Complete(Read(wrongImage.ToJsonString(),3)));
        wrongImage["FailureStage"]="MODULE_UNKNOWN_LOAD";
        Reject<InvalidDataException>(()=>Read(wrongImage.ToJsonString(),3));
        wrongImage["FailureStage"]="FIXTURE_KEY";
        Check(!Complete(Read(wrongImage.ToJsonString(),3)));
        wrongImage["SchemaVersion"]=2;
        Reject<InvalidDataException>(()=>Read(wrongImage.ToJsonString(),3));

        var lease=library.GetType("ProtectionLifecycle.OpenSslModuleLease",true)!;
        var moduleError=library.GetType("ProtectionLifecycle.OpenSslModuleException",true)!;
        var directory=lease.GetMethod("InstalledDirectory",Static)!;
        var admin=@"D:\Windows Applications\ClaudeCodeProtection\versions\"+id+@"\bin\admin";
        var image=Path.Combine(admin,"ProtectionBroker.exe");var managed=Path.Combine(admin,"ProtectionLifecycle.dll");
        Check((string?)Call(directory,id,admin+"\\",image,managed)==admin);
        foreach(var inputs in new (string Release,string Base,string Image,string Managed)[]{
            (new string('b',32),admin,image,managed),(id,admin,image,@"C:\Elsewhere\ProtectionLifecycle.dll"),
            (id,admin,Path.Combine(admin,"Unreviewed.exe"),managed),(id,admin.Replace(@"Applications\",@"Applications\..\"),image,managed),
            (id,@"\\host\share"+admin[2..],image,managed)})
        {
            try{_=Call(directory,inputs.Release,inputs.Base,inputs.Image,inputs.Managed);}
            catch(Exception error)when(error.GetType()==moduleError &&
                (string?)moduleError.GetProperty("Stage",Instance)!.GetValue(error)=="MODULE_IMAGE"){checks++;continue;}
            throw new InvalidDataException("Unbound installed image accepted");
        }
        Reject<UnauthorizedAccessException>(()=>Call(installed.GetMethod("QualifyOpenSslOffline")!));
        Reject<UnauthorizedAccessException>(()=>Call(installed.GetMethod("QualifyFixedOpenSslHead")!));
        var env="CPC_OPENSSL_OFFLINE_SESSION";var old=Environment.GetEnvironmentVariable(env);
        try
        {
            Environment.SetEnvironmentVariable(env,id);
            Reject<InvalidDataException>(()=>Call(installed.GetMethod("RunOpenSslOfflineChild")!));
        }
        finally{Environment.SetEnvironmentVariable(env,old);}

        var policy=library.GetType("ProtectionLifecycle.PackagePolicy",true)!;
        var catalog=library.GetType("ProtectionLifecycle.PackageAssetCatalog",true)!;
        var versions=catalog.GetMethod("ForSchema",Static)!;
        var assetIds=new HashSet<string>(StringComparer.Ordinal);
        JsonArray Assets(int schema,string label)
        {
            var result=new JsonArray();
            foreach(var asset in (IEnumerable)Call(versions,schema)!)
            {
                object? Field(string name)=>asset!.GetType().GetProperty(name,Instance)!.GetValue(asset);
                result.Add(new JsonObject {[label]=(string)Field("Id")!,["Length"]=(long?)Field("FixedLength")??1L,
                    ["SHA256"]=(string?)Field("FixedSHA256")??new string('A',64)});
            }
            return result;
        }
        var pinned=policy.GetMethod("ParsePinned",Static)!;
        object ParseManifest(int schema,JsonArray assets)
        {
            var bytes=JsonSerializer.SerializeToUtf8Bytes(new JsonObject {
                ["SchemaVersion"]=schema,["Scope"]="UNACTIVATED_PRODUCT",["Release"]=id,["Files"]=assets.DeepClone()
            });
            return Call(pinned,new ReadOnlyMemory<byte>(bytes),Convert.ToHexString(SHA256.HashData(bytes)))!;
        }
        var v1=Assets(1,"Asset");var v2=Assets(2,"Asset");var v3=Assets(3,"Asset");var v4=Assets(4,"Asset");var v5=Assets(5,"Asset");
        Check(v1.Count==14 && v2.Count==16 && v3.Count==16 && v4.Count==20 && v1.All(a=>assetIds.Add(a!["Asset"]!.GetValue<string>())) &&
            v2.Take(v1.Count).All(a=>assetIds.Contains(a!["Asset"]!.GetValue<string>())) &&
            v3.Take(v1.Count).All(a=>assetIds.Contains(a!["Asset"]!.GetValue<string>())));
        _=ParseManifest(1,v1);_=ParseManifest(2,v2);_=ParseManifest(3,v3);_=ParseManifest(4,v4);checks+=4;
        Check(v5.Count==23);_=ParseManifest(5,v5);checks++;
        Reject<InvalidDataException>(()=>ParseManifest(1,v2));
        Reject<InvalidDataException>(()=>ParseManifest(2,v1));
        Reject<InvalidDataException>(()=>ParseManifest(3,v2));
        Reject<InvalidDataException>(()=>ParseManifest(2,v3));
        Reject<InvalidDataException>(()=>ParseManifest(4,v3));
        Reject<InvalidDataException>(()=>ParseManifest(3,v4));
        Reject<InvalidDataException>(()=>ParseManifest(5,v4));
        Reject<InvalidDataException>(()=>ParseManifest(4,v5));
        var changed=v2.DeepClone().AsArray();changed[15]!["SHA256"]=new string('B',64);
        Reject<InvalidDataException>(()=>ParseManifest(2,changed));
        changed=v2.DeepClone().AsArray();changed[15]!["Length"]=10;
        Reject<InvalidDataException>(()=>ParseManifest(2,changed));
        changed=v2.DeepClone().AsArray();changed[15]=changed[14]!.DeepClone();
        Reject<InvalidDataException>(()=>ParseManifest(2,changed));
        changed=v4.DeepClone().AsArray();changed[19]!["SHA256"]=new string('B',64);
        Reject<InvalidDataException>(()=>ParseManifest(4,changed));
        var stage=policy.GetMethod("ParseInventory",Static)!;
        void ReadStage(JsonArray files,int schema)
        {
            using var document=JsonDocument.Parse(files.ToJsonString());
            _=Call(stage,document.RootElement,schema,"Id");
        }
        ReadStage(Assets(1,"Id"),1);ReadStage(Assets(2,"Id"),2);ReadStage(Assets(3,"Id"),3);checks+=3;
        ReadStage(Assets(4,"Id"),4);ReadStage(Assets(5,"Id"),5);checks+=2;
        Reject<InvalidDataException>(()=>ReadStage(Assets(2,"Id"),1));
        Reject<InvalidDataException>(()=>ReadStage(Assets(2,"Id"),3));
        Reject<InvalidDataException>(()=>ReadStage(v2,2));
        Reject<InvalidDataException>(()=>ReadStage(Assets(3,"Id"),4));
        Reject<InvalidDataException>(()=>ReadStage(Assets(4,"Id"),5));

        var trust=library.GetType("ProtectionLifecycle.FixedOpenSslHeadTrust",true)!;
        var trustRead=trust.GetMethod("Read",Static)!;
        var trustDir=Path.Combine(AppContext.BaseDirectory,"native");
        var inWindow=new DateTimeOffset(2026,11,8,2,0,0,TimeSpan.Zero);
        var trusted=Call(trustRead,trustDir,inWindow)!;
        Check(((byte[])trust.GetProperty("Root",Instance)!.GetValue(trusted)!).Length==914 &&
            ((IReadOnlyList<byte[]>)trust.GetProperty("Crls",Instance)!.GetValue(trusted)!).Count==3);
        Reject<InvalidDataException>(()=>Call(trustRead,trustDir,new DateTimeOffset(2026,11,7,22,13,7,TimeSpan.Zero)));
        Reject<InvalidDataException>(()=>Call(trustRead,trustDir,new DateTimeOffset(2026,11,15,22,32,38,TimeSpan.Zero)));
        Reject<InvalidDataException>(()=>Call(trustRead,Path.Combine(trustDir,"tampered"),inWindow));

        var gateway=library.GetType("ProtectionLifecycle.GatewayChildReport",true)!;
        var tlsFailure=library.GetType("ProtectionLifecycle.OpenSslFailure",true)!;
        var nativeFailure=Activator.CreateInstance(tlsFailure,Instance,null,new object[]{"HANDSHAKE",1,23},null)!;
        var gatewayResult=Call(gateway.GetMethod("Result",Static)!,id,"HTTPS_TLS_HANDSHAKE",125,Type.Missing,nativeFailure)!;
        var gatewayRaw=JsonSerializer.Serialize(gatewayResult,gateway);
        object ReadGateway(string json)=>Call(gateway.GetMethod("Parse",Static)!,json,id,(uint)Environment.ProcessId,125u)!;
        var errors=JsonNode.Parse(gatewayRaw)!["Errors"]!.AsArray();
        Check(errors.Count==2 && errors[0]!["Kind"]!.GetValue<string>()=="TLS_OPENSSL" &&
            errors[1]!["Kind"]!.GetValue<string>()=="TLS_OPENSSL_VERIFY" && errors[1]!["Code"]!.GetValue<int>()==23);
        _=ReadGateway(gatewayRaw);checks++;
        Reject<InvalidDataException>(()=>ReadGateway(gatewayRaw.Replace("HTTPS_TLS_HANDSHAKE","HTTPS_HTTP_EXCHANGE",StringComparison.Ordinal)));
        Reject<InvalidDataException>(()=>ReadGateway(gatewayRaw.Replace("\"Code\":1,","\"Code\":2,",StringComparison.Ordinal)
            .Replace("\"Code\":1}","\"Code\":2}",StringComparison.Ordinal)));
        var responseFailure=library.GetType("ProtectionLifecycle.FixedHeadResponseException",true)!;
        var reason=library.GetType("ProtectionLifecycle.FixedHeadResponseError",true)!;
        var malformed=Activator.CreateInstance(responseFailure,Instance,null,[Enum.Parse(reason,"InvalidFieldName"),null],null)!;
        var headResult=Call(gateway.GetMethod("Result",Static)!,id,"HTTPS_HTTP_EXCHANGE",125,Type.Missing,malformed)!;
        var headRaw=JsonSerializer.Serialize(headResult,gateway);
        var headErrors=JsonNode.Parse(headRaw)!["Errors"]!.AsArray();
        Check(headErrors.Count==1 && headErrors[0]!["Kind"]!.GetValue<string>()=="FIXED_HEAD_RESPONSE" &&
            headErrors[0]!["Code"]!.GetValue<int>()==4);
        _=ReadGateway(headRaw);checks++;
        Reject<InvalidDataException>(()=>ReadGateway(headRaw.Replace("HTTPS_HTTP_EXCHANGE","HTTPS_HTTP_WRITE",StringComparison.Ordinal)));
        Reject<InvalidDataException>(()=>ReadGateway(headRaw.Replace("\"Code\":4","\"Code\":8",StringComparison.Ordinal)));
        var tailType=library.GetType("ProtectionLifecycle.FixedHeadTrailingObservation",true)!;
        var tailKind=library.GetType("ProtectionLifecycle.FixedHeadTailKind",true)!;
        var tail=Activator.CreateInstance(tailType,Instance,null,[301,5,Enum.Parse(tailKind,"EmptyChunk")],null)!;
        var extra=Activator.CreateInstance(responseFailure,Instance,null,[Enum.Parse(reason,"BytesAfterFinalHeader"),tail],null)!;
        var extraRaw=JsonSerializer.Serialize(Call(gateway.GetMethod("Result",Static)!,id,"HTTPS_HTTP_EXCHANGE",125,Type.Missing,extra),gateway);
        var extraRecord=JsonNode.Parse(extraRaw)!.AsObject();
        var extraErrors=extraRecord["Errors"]!.AsArray();
        Check(extraRecord["HttpStatus"] is null && extraErrors.Count==4 && extraErrors[1]!["Code"]!.GetValue<int>()==301 &&
            extraErrors[2]!["Code"]!.GetValue<int>()==5 && extraErrors[3]!["Code"]!.GetValue<int>()==2);
        _=ReadGateway(extraRaw);checks++;
        foreach(var (index,code) in new[]{(0,4),(1,103),(2,512),(2,4),(3,9)})
        {
            var changedReport=extraRecord.DeepClone().AsObject();
            changedReport["Errors"]!.AsArray()[index]!["Code"]=code;
            Reject<InvalidDataException>(()=>ReadGateway(changedReport.ToJsonString()));
        }
        Reject<InvalidDataException>(()=>ReadGateway(extraRaw.Replace("HTTPS_HTTP_EXCHANGE","HTTPS_HTTP_WRITE",StringComparison.Ordinal)));
        extraErrors.RemoveAt(3);
        Reject<InvalidDataException>(()=>ReadGateway(extraRecord.ToJsonString()));
        extraErrors.RemoveAt(2);extraErrors.RemoveAt(1);
        _=ReadGateway(extraRecord.ToJsonString());checks++; // historical error-only receipt
        var writeResult=Call(gateway.GetMethod("Result",Static)!,id,"HTTPS_HTTP_WRITE",125,Type.Missing,new IOException())!;
        _=ReadGateway(JsonSerializer.Serialize(writeResult,gateway));checks++;
        Console.WriteLine($"PASS {checks} fixed OpenSSL and package compatibility checks. Real TLS and gateway replay in ordinary memory only.");
        return Task.CompletedTask;
    }

    internal static void VerifyRevocation(Assembly library)
    {
        var witness=library.GetType("ProtectionLifecycle.OpenSslOfflineWitness",true)!;
        var checks=((Task<int>)Call(witness.GetMethod("VerifyRevocationOrdinary",Static)!)!).GetAwaiter().GetResult();
        Console.WriteLine($"PASS {checks} fixed HEAD and revocation checks using ordinary in-memory TLS. No sockets or external requests.");
    }

    internal static void VerifyResolverTrust(Assembly library)
    {
        var lease=library.GetType("ProtectionLifecycle.OpenSslModuleLease",true)!;
        var id=new string('a',32);
        var directory=Path.Combine(AppContext.BaseDirectory,"native");
        var now=new DateTimeOffset(2026,11,8,2,0,0,TimeSpan.Zero);
        var checks=0;
        void Check(bool value){if(!value)throw new InvalidDataException("Offline resolver trust check failed");checks++;}
        void Reject(Action action)
        {
            try{action();}
            catch(InvalidDataException){checks++;return;}
            throw new InvalidDataException("Invalid offline resolver trust input accepted");
        }
        var trust=library.GetType("ProtectionLifecycle.FixedResolverTrust",true)!;
        var read=trust.GetMethod("Read",Static)!;
        var accepted=trust.GetMethod("AcceptsPlatformChain",Static)!;
        var evidence=library.GetType("ProtectionLifecycle.ResolverTlsEvidence",true)!;
        var verifier=library.GetType("ProtectionLifecycle.OpenSslOfflineChain",true)!.GetMethod("Verify",Static)!;
        byte[] Read(string name)=>File.ReadAllBytes(Path.Combine(directory,name));
        var fixedTrust=Call(read,directory,id,now)!;
        Reject(()=>Call(read,directory,id,new DateTimeOffset(2026,11,8,1,9,59,TimeSpan.Zero)));
        Reject(()=>Call(read,directory,id,new DateTimeOffset(2026,11,15,1,9,29,TimeSpan.Zero)));
        Reject(()=>Call(read,Path.Combine(directory,"tampered"),id,now));
        var root=Read("resolver-root.der");var issuer=Read("resolver-issuer.der");var leaf=Read("resolver-leaf.der");
        var leafList=Read("resolver-leaf-list.crl");var issuerList=Read("resolver-issuer-list.crl");
        var digests=new[]{leaf,issuer,root}.Select(bytes=>Convert.ToHexString(SHA256.HashData(bytes))).ToArray();
        object Evidence(SslPolicyErrors errors,int[] chainStatus,bool expectedHost=true,string[]? chainDigests=null)
            =>Activator.CreateInstance(evidence,Instance,null,
                [expectedHost,true,true,(int)errors,chainStatus,chainDigests??digests,false],null)!;
        var offline=Evidence(SslPolicyErrors.RemoteCertificateChainErrors,[64,16777216]);
        Check((bool)Call(accepted,offline)! && (bool)Call(accepted,Evidence(SslPolicyErrors.None,[]))!);
        Check(!(bool)Call(accepted,Evidence(SslPolicyErrors.RemoteCertificateChainErrors,[64,4]))!);
        Check(!(bool)Call(accepted,Evidence(SslPolicyErrors.RemoteCertificateChainErrors,[]))!);
        Check(!(bool)Call(accepted,Evidence(SslPolicyErrors.RemoteCertificateNameMismatch,[64,16777216]))!);
        Check(!(bool)Call(accepted,Evidence(SslPolicyErrors.None,[],false))!);
        Check(!(bool)Call(accepted,Evidence(SslPolicyErrors.None,[],true,[digests[0],digests[1]]))!);
        using var modules=(IDisposable)Call(lease.GetMethod("OpenForOrdinaryFixture",Static)!)!;
        bool Verify(string host,byte[] cert,IReadOnlyList<byte[]> lists)=>
            (bool)Call(verifier,modules,host,root,cert,issuer,lists)!;
        Check(Verify("cloudflare-dns.com",leaf,[leafList,issuerList]));
        Check(!Verify("www.microsoft.com",leaf,[leafList,issuerList]));
        Check(!Verify("cloudflare-dns.com",leaf,[leafList]));
        Check(!Verify("cloudflare-dns.com",leaf,[issuerList]));
        Check(!Verify("cloudflare-dns.com",[ ..leaf,0 ],[leafList,issuerList]));
        var tampered=leafList.ToArray();tampered[^1]^=1;
        Check(!Verify("cloudflare-dns.com",leaf,[tampered,issuerList]));
        using var rootCert=new X509Certificate2(root);
        using var issuerCert=new X509Certificate2(issuer);
        using var leafCert=new X509Certificate2(leaf);
        using var chain=new X509Chain();
        chain.ChainPolicy.TrustMode=X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(rootCert);
        chain.ChainPolicy.ExtraStore.Add(issuerCert);
        chain.ChainPolicy.DisableCertificateDownloads=true;
        chain.ChainPolicy.RevocationMode=X509RevocationMode.Offline;
        _=chain.Build(leafCert);
        Check(chain.ChainElements.Count==3 && chain.ChainStatus.All(status=>
            (status.Status&~(X509ChainStatusFlags.RevocationStatusUnknown|X509ChainStatusFlags.OfflineRevocation))==0));
        var observed=Call(evidence.GetMethod("Observe",Static)!,"cloudflare-dns.com",leafCert,chain,
            chain.ChainStatus.Length==0?SslPolicyErrors.None:SslPolicyErrors.RemoteCertificateChainErrors)!;
        var verify=trust.GetMethod("Verify",Instance)!;
        Check((bool)verify.Invoke(fixedTrust,[modules,observed,leafCert,chain])!);
        Check(!(bool)verify.Invoke(fixedTrust,[modules,observed,issuerCert,chain])!);
        Console.WriteLine($"PASS {checks} offline resolver trust checks using the exact native verifier and a Windows offline certificate chain. No sockets or external requests.");
    }

    private static object? Call(MethodInfo method,params object[] args)
    {
        try{return method.Invoke(null,args);}
        catch(TargetInvocationException error)when(error.InnerException is not null)
        {ExceptionDispatchInfo.Capture(error.InnerException).Throw();throw;}
    }
}
