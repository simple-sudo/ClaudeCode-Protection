using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Win32.SafeHandles;

internal static class OfflineConsoleNativeCases
{
    private const BindingFlags Instance=BindingFlags.Instance|BindingFlags.NonPublic|BindingFlags.Public;
    private const BindingFlags Static=BindingFlags.Static|BindingFlags.NonPublic;
    private const uint Success=0,StillRunning=258;

    internal static void Run(Assembly library)
    {
        var broker=library.GetType("ProtectionLifecycle.InstalledBroker",true)!;
        Refuse<UnauthorizedAccessException>(()=>Call(broker.GetMethod("QualifyOfflineConsole")!,null));
        Refuse<UnauthorizedAccessException>(()=>Call(broker.GetMethod("QualifyIndependentGitInit")!,null));
        Refuse<UnauthorizedAccessException>(()=>Call(broker.GetMethod("QualifyIndependentGitCommit")!,null));
        Refuse<UnauthorizedAccessException>(()=>Call(broker.GetMethod("QualifyIndependentCuda")!,null));
        var atomic=library.GetType("ProtectionLifecycle.AtomicChild",true)!;
        Refuse<InvalidDataException>(()=>Call(atomic.GetMethod("AssertOfflineConsoleWorkerIdentity",Static)!,null));
        var window=library.GetType("ProtectionLifecycle.SessionZeroWindowLease",true)!;
        Refuse<InvalidDataException>(()=>Call(window.GetMethod("AssertCurrentPrivateDesktop",Static)!,null,new string('a',32)));
        VerifyFailureMetadata(library);
        VerifyWorkspaceEnvironment(library);
        VerifyProjectionEvidence(library);
        VerifyHostIdentityEvidence(library);
        VerifyNativeIdentitySurvey(library);
        VerifyNetworkContentSurvey(library);
        var type=library.GetType("ProtectionLifecycle.OfflineConsoleStreams",true)!;
        var read=type.GetMethod("ReadBounded",Static)!;
        foreach(var length in new[]{0,4096})
        {
            using var bytes=new MemoryStream(new byte[length]);
            var result=Result((Task)Call(read,null,bytes)!);
            Require(result.Bytes.Length==length && !result.Overflow);
        }
        foreach(var mode in new[]{"normal","flood","gpu","gpu-flood"})RunChild(library,type,mode);
        Console.WriteLine("PASS native ordinary three-handle inheritance, stdin EOF, distinct output, ordinary and GPU capture bounds, excluded handle and child-creation refusal. LPAC and WFP not executed.");
    }

    internal static void VerifyGitCommit(Assembly library)
    {
        var git=library.GetType("ProtectionLifecycle.SessionGitToolchain",true)!;
        using var assets=(IDisposable)Call(git.GetMethod("Open",Static)!,null)!;
        var workspace=Directory.CreateTempSubdirectory("CpcGitCommit-").FullName;
        Call(git.GetMethod("PrepareIndependentCommit",Static)!,null,workspace);
        var start=(ProcessStartInfo)Call(git.GetMethod("StartIndependentCommit",Static)!,null,workspace)!;
        using var child=Process.Start(start)??throw new InvalidOperationException("Fixed Git did not start");
        child.StandardInput.Close();
        var stdout=child.StandardOutput.ReadToEndAsync();
        var stderr=child.StandardError.ReadToEndAsync();
        Require(child.WaitForExit(8000));
        var output=stdout.WaitAsync(TimeSpan.FromSeconds(1)).GetAwaiter().GetResult();
        var error=stderr.WaitAsync(TimeSpan.FromSeconds(1)).GetAwaiter().GetResult();
        if(child.ExitCode!=0 || output.Length!=0 || error.Length!=0)
            throw new InvalidOperationException($"Fixed Git failed with exit {child.ExitCode}: {error}");
        var verify=git.GetMethod("IndependentCommitObserved",Static)!;
        Require(Call(verify,null,workspace) is true);
        var reference=Path.Combine(workspace,"git-project",".git","refs","heads","qualification");
        File.WriteAllText(reference,new string('x',40)+"\n");
        Refuse<InvalidDataException>(()=>Call(verify,null,workspace));
        Console.WriteLine("PASS ordinary pinned Git commit -a, exact tracked text and nested binary objects, malformed branch refusal.");
    }

    private static void VerifyFailureMetadata(Assembly library)
    {
        var owner=library.GetType("ProtectionLifecycle.OfflineConsoleQualification",true)!;
        var output=library.GetType("ProtectionLifecycle.OfflineConsoleOutput",true)!;
        var parse=owner.GetMethod("ParseChildFailure",Static)!;
        const string known="CPC_OFFLINE_CONSOLE_FAILURE|Workspace|ACCESS|-2147024891\n";
        object? Parse(string message,uint exit=125,bool overflow=false)=>
            Call(parse,null,exit,Activator.CreateInstance(output,Encoding.ASCII.GetBytes(message),overflow));
        var result=Parse(known)!;
        Require(result.GetType().GetProperty("Stage")!.GetValue(result) as string=="Workspace");
        Require((int)result.GetType().GetProperty("Code")!.GetValue(result)! == -2147024891);
        var privateDesktop=Parse("CPC_OFFLINE_CONSOLE_FAILURE|PrivateDesktop|CONTRACT|-2146233087\n")!;
        Require(privateDesktop.GetType().GetProperty("Stage")!.GetValue(privateDesktop) as string=="PrivateDesktop");
        Require(Parse(known,0) is null && Parse(known,overflow:true) is null);
        Require(Parse(known.Replace("Workspace","4",StringComparison.Ordinal)) is null);
        Require(Parse(known.Replace("ACCESS","unreviewed",StringComparison.Ordinal)) is null);
        Require(Parse(known.Replace("-2147024891","+12",StringComparison.Ordinal)) is null);
        Require(Parse(known+"private extra") is null);
    }

    private static void VerifyWorkspaceEnvironment(Assembly library)
    {
        var owner=library.GetType("ProtectionLifecycle.OfflineConsoleQualification",true)!;
        var bind=owner.GetMethod("BindEnvironment",Static)!;
        var verify=owner.GetMethod("FindEnvironmentMismatch",Static)!;
        var session=new string('a',32);
        var parent=Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var workspace=Path.Combine(parent,"ClaudeCodeProtection-Task-"+session);
        var package="ClaudeCodeProtection."+new string('b',32);
        var nativeBase=Path.Combine(workspace,"local");
        var localData=Path.Combine(nativeBase,"Packages",package,"AC");
        var temp=Path.Combine(localData,"Temp");
        var env=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        _=Call(bind,null,env,workspace,package,session);
        Require(env.Count==11 && env["ProgramFiles"]==parent && env["CPC_OFFLINE_CONSOLE_SESSION"]==session &&
            env["TEMP"]==temp && env["TMP"]==temp && env["LOCALAPPDATA"]==nativeBase && env["CPC_OFFLINE_CONSOLE_PACKAGE"]==package);
        string? Diagnose(string cwd)=>Call(verify,null,workspace,localData,temp,cwd,(Func<string,string?>)(name=>env.GetValueOrDefault(name)))?.ToString();
        Require(Diagnose(workspace)=="LocalAppData");
        env["LOCALAPPDATA"]=localData;
        Require(Diagnose(workspace.ToUpperInvariant()) is null);
        Require(Diagnose(parent)=="CurrentDirectory");
        foreach(var (name,expected) in new[]{("TEMP","Temp"),("TMP","Tmp"),("LOCALAPPDATA","LocalAppData"),("USERPROFILE","UserProfile"),
            ("HOME","Home"),("XDG_CONFIG_HOME","XdgConfigHome"),("CLAUDE_CONFIG_DIR","ClaudeConfigDir"),("APPDATA","AppData")})
        {
            var original=env[name];
            Require(env.Remove(name) && Diagnose(workspace)==expected);
            env.Add(name,original);
        }
        env["TEMP"]=Path.Combine(parent,"HostTemp");
        Require(Diagnose(workspace)=="Temp");
        env["TEMP"]=Path.Combine(localData,"Packages",package,"AC","Temp");
        Require(Diagnose(workspace)=="Temp");
        env["TEMP"]=temp;
        env["HTTP_PROXY"]="unused";
        Require(Diagnose(workspace)=="UnexpectedAuthority");
        Refuse<InvalidDataException>(()=>Call(bind,null,env,workspace,package,session));
        Refuse<InvalidDataException>(()=>Call(bind,null,new Dictionary<string,string>(),parent,package,session));
        Refuse<InvalidDataException>(()=>Call(bind,null,new Dictionary<string,string>(),workspace,"..\\"+package,session));
        Refuse<InvalidDataException>(()=>Call(bind,null,new Dictionary<string,string>(),workspace,package+"\\..",session));
    }

    private static void VerifyProjectionEvidence(Assembly library)
    {
        var projection=library.GetType("ProtectionLifecycle.OfflineConsoleProjection",true)!;
        var parse=projection.GetMethod("Parse",Static)!;
        var classify=projection.GetMethod("Classify",Static)!;
        var session=new string('b',32);
        byte[] Frame(string? temp)=>System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new {
            SchemaVersion=1,SessionId=session,Pid=42,Temp=temp,Tmp=(string?)null,LocalAppData=""
        });
        var data=Frame(@"C:\Private\Path");
        _=Call(parse,null,data,session,42u);
        Refuse<InvalidDataException>(()=>Call(parse,null,data,session,43u));
        Refuse<InvalidDataException>(()=>Call(parse,null,data,new string('c',32),42u));
        Refuse<InvalidDataException>(()=>Call(parse,null,Frame(new string('x',241)),session,42u));
        Refuse<InvalidDataException>(()=>Call(parse,null,Frame("a\0b"),session,42u));
        var duplicate=Encoding.UTF8.GetBytes("{\"Temp\":null,"+Encoding.UTF8.GetString(data)[1..]);
        Refuse<InvalidDataException>(()=>Call(parse,null,duplicate,session,42u));
        foreach(var (actual,expected) in new (string?,string)[] {
            (null,"ABSENT"),("","EMPTY"),(@"C:\Profile\AC\Temp","OWNED_EXACT"),(@"C:\Profile\AC\Temp\","OWNED_TRAILING_SEPARATOR"),
            (@"C:\Task","TASK_WORKSPACE"),(@"C:\Host\Temp\","HOST_DEFAULT"),(@"C:\Unknown","OTHER")
        })
            Require((string?)Call(classify,null,actual,@"C:\Profile\AC\Temp",@"C:\Task",@"C:\Host\Temp")==expected);
    }

    private static void VerifyHostIdentityEvidence(Assembly library)
    {
        var type=library.GetType("ProtectionLifecycle.OfflineConsoleHostIdentity",true)!;
        var reading=library.GetType("ProtectionLifecycle.OfflineConsoleIdentityRead",true)!;
        var parse=type.GetMethod("Parse",Static)!;
        var compare=type.GetMethod("Compare",Static)!;
        var assertTokenUser=type.GetMethod("AssertTokenUser",Instance)!;
        var session=new string('c',32);
        var reference=Call(type.GetMethod("Capture",Static)!,null,session)!;
        var captured=JsonSerializer.SerializeToUtf8Bytes(reference,type);
        _=Call(parse,null,captured,session,(uint)Environment.ProcessId);
        using var identity=WindowsIdentity.GetCurrent();
        using(var document=JsonDocument.Parse(captured))
        {
            var root=document.RootElement;
            foreach(var field in new[]{"TokenUser","LogonName","ProfileDirectory","ComputerName","MachineGuid"})
                Require(root.GetProperty(field).GetProperty("Error").GetInt32()==0 &&
                    root.GetProperty(field).GetProperty("Value").GetString() is {Length:>0});
            Require(root.GetProperty("TokenUser").GetProperty("Value").GetString()==identity.User?.Value);
        }
        _=Call(assertTokenUser,reference,identity.User);
        Refuse<InvalidDataException>(()=>Call(assertTokenUser,reference,new SecurityIdentifier(WellKnownSidType.LocalServiceSid,null)));
        Refuse<InvalidDataException>(()=>Call(assertTokenUser,reference,(SecurityIdentifier?)null));
        var unreadable=JsonNode.Parse(captured)!.AsObject();
        unreadable["TokenUser"]=new JsonObject{["Error"]=5,["Value"]=null};
        var denied=Call(parse,null,JsonSerializer.SerializeToUtf8Bytes(unreadable),session,(uint)Environment.ProcessId)!;
        Refuse<InvalidDataException>(()=>Call(assertTokenUser,denied,identity.User));
        Refuse<InvalidDataException>(()=>Call(parse,null,captured,session,0u));
        Refuse<InvalidDataException>(()=>Call(parse,null,captured,new string('d',32),(uint)Environment.ProcessId));
        Refuse<InvalidDataException>(()=>Call(parse,null,new byte[32769],session,(uint)Environment.ProcessId));
        void Deny(Action<JsonObject> change)
        {
            var sample=JsonNode.Parse(captured)!.AsObject();
            change(sample);
            Refuse<InvalidDataException>(()=>Call(parse,null,JsonSerializer.SerializeToUtf8Bytes(sample),session,(uint)Environment.ProcessId));
        }
        Deny(sample=>sample["MachineGuid"]!["Error"]=5);
        Deny(sample=>sample["ProfileDirectory"]!["Value"]=new string('x',1024));
        Deny(sample=>sample["ComputerName"]!["Value"]="a\0b");
        Deny(sample=>sample["LogonName"]!["Extra"]=true);
        Deny(sample=>sample.Remove("TokenUser"));
        object Reading(int error,string? value)=>Activator.CreateInstance(reading,error,value)!;
        var host=Reading(0,"Owner");
        foreach(var (actor,expected) in new[]{
            (Reading(0,"owner"),"MATCHES_HOST"),(Reading(0,"other"),"DIFFERS_FROM_HOST"),
            (Reading(5,null),"DENIED"),(Reading(2,null),"UNAVAILABLE")})
            Require((string?)Call(compare,null,actor,host)==expected);
        Require((string?)Call(compare,null,host,Reading(5,null))=="REFERENCE_UNAVAILABLE");
        Console.WriteLine("PASS five actual ordinary identity reads and bounded identity evidence controls. Restricted identity not executed.");
    }

    private static void VerifyNativeIdentitySurvey(Assembly library)
    {
        var type=library.GetType("ProtectionLifecycle.OfflineConsoleHostIdentity",true)!;
        var session=new string('e',32);
        var capture=Call(type.GetMethod("CaptureSurvey",Static)!,null,session)!;
        var encoded=JsonSerializer.SerializeToUtf8Bytes(capture,type);
        var parse=type.GetMethod("Parse",Static)!;
        _=Call(parse,null,encoded,session,(uint)Environment.ProcessId);
        var survey=JsonNode.Parse(encoded)!.AsObject();
        Require(survey["SchemaVersion"]!.GetValue<int>()==2);
        foreach(var field in new[]{"LsaName","LsaDomain","FirmwareUuid","FirmwareSerial"})
            Require(survey["Native"]![field]!["Error"]!.GetValue<int>()==0 &&
                survey["Native"]![field]!["Value"]!.GetValue<string>().Length>0);
        survey["Native"]!["FirmwareUuid"]!["Value"]="not-native-hex";
        Refuse<InvalidDataException>(()=>Call(parse,null,JsonSerializer.SerializeToUtf8Bytes(survey),session,(uint)Environment.ProcessId));

        var native=library.GetType("ProtectionLifecycle.OfflineConsoleNativeIdentity",true)!;
        var parseFirmware=native.GetMethod("ParseFirmware",Static)!;
        var fixture=new byte[8+24+5];
        BinaryPrimitives.WriteUInt32LittleEndian(fixture.AsSpan(4),29);
        fixture[8]=1;fixture[9]=24;fixture[15]=2;
        fixture[16]=42;
        fixture[32]=(byte)'A';fixture[34]=(byte)'B';
        void CheckFirmware(byte[] bytes,int uuidError,string? serial)
        {
            var result=Call(parseFirmware,null,bytes)!;
            var first=result.GetType().GetField("Item1")!.GetValue(result)!;
            var second=result.GetType().GetField("Item2")!.GetValue(result)!;
            var read=first.GetType();
            Require((int)read.GetProperty("Error")!.GetValue(first)! ==uuidError);
            Require((string?)read.GetProperty("Value")!.GetValue(second)==serial);
        }
        CheckFirmware(fixture,0,"42");
        CheckFirmware(fixture[..^1],13,null);
        fixture[16]=0;
        CheckFirmware(fixture,1168,"42");
        fixture[9]=2;
        CheckFirmware(fixture,13,null);

        var surveyType=library.GetType("ProtectionLifecycle.OfflineConsoleIdentitySurvey",true)!;
        var gate=library.GetType("ProtectionLifecycle.OfflineConsoleQualification",true)!.GetMethod("SurveyIdentityObserved",Static)!;
        bool Accepted(string name,string domain,string uuid,string serial) =>
            Call(gate,null,Activator.CreateInstance(surveyType,5,5,5,5,5,name,domain,uuid,serial)) is true;
        Require(Accepted("DENIED","DENIED","DENIED","DENIED"));
        Require(!Accepted("UNAVAILABLE","DENIED","DENIED","DENIED"));
        Require(!Accepted("DENIED","MATCHES_HOST","DENIED","DENIED"));
        Require(!Accepted("DENIED","DENIED","DIFFERS_FROM_HOST","DENIED"));
        Require(!Accepted("DENIED","DENIED","DENIED","MATCHES_HOST"));
        Console.WriteLine("PASS actual ordinary own-logon and SMBIOS content reads, bounded firmware parsing and identity survey refusals.");
    }

    internal static void VerifyNetworkProfileMapping(Assembly library)=>VerifyNetworkContentSurvey(library);

    private static void VerifyNetworkContentSurvey(Assembly library)
    {
        var type=library.GetType("ProtectionLifecycle.OfflineConsoleNetworkSurvey",true)!;
        var session=new string('f',32);
        var start=DateTime.UtcNow.ToFileTimeUtc();
        var captured=Call(type.GetMethod("Capture",Static)!,null,session)!;
        var parse=type.GetMethod("Parse",Static)!;
        var bytes=JsonSerializer.SerializeToUtf8Bytes(captured,type);
        var native=Call(parse,null,bytes,session,(uint)Environment.ProcessId,start)!;
        var after=Call(type.GetMethod("CaptureProcesses",Static)!,null)!;
        var comparison=Call(type.GetMethod("Compare",Instance)!,native,captured,after,new string('A',64))!;
        var receiptsType=type.GetNestedType("ActorReceipts",BindingFlags.NonPublic)!;
        var receiptsCtor=receiptsType.GetConstructors(BindingFlags.Instance|BindingFlags.Public|BindingFlags.NonPublic)
            .Single(ctor=>ctor.GetParameters().Length==2 && ctor.GetParameters()[0].ParameterType==typeof(string[]) &&
                ctor.GetParameters()[1].ParameterType==typeof(string));
        var readReceipts=Enumerable.Repeat(new string('A',64),3).ToArray();
        var actorReceipts=receiptsCtor.Invoke(new object[]{readReceipts,new string('B',64)});
        var profile=Call(type.GetMethod("BuildEvidenceProfile",Instance)!,native,session,actorReceipts,actorReceipts,captured,after)!;
        var profileNode=JsonSerializer.SerializeToNode(profile)!;
        Require(profileNode["Assessments"]!.AsArray().Any(item=>item?["Classification"]!.GetValue<int>()==0));
        Require(profileNode["Assessments"]!.AsArray().Any(item=>item?["Classification"]!.GetValue<int>()==1));
        Require(profileNode["P0Exposure"]!.GetValue<bool>());
        var summary=JsonSerializer.SerializeToNode(comparison)!;
        Require(summary["Adapters"]!["Status"]!.GetValue<string>()=="CONTENT_READ");
        Require(summary["MatchingAdapterNames"]!.GetValue<int>()>0);
        Require(summary["MatchingAdapterMacs"]!.GetValue<int>()>0);
        Require(summary["TcpV4"]!["CapturedBytes"]!.GetValue<int>()>0 &&
            summary["TcpV6"]!["CapturedBytes"]!.GetValue<int>()>0);
        Refuse<InvalidDataException>(()=>Call(parse,null,bytes,session,0u,start));
        Refuse<InvalidDataException>(()=>Call(parse,null,bytes,session,(uint)Environment.ProcessId+1,start));
        Refuse<InvalidDataException>(()=>Call(parse,null,bytes,session,(uint)Environment.ProcessId,DateTime.UtcNow.AddSeconds(10).ToFileTimeUtc()));
        var wrongRole=JsonNode.Parse(bytes)!;
        wrongRole["Network"]!["Reads"]![0]!["Role"]="other";
        Refuse<InvalidDataException>(()=>Call(parse,null,JsonSerializer.SerializeToUtf8Bytes(wrongRole),session,(uint)Environment.ProcessId,start));
        var wrongProcess=JsonNode.Parse(bytes)!;
        wrongProcess["Processes"]!["Rows"]!.AsArray().Add(new JsonObject{
            ["Name"]="other",["Pid"]=1,["CreatedFileTime"]=null
        });
        Refuse<InvalidDataException>(()=>Call(parse,null,JsonSerializer.SerializeToUtf8Bytes(wrongProcess),session,(uint)Environment.ProcessId,start));
        Console.WriteLine("PASS ordinary network-content fixture and deterministic host/actor profile mapping; NOT LPAC/L3.");
    }

    private static void RunChild(Assembly library,Type type,string mode)
    {
        using var transport=(IDisposable)Activator.CreateInstance(type,nonPublic:true)!;
        using var binding=(IDisposable)Call(type.GetMethod("PrepareCreationAttributes",Instance)!,transport)!;
        var (input,output,error)=((IntPtr,IntPtr,IntPtr))binding.GetType().GetProperty("Channels",Instance)!.GetValue(binding)!;
        using var excluded=new EventWaitHandle(false,EventResetMode.ManualReset);
        if(!SetHandleInformation(excluded.SafeWaitHandle,1,1))throw Error("MakeFixtureEventInheritable");
        var image=Environment.ProcessPath!;
        var gpu=mode is "gpu" or "gpu-flood";
        var value=excluded.SafeWaitHandle.DangerousGetHandle().ToInt64().ToString(CultureInfo.InvariantCulture);
        var command=new StringBuilder($"\"{image}\" offline-console-streams-worker {mode} {value}");
        var jobType=library.GetType("ProtectionLifecycle.SafeJobHandle",true)!;
        using var job=(SafeHandle)Activator.CreateInstance(jobType)!;
        using(var createdJob=new SafeFileHandle(CreateJobObject(IntPtr.Zero,null),ownsHandle:true))
        {
            if(createdJob.IsInvalid)throw Error("CreateOrdinaryConsoleFixtureJob");
            _=Call(typeof(SafeHandle).GetMethod("SetHandle",Instance)!,job,createdJob.DangerousGetHandle());
            createdJob.SetHandleAsInvalid();
        }
        using var assignment=(SafeHandle)Call(jobType.GetMethod("DuplicateAssignment",Instance)!,job)!;
        nuint size=0;
        _=InitializeProcThreadAttributeList(IntPtr.Zero,3,0,ref size);
        if(size is 0 or >65536)throw Error("SizeFixtureAttributeList");
        var attributes=Marshal.AllocHGlobal(checked((int)size));
        var jobList=IntPtr.Zero;
        ProcessInfo native;
        bool initialized=false;
        try
        {
            if(!InitializeProcThreadAttributeList(attributes,3,0,ref size))throw Error("CreateFixtureAttributeList");
            initialized=true;
            _=Call(binding.GetType().GetMethod("Bind",Instance)!,binding,attributes);
            jobList=Marshal.AllocHGlobal(IntPtr.Size);Marshal.WriteIntPtr(jobList,assignment.DangerousGetHandle());
            if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)0x2000d,jobList,(nuint)IntPtr.Size,IntPtr.Zero,IntPtr.Zero))
                throw Error("BindFixtureAssignOnlyJob");
            var startup=new StartupEx{Basic=new(){Size=Marshal.SizeOf<StartupEx>(),Flags=0x100,Input=input,Output=output,Error=error},
                Attributes=attributes};
            var detached=(uint)type.GetField("DetachedCreationFlag",Static)!.GetRawConstantValue()!;
            if(!CreateProcess(image,command,IntPtr.Zero,IntPtr.Zero,true,0x00080004u|detached,IntPtr.Zero,null,ref startup,out native))
                throw Error("CreateSuspendedConsoleFixture");
        }
        finally
        {
            if(initialized)DeleteProcThreadAttributeList(attributes);
            if(jobList!=IntPtr.Zero)Marshal.FreeHGlobal(jobList);
            Marshal.FreeHGlobal(attributes);
        }
        using var process=new SafeProcessHandle(native.Process,true);
        using var thread=new SafeWaitHandle(native.Thread,true);
        try
        {
            var atomic=library.GetType("ProtectionLifecycle.AtomicChild",true)!;
            Require(IsProcessInJob(process,job,out var member) && member);
            _=Call(atomic.GetMethod("AssertNoChildCreation",Static)!,null,process);
            var checkInitialThread=atomic.GetMethod("AssertHeldInitialThread",Static)!;
            _=Call(checkInitialThread,null,process,thread,native.Pid,native.Tid);
            Refuse<InvalidDataException>(()=>Call(checkInitialThread,null,process,thread,native.Pid,0u));
            Refuse<InvalidDataException>(()=>Call(checkInitialThread,null,process,thread,(uint)Environment.ProcessId,native.Tid));
            using(var foreign=new SafeWaitHandle(GetCurrentThread(),ownsHandle:false))
                Refuse<InvalidDataException>(()=>Call(checkInitialThread,null,process,foreign,native.Pid,GetCurrentThreadId()));
            var tokenArguments=new object?[]{process,false,true,null};
            _=Call(atomic.GetMethod("ReadTokenSnapshot",Static)!,null,tokenArguments);
            using(var identity=WindowsIdentity.GetCurrent())
                Require(tokenArguments[3] is SecurityIdentifier childUser && childUser.Value==identity.User?.Value);
            using(var query=(SafeAccessTokenHandle)Call(atomic.GetMethod("OpenCreatorQueryToken",Static)!,null,process)!)
            {
                var stats=library.GetType("ProtectionLifecycle.WindowsTokenInformation",true)!;
                var tokenBinding=Call(stats.GetMethod("ReadPrimaryBinding",Static)!,null,query);
                var observed=Call(atomic.GetMethod("ObserveCreatorTokenProof",Static)!,null,process)!;
                Require(Equals(tokenBinding,observed.GetType().GetProperty("Binding")!.GetValue(observed)));
                Require(observed.GetType().GetProperty("PackageAccess")!.GetValue(observed) is 3u);
                Refuse<InvalidDataException>(()=>Call(atomic.GetMethod("AssertCreatorLpacBinding",Static)!,null,observed,tokenBinding));
            }
            var captures=(ITuple)Call(type.GetMethod(gpu?"ReadGpuAfterCreate":"ReadAfterCreate",Instance)!,transport)!;
            Refuse<InvalidDataException>(()=>Call(type.GetMethod("ReadAfterCreate",Instance)!,transport));
            Require(ResumeThread(thread)==1);
            var wait=WaitForSingleObject(process,6000);
            if(wait!=Success || !GetExitCodeProcess(process,out var exit))
                throw new InvalidDataException("Ordinary console fixture exit unavailable: "+wait);
            var stdout=Result((Task)captures[0]!);
            var stderr=Result((Task)captures[1]!);
            if(exit!=0)throw new InvalidDataException($"Ordinary console fixture exit {exit}, stderr bytes {stderr.Bytes.Length}");
            Refuse<InvalidDataException>(()=>Call(checkInitialThread,null,process,thread,native.Pid,native.Tid));
            Require(!stderr.Overflow && stderr.Bytes.AsSpan().SequenceEqual("fixture-stderr\n"u8));
            Require(mode switch {
                "flood"=>stdout.Overflow && stdout.Bytes.Length==4096 && stdout.Bytes.All(value=>value==65),
                "gpu"=>!stdout.Overflow && stdout.Bytes.Length==5185 && stdout.Bytes.All(value=>value==65),
                "gpu-flood"=>stdout.Overflow && stdout.Bytes.Length==8192 && stdout.Bytes.All(value=>value==65),
                _=>!stdout.Overflow && stdout.Bytes.AsSpan().SequenceEqual("fixture-stdout\n"u8)
            });
            Require(!excluded.WaitOne(0));
        }
        finally
        {
            if(WaitForSingleObject(process,0)==StillRunning)
            {
                if(!TerminateProcess(process,125) || WaitForSingleObject(process,3000)!=Success)
                    throw Error("StopExactOrdinaryFixture");
            }
        }
    }

    internal static int Worker(string mode,string eventValue)
    {
        if(mode is not ("normal" or "flood" or "gpu" or "gpu-flood") || !long.TryParse(eventValue,NumberStyles.None,CultureInfo.InvariantCulture,out var raw) ||
            raw<=0 || !Console.IsInputRedirected || !Console.IsOutputRedirected || !Console.IsErrorRedirected)return 120;
        using(var input=Console.OpenStandardInput())
            if(input.ReadByte()!=-1)return 121;
        if(SetEvent((IntPtr)raw) || Marshal.GetLastWin32Error()!=6)return 122;
        var child=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,CreateNoWindow=true};
        child.ArgumentList.Add("ordinary-console-fixture-inert");
        try{using var unexpected=Process.Start(child);return 123;}
        catch(Win32Exception error)when(error.NativeErrorCode==367){}
        using(var stdout=Console.OpenStandardOutput())
        {
            if(mode=="normal")stdout.Write("fixture-stdout\n"u8);
            else stdout.Write(Enumerable.Repeat((byte)65,mode switch {"gpu"=>5185,"gpu-flood"=>8193,_=>4097}).ToArray());
        }
        using(var stderr=Console.OpenStandardError())stderr.Write("fixture-stderr\n"u8);
        return 0;
    }

    private static (byte[] Bytes,bool Overflow) Result(Task task)
    {
        task.WaitAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();
        var value=task.GetType().GetProperty("Result")!.GetValue(task)!;
        return ((byte[])value.GetType().GetProperty("Bytes")!.GetValue(value)!,
            (bool)value.GetType().GetProperty("Overflow")!.GetValue(value)!);
    }
    private static void Require(bool value){if(!value)throw new InvalidDataException("Offline console native fixture differs");}
    private static void Refuse<T>(Action action) where T:Exception
    {try{action();}catch(T){return;}throw new InvalidDataException("Offline console refusal missing");}
    private static object? Call(MethodInfo method,object? target,params object?[] args)
    {
        try{return method.Invoke(target,args);}
        catch(TargetInvocationException ex)when(ex.InnerException is not null){ExceptionDispatchInfo.Capture(ex.InnerException).Throw();throw;}
    }
    private static Win32Exception Error(string stage)=>new(Marshal.GetLastWin32Error(),stage);

    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
    private struct Startup
    {
        internal int Size;
        internal string? Reserved,Desktop,Title;
        internal int X,Y,XSize,YSize,XCount,YCount,Fill;
        internal uint Flags;
        internal ushort Show,ReservedBytes;
        internal IntPtr ReservedPointer,Input,Output,Error;
    }
    [StructLayout(LayoutKind.Sequential)] private struct StartupEx {internal Startup Basic;internal IntPtr Attributes;}
    [StructLayout(LayoutKind.Sequential)] private struct ProcessInfo {internal IntPtr Process,Thread;internal uint Pid,Tid;}
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,int flags,ref nuint size);
    [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,
        IntPtr attribute,IntPtr value,nuint size,IntPtr previous,IntPtr returned);
    [DllImport("kernel32.dll",EntryPoint="CreateJobObjectW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern IntPtr CreateJobObject(IntPtr attributes,string? name);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool IsProcessInJob(SafeProcessHandle process,SafeHandle job,
        [MarshalAs(UnmanagedType.Bool)]out bool member);
    [DllImport("kernel32.dll",EntryPoint="CreateProcessW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern bool CreateProcess(string image,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,bool inherit,
        uint flags,IntPtr environment,string? cwd,ref StartupEx startup,out ProcessInfo info);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool SetHandleInformation(SafeWaitHandle handle,uint mask,uint flags);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool SetEvent(IntPtr handle);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint ResumeThread(SafeWaitHandle thread);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern uint WaitForSingleObject(SafeProcessHandle process,uint milliseconds);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetExitCodeProcess(SafeProcessHandle process,out uint code);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool TerminateProcess(SafeProcessHandle process,uint code);
    [DllImport("kernel32.dll",ExactSpelling=true)] private static extern IntPtr GetCurrentThread();
    [DllImport("kernel32.dll",ExactSpelling=true)] private static extern uint GetCurrentThreadId();
}
