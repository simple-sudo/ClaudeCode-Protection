using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ProtectionLifecycle;

internal static class ResourceChildRunner
{
    internal static string ToolPath=>SessionPowerShellToolchain.ToolFor(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
    internal static SafeFileHandle OpenExecutableForProbe(string path)=>CreateFile(path,0xa0000000,1,IntPtr.Zero,3,0x80,IntPtr.Zero);
    internal static int RunChild(string packageSid)
    {
        var raw=Environment.GetEnvironmentVariable("CPC_RESOURCE_PLAN");if(raw is null || raw.Length>1024)throw WfpNative.Contract("ResourcePlanBoundsRefused");
        var plan=ResourceProbePlan.Parse(raw);
        using var sid=InstallationPackageSid.FromInstallationId(plan.InstallationId);
        if(sid.Value!=packageSid || Environment.GetEnvironmentVariable("CPC_NETWORK_PLAN") is not null ||
            Environment.GetEnvironmentVariable("CPC_GPU_PLAN") is not null || Environment.GetEnvironmentVariable("CPC_SESSION_ID") is not null ||
            !string.Equals(Environment.ProcessPath,plan.ExpectedChildImage,StringComparison.OrdinalIgnoreCase))throw WfpNative.Contract("ResourceChildPlanIdentityMismatch");
        var workspace=plan.Workspace(packageSid);var cases=new List<ResourceAccessCase>();bool matched=false,compiled=false;int? toolExit=null;string? failure=null;
        string stage="READ_WORKSPACE_INPUT";int? failureCode=null;string? failureStage=null;string? toolDiagnostic=null;GitToolchainReport? gitReport=null;ToolCreationEvidence? creationEvidence=null;ProjectTaskFailure? projectFailure=null;
        try
        {
            // The trusted owner holds and checks this complete ancestry and
            // input object. File-system/volume security metadata queries are
            // management work; the restricted tool needs ordinary file I/O.
            // The owner independently verifies both actual output identities.
            var input=ReadSmall(WindowsPathSeal.Child(workspace,"input.txt"));
            if(!input.AsSpan().SequenceEqual(plan.Input))throw WfpNative.Contract("ResourceInputMismatch");
            var result=WindowsPathSeal.Child(workspace,"root-output.txt");
            stage="WRITE_AND_READ_WORKSPACE_OUTPUT";
            using(var output=new FileStream(result,FileMode.CreateNew,FileAccess.Write,FileShare.None)){output.Write(input);output.Flush(true);}
            matched=ReadSmall(result).AsSpan().SequenceEqual(input);
            stage="DENY_PRIVATE_STATE_AND_BROKER_HANDLE";
            foreach(var access in new[]{FileAccess.Read,FileAccess.Write})
            {
                try{using var opened=new FileStream(plan.Fixture,FileMode.Open,access,FileShare.ReadWrite);cases.Add(new("private-state-"+access,"OPENED",null));}
                catch(UnauthorizedAccessException){cases.Add(new("private-state-"+access,"ACCESS_DENIED",5));}
                catch(Exception ex){cases.Add(new("private-state-"+access,"UNKNOWN",ex.HResult));}
            }
            try{using var opened=File.OpenRead(WindowsPathSeal.Child(workspace,"all-packages-only.json"));cases.Add(new("all-packages-only-Read","OPENED",null));}
            catch(UnauthorizedAccessException){cases.Add(new("all-packages-only-Read","ACCESS_DENIED",5));}
            catch(Exception ex){cases.Add(new("all-packages-only-Read","UNKNOWN",ex.HResult));}
            using(var broker=OpenProcess(0x10,false,checked((uint)plan.BrokerPid)))
            {
                var error=Marshal.GetLastWin32Error();cases.Add(new("broker-vm-read-open",!broker.IsInvalid?"OPENED":error==5?"ACCESS_DENIED":"UNKNOWN",broker.IsInvalid?error:null));
            }
            var etwQuery=SessionEtwProviderAccess.RestrictedQueryCode();
            cases.Add(new("etw-provider-security-query",etwQuery==5?"ACCESS_DENIED":"QUERY_NOT_DENIED",unchecked((int)etwQuery)));
            // The fixed OS tool executes no user profile, module, supplied
            // script or network request. It uses the same workspace and must
            // independently fail to read the protected non-secret fixture.
            // Readiness is coordination, not evidence of identity. The owner
            // verifies held process handles/tokens/Job before releasing this
            // compiled script. Planned startup/exit need not be atomic Job
            // membership snapshots; all traffic remains quarantined.
            stage="VERIFY_FIXED_TOOL_BYTES";
            using(var tool=File.OpenRead(plan.PowerShellLaunchImage))
                if(Convert.ToHexString(SHA256.HashData(tool))!=plan.ToolSHA256)throw WfpNative.Contract("FixedToolBytesChanged");
            if(plan.DevelopProject)
            {
                stage="DENY_NAMED_HOST_RESOURCES";
                if(!HostPrivacyProbe.RunRestricted(plan,workspace,"root"))throw WfpNative.Contract("NamedHostResourceReadOpenNotDenied");
                stage="PROJECT_GIT_BASELINE";gitReport=SessionGitToolchain.RunChild(plan,workspace);
                if(!SessionGitToolchain.QualifiedForPlan(plan,gitReport))throw WfpNative.Contract("FixedGitToolchainNotQualified");
                stage="START_FIXED_PRIVACY_PROBE";
                using(var probe=AtomicChild.StartInheritedTool(BundledProjectDevelopment.ProbeStart(plan,workspace)))
                {
                    probe.StandardInput.Close();var probeOut=new ToolOutputCapture(probe.StandardOutput);var probeError=new ToolOutputCapture(probe.StandardError);
                    stage="WAIT_FIXED_PRIVACY_PROBE";
                    if(!probe.WaitForExit(10000))throw new TimeoutException("Fixed privacy probe deadline");
                    if(probe.ExitCode!=0 || probeOut.Completion.WaitAsync(TimeSpan.FromSeconds(1)).GetAwaiter().GetResult().Length!=0 ||
                        probeError.Completion.WaitAsync(TimeSpan.FromSeconds(1)).GetAwaiter().GetResult().Length!=0)
                        throw WfpNative.Contract("FixedPrivacyProbeNotConfirmed");
                }
                stage="START_PROJECT_COMPILER";
                using var project=AtomicChild.StartInheritedTool(BundledProjectDevelopment.Start(plan,workspace));creationEvidence=project.CreationEvidence;project.StandardInput.Close();
                var output=new ToolOutputCapture(project.StandardOutput);var errors=new ToolOutputCapture(project.StandardError);
                stage="WAIT_PROJECT_COMPILER";
                if(!project.WaitForExit(10000))throw new TimeoutException("Fixed development task deadline");
                toolExit=project.ExitCode;var stdout=output.Completion.WaitAsync(TimeSpan.FromSeconds(1)).GetAwaiter().GetResult();var stderr=errors.Completion.WaitAsync(TimeSpan.FromSeconds(1)).GetAwaiter().GetResult();
                if(toolExit!=0 || stdout.Length!=0 || stderr.Length!=0)
                {
                    if(toolExit!=0 && plan.CallerProjectKind is not null)
                        projectFailure=ProjectFailureContract.ReadToolError(stdout,stderr,CSharpProjectTask.Parse(plan.ProjectBundle).Definition.Sources.Length);
                    toolDiagnostic=ToolOutputCapture.Classify(stdout,stderr);SaveToolFailure(workspace,stdout,stderr,"EXITED_UNEXPECTED_OUTPUT");throw WfpNative.Contract("ProjectDevelopmentNotConfirmed");
                }
                compiled=true;
            }
            if(plan.RequiresPowerShell)
            {
                var start=PowerShellStart(plan,workspace);
                stage="START_FIXED_POWERSHELL";
                using var process=AtomicChild.StartInheritedTool(start);creationEvidence=process.CreationEvidence;process.StandardInput.Close();
                var outputCapture=new ToolOutputCapture(process.StandardOutput);var errorCapture=new ToolOutputCapture(process.StandardError);
                var stdout=outputCapture.Completion;var stderr=errorCapture.Completion;
                stage="WAIT_FIXED_POWERSHELL";
                if(!process.WaitForExit(10000))
                {
                    var partialOut=outputCapture.Snapshot();var partialError=errorCapture.Snapshot();
                    toolDiagnostic=ToolOutputCapture.Classify(partialOut,partialError);
                    SaveToolFailure(workspace,partialOut,partialError,"TIMEOUT_PARTIAL_PIPE_SNAPSHOT");
                    throw new TimeoutException("Fixed offline tool deadline");
                }
                toolExit=process.ExitCode;
                var toolOut=stdout.WaitAsync(TimeSpan.FromSeconds(1)).GetAwaiter().GetResult();
                var toolError=stderr.WaitAsync(TimeSpan.FromSeconds(1)).GetAwaiter().GetResult();
                if(toolOut.Length!=0 || toolError.Length!=0)
                {
                    var diagnostic=toolError.Trim();
                    toolDiagnostic=System.Text.RegularExpressions.Regex.IsMatch(diagnostic,
                        @"\ACPC_TOOL_FAILURE\|(READY|WAIT_OWNER|READ_OWNER_GATE|WORKSPACE_IO|DENY_PRIVATE_FIXTURE|COMPILE_OWNED_SAMPLE)\|[A-Za-z0-9.]{1,80}\|-?[0-9]{1,12}\z")?
                        diagnostic:ToolOutputCapture.Classify(toolOut,toolError);
                    SaveToolFailure(workspace,toolOut,toolError,"EXITED_UNEXPECTED_OUTPUT");
                    throw WfpNative.Contract("FixedToolUnexpectedOutput");
                }
                stage="VERIFY_OWNED_COMPILATION_RESULT";
                if(toolExit!=0 || !ReadSmall(WindowsPathSeal.Child(workspace,"owned-build-result.txt")).AsSpan().SequenceEqual("12"u8))
                    throw WfpNative.Contract("OwnedCompilationResultNotConfirmed");
                compiled=true;
            }
            if(plan.GitAssetSetSHA256 is not null && !plan.DevelopProject)
            {stage="FIXED_OFFLINE_GIT_TOOLCHAIN";gitReport=SessionGitToolchain.RunChild(plan,workspace);if(!SessionGitToolchain.Qualified(gitReport))throw WfpNative.Contract("FixedGitToolchainNotQualified");}
        }
        catch(Exception ex)
        {
            failure=ex.GetType().Name;failureCode=ex is System.ComponentModel.Win32Exception native?native.NativeErrorCode:ex.HResult;
            if(ex.Data["ToolCreationEvidence"] is ToolCreationEvidence observedCreation)creationEvidence=observedCreation;
            if(stage=="START_FIXED_POWERSHELL" && ex is System.ComponentModel.Win32Exception)
            {
                // Process.Start can fail while creating/duplicating redirected
                // pipes BEFORE CreateProcess. Keep only known framework method
                // labels; no raw stack, path, arguments or exception message.
                stage+="/"+ToolStartFailurePhase(ex);
            }
            failureStage=stage+(ex.Data["Stage"] is string nativeStage?"/"+nativeStage:"");
        }
        var report=new ResourceChildReport(1,Environment.ProcessId,plan.Nonce,matched,toolExit,cases.ToArray(),failure,failureCode,failureStage,toolDiagnostic,gitReport,creationEvidence,compiled,projectFailure);
        Console.WriteLine(JsonSerializer.Serialize(report));return Qualified(report,plan.RequiresCompilerTool)?0:3;
    }
    internal static ProcessStartInfo PowerShellStart(ResourceProbePlan plan,string workspace)
    {
            if(!plan.RequiresPowerShell)throw WfpNative.Contract("WorkspaceDataCannotRequestPowerShell");
            const string script="$ErrorActionPreference='Stop';$stage='READY';try{[IO.File]::WriteAllText('tool-ready.txt',$env:CPC_RESOURCE_NONCE);[IO.File]::WriteAllText('tool-ready.signal','');$stage='WAIT_OWNER';$until=[DateTime]::UtcNow.AddSeconds(8);while(![IO.File]::Exists('tool-go.signal')){if([DateTime]::UtcNow -ge $until){exit 24};[Threading.Thread]::Sleep(20)};$stage='READ_OWNER_GATE';if([IO.File]::ReadAllText('tool-go.txt') -cne $env:CPC_RESOURCE_NONCE){exit 25};$stage='WORKSPACE_IO';$v=[IO.File]::ReadAllText('input.txt');[IO.File]::WriteAllText('tool-output.txt',$v);$stage='COMPILE_OWNED_SAMPLE';[void][Reflection.Assembly]::LoadFrom([IO.Path]::Combine($PSHOME,'Microsoft.CodeAnalysis.dll'));[void][Reflection.Assembly]::LoadFrom([IO.Path]::Combine($PSHOME,'Microsoft.CodeAnalysis.CSharp.dll'));$tree=[Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree]::ParseText('public static class CpcOwnedBuildProbe{public static int Sum(int a,int b){return checked(a+b);}}');$refs=[Collections.Generic.List[Microsoft.CodeAnalysis.MetadataReference]]::new();foreach($reference in [IO.Directory]::GetFiles([IO.Path]::Combine($PSHOME,'ref'),'*.dll')){$refs.Add([Microsoft.CodeAnalysis.MetadataReference]::CreateFromFile($reference))};$options=[Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions]::new([Microsoft.CodeAnalysis.OutputKind]::DynamicallyLinkedLibrary);$compilation=[Microsoft.CodeAnalysis.CSharp.CSharpCompilation]::Create('CpcOwnedBuildProbe',[Microsoft.CodeAnalysis.SyntaxTree[]]@($tree),$refs.ToArray(),$options);$output=[IO.File]::Create('owned-build.dll');try{$emitted=$compilation.Emit($output)}finally{$output.Dispose()};if(!$emitted.Success){exit 28};Add-Type -Path ([IO.Path]::GetFullPath('owned-build.dll')) -ErrorAction Stop;if([CpcOwnedBuildProbe]::Sum(7,5) -ne 12){exit 27};[IO.File]::WriteAllText('owned-build-result.txt','12');$stage='DENY_PRIVATE_FIXTURE';foreach($fixture in @($env:CPC_DENIAL_FIXTURE,$env:CPC_LPAC_FIXTURE)){$denied=$false;try{$f=[IO.File]::OpenRead($fixture);$f.Dispose()}catch{if($_.Exception -is [UnauthorizedAccessException] -or $_.Exception.InnerException -is [UnauthorizedAccessException]){$denied=$true}else{exit 22}};if(!$denied){exit 23}};exit 0}catch{$e=$_.Exception.GetBaseException();[Console]::Error.WriteLine('CPC_TOOL_FAILURE|'+$stage+'|'+$e.GetType().Name+'|'+$e.HResult);exit 26}";
            var start=new ProcessStartInfo(plan.PowerShellLaunchImage){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=workspace,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
            start.Environment.Clear();
            foreach(var name in new[]{"SystemRoot","windir","SystemDrive","PROCESSOR_ARCHITECTURE"})
            {var value=Environment.GetEnvironmentVariable(name);if(value is not null)start.Environment[name]=value;}
            foreach(var name in new[]{"TEMP","TMP","LOCALAPPDATA","USERPROFILE"})start.Environment[name]=workspace;
            start.Environment["PATH"]=Environment.SystemDirectory;
            start.Environment["PSModulePath"]=WindowsPathSeal.Child(plan.PowerShellDirectory,"Modules");
            start.Environment["POWERSHELL_TELEMETRY_OPTOUT"]="1";
            start.Environment["POWERSHELL_UPDATECHECK"]="Off";
            start.Environment["PSModuleAnalysisCachePath"]=WindowsPathSeal.Child(workspace,"powershell-analysis-cache");
            start.Environment["DOTNET_ROOT"]=WindowsPathSeal.Child(plan.ProgramFilesRoot,"dotnet");
            start.Environment["CPC_DENIAL_FIXTURE"]=plan.Fixture;
            start.Environment["CPC_LPAC_FIXTURE"]=WindowsPathSeal.Child(workspace,"all-packages-only.json");
            start.Environment["CPC_RESOURCE_NONCE"]=plan.Nonce;
            start.Environment["CPC_RESOURCE_PLAN"]=JsonSerializer.Serialize(plan);
            start.Environment["CPC_POWERSHELL_POLICY_NONCE"]=plan.Nonce;
            start.ArgumentList.Add("resource-powershell");
            foreach(var arg in new[]{"-NoLogo","-NoProfile","-NonInteractive","-Command",script})start.ArgumentList.Add(arg);
        return start;
    }
    private static string ToolStartFailurePhase(Exception error)
    {
        if(error.Data["Stage"] is string native)
        {
            if(native is "InheritedToolCreateProcess" or "OwnedToolCreateProcess")return "CREATE_PROCESS";
            if(native is "InheritedToolInputPipe" or "InheritedToolOutputPipe" or "InheritedToolErrorPipe")return "CREATE_REDIRECT_PIPE";
            if(native=="InheritedToolParentHandleSeal")return "DUPLICATE_REDIRECT_HANDLE";
        }
        var methods=new StackTrace(error,false).GetFrames()?.Select(f=>f.GetMethod()).Where(m=>m?.DeclaringType==typeof(Process)).Select(m=>m!.Name).ToArray()??Array.Empty<string>();
        return methods.Contains("CreatePipeWithSecurityAttributes")?"CREATE_REDIRECT_PIPE":methods.Contains("CreatePipe")?"DUPLICATE_REDIRECT_HANDLE":
            methods.Contains("StartWithCreateProcess")?"CREATE_PROCESS":"START_UNCLASSIFIED";
    }
    internal static bool Qualified(ResourceChildReport report,bool requirePowerShell=true)=>report.SchemaVersion==1 && report.WorkspaceWriteReadMatched &&
        (requirePowerShell?report.ToolExit==0 && report.OwnedCompilationObserved:report.ToolExit is null && !report.OwnedCompilationObserved && report.Git is not null) &&
        report.FailureType is null && report.FailureCode is null && report.FailureStage is null && report.ToolDiagnostic is null && report.ProjectFailure is null &&
        (report.Git is null || SessionGitToolchain.Qualified(report.Git)) && report.Cases.Length==5 && report.Cases.Select(c=>c.Role).SequenceEqual(new[]{"private-state-Read","private-state-Write","all-packages-only-Read","broker-vm-read-open","etw-provider-security-query"}) &&
        report.Cases.All(c=>c.Status=="ACCESS_DENIED" && c.Error==5);
    private static void SaveToolFailure(string workspace,string stdout,string stderr,string status)
    {
        if(stdout.Length>4096 || stderr.Length>4096)throw WfpNative.Contract("ToolFailureSnapshotBounds");
        var bytes=JsonSerializer.SerializeToUtf8Bytes(new{SchemaVersion=1,Status=status,Stdout=stdout[..Math.Min(stdout.Length,2048)],
            Stderr=stderr[..Math.Min(stderr.Length,2048)],Truncated=stdout.Length>2048 || stderr.Length>2048});
        using var file=new FileStream(WindowsPathSeal.Child(workspace,"tool-last-result.json"),FileMode.CreateNew,FileAccess.Write,FileShare.None);
        file.Write(bytes);file.Flush(true);
    }
    internal static async Task<string> ReadBounded(StreamReader reader)
    {
        var data=new char[4097];var total=0;
        while(total<data.Length){var count=await reader.ReadAsync(data.AsMemory(total));if(count==0)return new string(data,0,total);total+=count;}
        throw WfpNative.Contract("ResourceReportTooLarge");
    }
    private static byte[] ReadSmall(string path)
    {
        using var file=File.OpenRead(path);if(file.Length is <1 or >1024)throw WfpNative.Contract("ResourceFixtureBounds");
        var data=new byte[checked((int)file.Length)];file.ReadExactly(data);return data;
    }

    [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr attributes,uint disposition,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern SafeProcessHandle OpenProcess(uint access,[MarshalAs(UnmanagedType.Bool)] bool inherit,uint pid);
}
