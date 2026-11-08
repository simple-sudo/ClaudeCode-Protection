using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace ProtectionLifecycle;

// This fixed Broker workload qualifies process creation and transport for the
// offline launcher. Its image cannot be supplied by the caller.
internal static class OfflineConsoleQualification
{
    internal const string ChildCommand="offline-console-qualification-child",SessionVariable="CPC_OFFLINE_CONSOLE_SESSION";
    private const string DescendantCommand="offline-console-denial-target",OutputLeaf="offline-console-output.txt";
    private static ReadOnlySpan<byte> ExpectedOutput=>"CPC_OFFLINE_CONSOLE_STDOUT\n"u8;
    private static ReadOnlySpan<byte> ExpectedError=>"CPC_OFFLINE_CONSOLE_STDERR\n"u8;
    private static ReadOnlySpan<byte> ExpectedFile=>"CPC_OFFLINE_CONSOLE_WORKSPACE\n"u8;
    private enum ChildStage
    {
        Identity, Environment, SessionId, ProgramFiles, WorkspacePath, CurrentDirectory, Temp, Tmp,
        LocalAppData, UserProfile, Home, XdgConfigHome, ClaudeConfigDir, AppData, UnexpectedAuthority,
        Streams, InputEof, Workspace, Descendant, Output
    }
    private static readonly (string Name,ChildStage Stage)[] WorkspaceVariables=[
        ("TEMP",ChildStage.Temp),("TMP",ChildStage.Tmp),("LOCALAPPDATA",ChildStage.LocalAppData),("USERPROFILE",ChildStage.UserProfile),
        ("HOME",ChildStage.Home),("XDG_CONFIG_HOME",ChildStage.XdgConfigHome),("CLAUDE_CONFIG_DIR",ChildStage.ClaudeConfigDir),
        ("APPDATA",ChildStage.AppData)
    ];
    private static readonly string[] ForbiddenVariables=[
        "CPC_SESSION_ID","CPC_SESSION_SECRET","CPC_NETWORK_PLAN","CPC_RESOURCE_PLAN","CPC_GPU_PLAN",
        "HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","ANTHROPIC_API_KEY","CLAUDE_CODE_OAUTH_TOKEN"
    ];
    private sealed record ChildFailure(string Stage,string Kind,int Code);

    internal static void BindEnvironment(IDictionary<string,string> environment,string workspace,string session)
    {
        var programFiles=Path.GetDirectoryName(workspace)??throw WfpNative.Contract("OfflineConsoleProgramFilesMissing");
        if(!string.Equals(workspace,SessionTaskWorkspace.PathFor(session,programFiles),StringComparison.OrdinalIgnoreCase) ||
            ForbiddenVariables.Any(environment.ContainsKey))throw WfpNative.Contract("OfflineConsoleParentEnvironmentDiffers");
        environment["ProgramFiles"]=programFiles;
        environment[SessionVariable]=session;
        foreach(var (name,_) in WorkspaceVariables)environment[name]=workspace;
    }

    internal static int RunChild()
    {
        var stage=ChildStage.Identity;
        try{return RunCheckedChild(ref stage);}
        catch(Exception error) when(error is not OutOfMemoryException)
        {
            var kind=error switch {
                Win32Exception=>"WIN32",WfpFailure=>"NATIVE",InvalidDataException=>"CONTRACT",
                UnauthorizedAccessException=>"ACCESS",IOException=>"IO",_=>"OTHER"
            };
            var code=error is Win32Exception win32?win32.NativeErrorCode:error.HResult;
            using var stderr=Console.OpenStandardError();
            stderr.Write(Encoding.ASCII.GetBytes(FormattableString.Invariant($"CPC_OFFLINE_CONSOLE_FAILURE|{stage}|{kind}|{code}\n")));
            return 125;
        }
    }

    private static int RunCheckedChild(ref ChildStage stage)
    {
        AtomicChild.AssertOfflineConsoleWorkerIdentity();
        stage=ChildStage.SessionId;
        var session=Identifiers.Hex32(Environment.GetEnvironmentVariable(SessionVariable)??"");
        // Use the canonical Program Files root chosen by the original owner.
        // The restricted process need not query the shell's known folders.
        stage=ChildStage.ProgramFiles;
        var programFiles=Environment.GetEnvironmentVariable("ProgramFiles")??throw WfpNative.Contract("OfflineConsoleProgramFilesMissing");
        stage=ChildStage.WorkspacePath;
        var workspace=SessionTaskWorkspace.PathFor(session,programFiles);
        stage=ChildStage.CurrentDirectory;
        if(FindEnvironmentMismatch(workspace,Environment.CurrentDirectory,Environment.GetEnvironmentVariable) is { } mismatch)
        {
            stage=mismatch;
            throw WfpNative.Contract("OfflineConsoleChildEnvironmentDiffers");
        }
        stage=ChildStage.Streams;
        if(!Console.IsInputRedirected || !Console.IsOutputRedirected || !Console.IsErrorRedirected)
            throw WfpNative.Contract("OfflineConsoleRedirectionMissing");
        stage=ChildStage.InputEof;
        using(var stdin=Console.OpenStandardInput())
            if(stdin.ReadByte()!=-1)throw WfpNative.Contract("OfflineConsoleInputMustBeEof");
        stage=ChildStage.Workspace;
        using(var file=new FileStream(WindowsPathSeal.Child(workspace,OutputLeaf),FileMode.CreateNew,FileAccess.Write,FileShare.None))
        {file.Write(ExpectedFile);file.Flush(true);}
        stage=ChildStage.Descendant;
        // This inert same-image invocation exists only as a negative control.
        // If the policy fails, the original owner stops its exact Job.
        var start=new ProcessStartInfo(Environment.ProcessPath??throw WfpNative.Contract("OfflineConsoleImageMissing")){
            UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=workspace
        };
        start.ArgumentList.Add(DescendantCommand);
        try
        {
            using var unexpected=Process.Start(start);
            throw WfpNative.Contract("OfflineConsoleDescendantNotBlocked");
        }
        catch(Win32Exception denied)when(denied.NativeErrorCode==367){}
        stage=ChildStage.Output;
        using(var stdout=Console.OpenStandardOutput())stdout.Write(ExpectedOutput);
        using(var stderr=Console.OpenStandardError())stderr.Write(ExpectedError);
        return 0;
    }

    private static ChildStage? FindEnvironmentMismatch(string workspace,string currentDirectory,Func<string,string?> get)
    {
        if(!string.Equals(currentDirectory,workspace,StringComparison.OrdinalIgnoreCase))return ChildStage.CurrentDirectory;
        foreach(var (name,stage) in WorkspaceVariables)
            if(!string.Equals(get(name),workspace,StringComparison.OrdinalIgnoreCase))return stage;
        return ForbiddenVariables.Any(name=>get(name) is not null)?ChildStage.UnexpectedAuthority:null;
    }

    internal static (int ExitCode,string Report) Run(FixedLayout layout,ProtectedState state,VerifiedVersion version)
    {
        state.AssertHeld();version.AssertHeld(state);LifecycleRecovery.AssertNoPending(state);
        InstallationLoopbackLease.AssertClosedHistory(state);
        foreach(var intent in OwnedJobIntent.ReadAll(state))
            if(AtomicJobCompletion.ReadClosed(state,intent) is null)
                throw WfpNative.Contract("OfflineConsoleRequiresPriorAdmissionsClosed");
        var plans=FencePlan.ReadAll(state);
        if(plans.Count==0)throw WfpNative.Contract("OfflineConsoleRequiresExistingQuarantine");

        var id=Guid.NewGuid().ToString("N");
        var fences=new List<PersistentFence>();
        var failures=new List<Exception>();
        string? jobId=null;
        uint? exit=null;
        bool resumed=false,singleProcess=false,workspaceMatched=false,workspaceClosed=false;
        RuntimeStop? stopped=null;
        OfflineConsoleOutput? stdout=null,stderr=null;
        try
        {
            foreach(var plan in plans)fences.Add(PersistentFence.OpenExisting(state,plan.Data.FenceId));
            AssertQuarantine();
            using(var profile=InstallationProfileLease.Create(state))
            using(var workspace=SessionResources.CreateOwnedTaskDirectory(state,profile,id))
            using(var streams=new OfflineConsoleStreams())
            {
                AssertWorkspace(workspace,state);
                using var job=OwnedKernelJob.CreateEmpty(state,version);
                jobId=job.JobId;
                AtomicChild? child=null;
                ProtectionRuntimeLease? runtime=null;
                (Task<OfflineConsoleOutput> Output,Task<OfflineConsoleOutput> Error)? capture=null;
                try
                {
                    child=AtomicChild.CreateOfflineConsoleQualification(layout,state,version,job,profile,id,workspace,streams);
                    capture=streams.ReadAfterCreate();
                    runtime=ProtectionRuntimeLease.ForFixedOfflineConsole(state,version,job,fences,child,id);
                    runtime.Activate(10000);
                    _=child.ResumeQuarantined();resumed=true;
                    do
                    {
                        runtime.AssertHealthy();
                        DemandCaptureWithinBound(capture.Value.Output);
                        DemandCaptureWithinBound(capture.Value.Error);
                        exit=child.ObserveOfflineConsoleExit();
                    }while(exit is null);
                    runtime.AssertHealthy();
                    if(exit!=0)throw WfpNative.Contract("OfflineConsoleChildExitDiffers");
                }
                catch(Exception error){failures.Add(error);}
                finally
                {
                    try
                    {
                        if(runtime is not null)
                        {
                            stopped=runtime.Stop(RuntimeStop.OfflineConsoleTerminalReason);
                            if(stopped.FinalJob is not null)profile.AfterOwnedJobZero(stopped.FinalJob);
                            if(!stopped.ConfirmsClosedOfflineConsole(id,job.JobId))
                                throw WfpNative.Contract("OfflineConsoleStopUnconfirmed");
                            job.AssertSingleProcessEverAdmitted();singleProcess=true;
                        }
                        else if(job.AtomicAdmissionReserved)
                        {
                            foreach(var fence in fences)
                                try{if(!fence.Observe().FullQuarantineObserved)_=fence.ReinstateQuarantine();}
                                catch(Exception error){failures.Add(error);}
                            var zero=job.CloseAtomicAdmissionAndStop();
                            if(profile.ProcessCreationAttempted)profile.AfterOwnedJobZero(zero);
                        }
                    }
                    catch(Exception error){failures.Add(error);}
                    child?.Dispose();
                }
                if(capture is { } readers)
                {
                    try{stdout=readers.Output.WaitAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();}
                    catch(Exception error){failures.Add(error);}
                    try{stderr=readers.Error.WaitAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult();}
                    catch(Exception error){failures.Add(error);}
                }
                if(singleProcess && exit==0)
                {
                    AssertWorkspace(workspace,state);
                    using var file=new FileStream(WindowsPathSeal.Open(WindowsPathSeal.Child(workspace.Path,OutputLeaf),false,true),FileAccess.Read);
                    var buffer=new byte[ExpectedFile.Length];
                    if(file.Length!=buffer.Length)throw WfpNative.Contract("OfflineConsoleWorkspaceOutputLengthDiffers");
                    file.ReadExactly(buffer);workspaceMatched=ExpectedFile.SequenceEqual(buffer);
                }
            }
            workspaceClosed=true;
        }
        catch(Exception error){failures.Add(error);}
        finally
        {
            try{AssertQuarantine();}catch(Exception error){failures.Add(error);}
            foreach(var fence in fences)try{fence.Dispose();}catch(Exception error){failures.Add(error);}
        }
        var matched=stdout is {Overflow:false} && stderr is {Overflow:false} &&
            ExpectedOutput.SequenceEqual(stdout.Bytes) && ExpectedError.SequenceEqual(stderr.Bytes);
        var closed=jobId is not null && stopped?.ConfirmsClosedOfflineConsole(id,jobId)==true;
        var complete=failures.Count==0 && closed && workspaceClosed && singleProcess && workspaceMatched && matched && exit==0 && resumed;
        var childFailure=ParseChildFailure(exit,stderr);
        var report=JsonSerializer.Serialize(new {
            SchemaVersion=1,Scope="INSTALLED_FIXED_OFFLINE_CONSOLE",state.InstallationId,SessionId=id,JobId=jobId,
            version.Package.Release,version.Package.ManifestHash,Status=complete?"OFFLINE_CONSOLE_CLOSED":"OFFLINE_CONSOLE_NOT_CONFIRMED",
            ProcessResumed=resumed,ChildExit=exit,SingleProcessEverAdmitted=singleProcess,WorkspaceMatched=workspaceMatched,WorkspaceClosed=workspaceClosed,
            Output=Summarize(stdout),Error=Summarize(stderr),ChildFailure=childFailure,StreamsMatched=matched,OriginalOwnerClosed=closed,StopObservation=stopped,
            Failures=failures.SelectMany(WfpNative.Describe).ToArray(),GatewayOpened=false,NetworkQualified=false,
            LaunchAuthorized=false,FormalAdmissionIssued=false,ClaudeLaunched=false
        });
        state.WriteNew("offline-console-after-"+id+".json",System.Text.Encoding.UTF8.GetBytes(report));
        return (complete?0:3,report);

        void AssertQuarantine()
        {
            if(fences.Count!=plans.Count || fences.Any(f=>!f.Observe().FullQuarantineObserved))
                throw WfpNative.Contract("OfflineConsoleFullQuarantineRequired");
        }
    }

    private static ChildFailure? ParseChildFailure(uint? exit,OfflineConsoleOutput? output)
    {
        if(exit!=125 || output is not {Overflow:false,Bytes.Length:>0 and <=96} ||
            output.Bytes[^1]!=(byte)'\n')return null;
        var parts=Encoding.ASCII.GetString(output.Bytes.AsSpan(0,output.Bytes.Length-1)).Split('|');
        if(parts is not ["CPC_OFFLINE_CONSOLE_FAILURE",var name,var kind,var number] ||
            !Enum.TryParse<ChildStage>(name,out var stage) || stage.ToString()!=name ||
            kind is not ("WIN32" or "NATIVE" or "CONTRACT" or "ACCESS" or "IO" or "OTHER") ||
            !int.TryParse(number,NumberStyles.AllowLeadingSign,CultureInfo.InvariantCulture,out var code) ||
            number!=code.ToString(CultureInfo.InvariantCulture))return null;
        return new(name,kind,code);
    }

    private static object? Summarize(OfflineConsoleOutput? output)=>output is null?null:new {
        Length=output.Bytes.Length,output.Overflow,SHA256=Convert.ToHexString(SHA256.HashData(output.Bytes))
    };
    private static void DemandCaptureWithinBound(Task<OfflineConsoleOutput> pending)
    {
        if(pending.IsCompleted && pending.GetAwaiter().GetResult().Overflow)
            throw WfpNative.Contract("OfflineConsoleOutputLimit");
    }
    private static void AssertWorkspace(PathLease workspace,ProtectedState state)
    {
        workspace.AssertHeld();
        using var user=WindowsIdentity.GetCurrent();
        using var package=new InstallationPackageSid(state);
        using var handle=WindowsPathSeal.Open(workspace.Path,true,false);
        if(WindowsPathSeal.Identity(handle)!=workspace.ObjectIdentity())throw WfpNative.Contract("OfflineConsoleWorkspaceReplaced");
        SessionResources.AssertMutableWorkspace(handle,user.User?.Value??throw WfpNative.Contract("WorkspaceHumanOwnerMissing"),package.Value);
    }
}
