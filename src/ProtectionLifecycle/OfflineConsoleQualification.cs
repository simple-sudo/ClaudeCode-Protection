using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Principal;
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

    internal static int RunChild()
    {
        AtomicChild.AssertOfflineConsoleWorkerIdentity();
        var session=Identifiers.Hex32(Environment.GetEnvironmentVariable(SessionVariable)??"");
        var workspace=SessionTaskWorkspace.PathFor(session);
        if(!string.Equals(Environment.CurrentDirectory,workspace,StringComparison.OrdinalIgnoreCase) ||
            new[]{"TEMP","TMP","LOCALAPPDATA","USERPROFILE","HOME","XDG_CONFIG_HOME","CLAUDE_CONFIG_DIR","APPDATA"}.Any(
                name=>Environment.GetEnvironmentVariable(name)!=workspace) ||
            new[]{"CPC_SESSION_ID","CPC_SESSION_SECRET","CPC_NETWORK_PLAN","CPC_RESOURCE_PLAN","CPC_GPU_PLAN",
                "HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","ANTHROPIC_API_KEY","CLAUDE_CODE_OAUTH_TOKEN"}.Any(
                name=>Environment.GetEnvironmentVariable(name) is not null))
            throw WfpNative.Contract("OfflineConsoleChildEnvironmentDiffers");
        if(!Console.IsInputRedirected || !Console.IsOutputRedirected || !Console.IsErrorRedirected)
            throw WfpNative.Contract("OfflineConsoleRedirectionMissing");
        using(var stdin=Console.OpenStandardInput())
            if(stdin.ReadByte()!=-1)throw WfpNative.Contract("OfflineConsoleInputMustBeEof");
        using(var file=new FileStream(WindowsPathSeal.Child(workspace,OutputLeaf),FileMode.CreateNew,FileAccess.Write,FileShare.None))
        {file.Write(ExpectedFile);file.Flush(true);}
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
        using(var stdout=Console.OpenStandardOutput())stdout.Write(ExpectedOutput);
        using(var stderr=Console.OpenStandardError())stderr.Write(ExpectedError);
        return 0;
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
        var report=JsonSerializer.Serialize(new {
            SchemaVersion=1,Scope="INSTALLED_FIXED_OFFLINE_CONSOLE",state.InstallationId,SessionId=id,JobId=jobId,
            version.Package.Release,version.Package.ManifestHash,Status=complete?"OFFLINE_CONSOLE_CLOSED":"OFFLINE_CONSOLE_NOT_CONFIRMED",
            ProcessResumed=resumed,ChildExit=exit,SingleProcessEverAdmitted=singleProcess,WorkspaceMatched=workspaceMatched,WorkspaceClosed=workspaceClosed,
            Output=Summarize(stdout),Error=Summarize(stderr),StreamsMatched=matched,OriginalOwnerClosed=closed,StopObservation=stopped,
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
