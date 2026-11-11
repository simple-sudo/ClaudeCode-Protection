using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionCenter;

internal sealed record BackendResult(int ExitCode, string Output, string Error);
internal static class BackendClient
{
    internal static string Root => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", ".."));
    internal static async Task<BackendResult> Command(params string[] arguments)
    {
        WorkspaceFiles.RequireOrdinaryUser();
        // Defense in depth: the GUI cannot dispatch engineering commands even
        // if a future caller accidentally wires one into a button.
        if (arguments.Length == 0 || arguments[0] is not ("audit" or "preflight" or "system-proxy-baseline" or "repair-proxy-plan" or "repair-proxy" or "restore-proxy"))
            throw new InvalidOperationException("此操作不属于日常检查与维护");
        return await Run(Path.Combine(Root, "bin", "current", "ClaudeProtection.exe"), arguments);
    }
    internal static void RequireInstalledProjectLocation(string root,string? image,string? assembly,string programFiles)
    {
        var release=Path.GetFileName(root);
        if(release.Length!=32 || release.Any(c=>c is not (>= '0' and <= '9' or >= 'a' and <= 'f')) ||
            !string.Equals(root,Path.Combine(programFiles,"ClaudeCodeProtection","versions",release),StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(image,Path.Combine(root,"bin","center","ProtectionCenter.exe"),StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(assembly,Path.Combine(root,"bin","center","ProtectionCenter.dll"),StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("请从已安装的保护中心发起项目任务。");
    }
    internal static void AssertProjectLocation()
    {
        WorkspaceFiles.RequireOrdinaryUser();
        RequireInstalledProjectLocation(Root,Environment.ProcessPath,System.Reflection.Assembly.GetEntryAssembly()?.Location,
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
    }
    // Separate typed entry: the maintenance dispatcher still cannot request
    // project execution, arbitrary Broker commands or a caller executable.
    internal static IDisposable HoldReviewedInput(string inputPath,string expectedSHA256)
    {
        WorkspaceFiles.RequireOrdinaryUser();
        if(!WorkspaceBundle.IsHash(expectedSHA256))throw new InvalidDataException("Reviewed input fingerprint required");
        var held=new WorkspaceFiles.HeldPaths();
        try
        {
            held.DirectoryChain(Path.GetDirectoryName(inputPath)??throw new InvalidDataException("Reviewed input parent required"));
            var input=held.ReadFile(inputPath);
            if(input.Length is <1 or >WorkspaceBundle.MaxBundleBytes || Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(input))!=expectedSHA256)
                throw new InvalidDataException("Reviewed project input changed");
            return held;
        }
        catch{held.Dispose();throw;}
    }
    internal static async Task<BackendResult> BuildCallerProject(string inputPath,string resultPath,string expectedSHA256,CancellationToken cancellation=default)
    {
        cancellation.ThrowIfCancellationRequested();
        AssertProjectLocation();using var held=new ClaudeProtection.WorkspaceInstalledHost(Root);
        using var reviewed=HoldReviewedInput(inputPath,expectedSHA256);
        var executable=Path.Combine(Root,"bin","current","ClaudeProtection.exe");
        var info=new ProcessStartInfo(executable){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=Root,
            RedirectStandardInput=true,StandardInputEncoding=new System.Text.UTF8Encoding(false),
            RedirectStandardOutput=true,RedirectStandardError=true,StandardOutputEncoding=System.Text.Encoding.UTF8,StandardErrorEncoding=System.Text.Encoding.UTF8};
        info.Environment.Clear();
        foreach(var name in new[]{"SystemRoot","windir","SystemDrive","TEMP","TMP","USERPROFILE","LOCALAPPDATA","APPDATA","ProgramFiles","ProgramFiles(x86)","ProgramW6432","PROCESSOR_ARCHITECTURE"})
            if(Environment.GetEnvironmentVariable(name) is string value)info.Environment[name]=value;
        info.Environment["PATH"]=@"C:\Program Files\dotnet;C:\Windows\System32;C:\Windows";
        info.Environment["DOTNET_ROOT"]=@"C:\Program Files\dotnet";info.Environment["DOTNET_ROLL_FORWARD"]="LatestPatch";
        info.ArgumentList.Add("workspace-build-csharp");info.ArgumentList.Add(inputPath);info.ArgumentList.Add(resultPath);
        info.ArgumentList.Add(WorkspaceStopControl.ClientFlag);
        cancellation.ThrowIfCancellationRequested();
        using var process=Process.Start(info)??throw new IOException("项目调用未能启动");
        return await WaitProjectClient(process,executable,cancellation,cooperativeStop:true);
    }
    // Only receives the process returned by the immediately preceding ordinary
    // Start. No PID lookup/tree stop or elevated-owner management is provided.
    // WaitHandle adapter that borrows the exact Process.Start handle without
    // transferring ownership. DangerousAddRef keeps it valid through the
    // registered wait; disposing this adapter never closes the process handle.
    private sealed class BorrowedProcessWaitHandle : WaitHandle
    {
        private readonly SafeProcessHandle owner;
        private bool ownerReference;
        internal BorrowedProcessWaitHandle(SafeProcessHandle owner)
        {
            this.owner=owner;
            owner.DangerousAddRef(ref ownerReference);
            try{SafeWaitHandle=new SafeWaitHandle(owner.DangerousGetHandle(),ownsHandle:false);}
            catch{if(ownerReference){ownerReference=false;owner.DangerousRelease();}throw;}
        }
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if(ownerReference){ownerReference=false;owner.DangerousRelease();}
        }
    }
    private static async Task WaitForProcessExitAsync(SafeProcessHandle process,CancellationToken cancellation)
    {
        using var waitHandle=new BorrowedProcessWaitHandle(process);
        var completion=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        RegisteredWaitHandle? registration=null;
        try
        {
            registration=ThreadPool.RegisterWaitForSingleObject(waitHandle,
                static (state,timedOut)=>{if(!timedOut)((TaskCompletionSource)state!).TrySetResult();},
                completion,Timeout.Infinite,executeOnlyOnce:true);
            using var cancellationRegistration=cancellation.Register(()=>completion.TrySetCanceled(cancellation));
            await completion.Task.ConfigureAwait(false);
        }
        finally{registration?.Unregister(null);}
    }
    private static bool WaitForProcessSignal(SafeProcessHandle process,uint milliseconds)
    {
        if(process.IsClosed || process.IsInvalid)throw new ObjectDisposedException(nameof(process));
        var result=WaitForSingleObject(process,milliseconds);
        if(result==0)return true;
        if(result==258)return false;
        throw new Win32Exception(Marshal.GetLastWin32Error(),"Wait for the original project-client handle");
    }
    private static long ProcessCreationFileTime(SafeProcessHandle process)
    {
        if(!GetProcessTimes(process,out var created,out _,out _,out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(),"Read original project-client creation time");
        return created;
    }
    private static string ProcessImagePath(SafeProcessHandle process)
    {
        var path=new StringBuilder(32768);uint length=(uint)path.Capacity;
        if(!QueryFullProcessImageName(process,0,path,ref length))
            throw new Win32Exception(Marshal.GetLastWin32Error(),"Read original project-client image path");
        return path.ToString();
    }
    private static int ReadSignaledExitCode(SafeProcessHandle process)
    {
        if(!WaitForProcessSignal(process,0))throw new InvalidOperationException("ProjectClientHandleNotSignaled");
        if(!GetExitCodeProcess(process,out var code))
            throw new Win32Exception(Marshal.GetLastWin32Error(),"Read signaled project-client exit code");
        return unchecked((int)code);
    }
    private static void TerminateOwnedProjectClient(SafeProcessHandle process)
    {
        if(!TerminateProcess(process,0xC000013A))
        {
            var error=Marshal.GetLastWin32Error();
            if(WaitForProcessSignal(process,250))return;
            throw new Win32Exception(error,"Terminate the original owned project client");
        }
        if(!WaitForProcessSignal(process,3000))
            throw new TimeoutException("Original owned project client did not signal after termination");
    }
    internal static async Task<BackendResult> WaitProjectClient(Process process,string executable,CancellationToken cancellation,bool cooperativeStop=false)
    {
        // Avoid Process.StartTime/ExitCode/HasExited/WaitForExitAsync/Kill.
        // .NET 8 ProcessManager initialization can adjust SeDebugPrivilege, and
        // exit code 259 is not a reliable liveness indicator.
        var processHandle=process.SafeHandle;
        var created=ProcessCreationFileTime(processHandle);
        using var signalLifetime=CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        async Task SendStop()
        {
            try{await Task.Delay(Timeout.Infinite,signalLifetime.Token);}
            catch(OperationCanceledException){}
            if(!cancellation.IsCancellationRequested)return;
            try
            {
                await process.StandardInput.BaseStream.WriteAsync(new[]{WorkspaceStopControl.Request}.AsMemory());
                await process.StandardInput.BaseStream.FlushAsync();
            }
            catch(Exception error)when(error is IOException or InvalidOperationException){}
        }
        var stopRequest=cooperativeStop?SendStop():Task.CompletedTask;
        var exitObserved=false;
        try
        {
            async Task<string> ReadBounded(StreamReader reader,int maximum)
            {
                var text=new StringBuilder();var buffer=new char[4096];
                while(true){var count=await reader.ReadAsync(buffer);if(count==0)return text.ToString();if(text.Length+count>maximum)throw new IOException("项目调用输出超出上限");text.Append(buffer,0,count);}
            }
            var output=ReadBounded(process.StandardOutput,65536);var error=ReadBounded(process.StandardError,16384);
            using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cooperativeStop?CancellationToken.None:cancellation);deadline.CancelAfter(TimeSpan.FromSeconds(180));
            var exited=WaitForProcessExitAsync(processHandle,deadline.Token);
            var first=await Task.WhenAny(exited,output,error);
            await first;
            if(first!=exited)
            {
                var remaining=first==output?error:output;
                var second=await Task.WhenAny(exited,remaining);
                await second;
            }
            await exited;
            exitObserved=true;
            if(!cooperativeStop)cancellation.ThrowIfCancellationRequested();
            var stdout=await output.WaitAsync(TimeSpan.FromSeconds(1));var stderr=await error.WaitAsync(TimeSpan.FromSeconds(1));
            return new(ReadSignaledExitCode(processHandle),stdout,stderr);
        }
        finally
        {
            signalLifetime.Cancel();
            await stopRequest;
            if(!exitObserved)exitObserved=WaitForProcessSignal(processHandle,250);
            if(!exitObserved)
            {
                bool identityMatches;
                try
                {
                    identityMatches=ProcessCreationFileTime(processHandle)==created &&
                        SameProjectClientImage(ProcessImagePath(processHandle),executable);
                }
                catch(Exception identityError)when(identityError is InvalidOperationException or Win32Exception)
                {
                    if(WaitForProcessSignal(processHandle,250))exitObserved=true;
                    else throw new IOException("普通调用身份无法核对，未结束任何进程。",identityError);
                    identityMatches=false;
                }
                if(!exitObserved && !identityMatches)
                    throw new IOException("普通调用身份无法核对，未结束任何进程。");
                if(!exitObserved)
                {
                    TerminateOwnedProjectClient(processHandle);
                    exitObserved=true;
                }
            }
        }
    }
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",SetLastError=true)]
    private static extern uint WaitForSingleObject(SafeProcessHandle process,uint milliseconds);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(SafeProcessHandle process,out long created,out long exited,out long kernel,out long user);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",EntryPoint="QueryFullProcessImageNameW",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(SafeProcessHandle process,uint flags,StringBuilder path,ref uint length);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(SafeProcessHandle process,out uint exitCode);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll",SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(SafeProcessHandle process,uint exitCode);
    internal static bool SameProjectClientImage(string? actual,string expected)
        =>actual is not null && Path.IsPathFullyQualified(actual) && Path.IsPathFullyQualified(expected) &&
            string.Equals(Path.GetFullPath(actual),Path.GetFullPath(expected),StringComparison.OrdinalIgnoreCase);
    internal static BackendResult CancelledProjectResult()=>new(130,JsonSerializer.Serialize(new {
        Status="PROJECT_OPERATION_CANCELLED",OwnerClosureConfirmed=false,ResultAutomaticallyExtracted=false,AutomaticRetry=false}),"");
    private static async Task<BackendResult> Run(string executable, IEnumerable<string> arguments)
    {
        var info = new ProcessStartInfo(executable)
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = System.Text.Encoding.UTF8, StandardErrorEncoding = System.Text.Encoding.UTF8,
            WorkingDirectory = Root
        };
        info.Environment.Remove("PSModulePath");
        foreach (var argument in arguments) info.ArgumentList.Add(argument);
        using var process = Process.Start(info) ?? throw new InvalidOperationException("检查程序未能启动");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        // Daily operations own their completion; engineering harnesses are excluded.
        await process.WaitForExitAsync();
        return new(process.ExitCode, await output, await error);
    }
    internal static string SaveReport(string name, BackendResult result, BackendResult? baseline = null)
    {
        if(name is not ("environment" or "config-repair" or "config-restore" or "project-build"))throw new InvalidDataException("Unknown report kind");
        var directory = ClaudeProtection.Storage.UserDataPaths.Reports;
        var file = Path.Combine(directory, name + "-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..6] + ".json");
        using(var stream=new FileStream(file,FileMode.CreateNew,FileAccess.Write,FileShare.Read))
        {JsonSerializer.Serialize(stream,new { atUtc = DateTimeOffset.UtcNow, result.ExitCode, result.Output, result.Error, baseline },new JsonSerializerOptions{WriteIndented=true});stream.Flush(true);}
        return file;
    }
}
