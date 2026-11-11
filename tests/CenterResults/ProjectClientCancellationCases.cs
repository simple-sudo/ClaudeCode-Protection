using System.Diagnostics;
using System.IO.Pipes;
using System.Reflection;
using System.Text.Json;
using ClaudeCodeProtection.Workspaces;
using ProtectionCenter;

internal static class ProjectClientCancellationCases
{
    internal static async Task<int> RunCooperative()
    {
        var host=@"C:\Program Files\dotnet\dotnet.exe";
        var start=new ProcessStartInfo(host){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=AppContext.BaseDirectory,
            RedirectStandardInput=true,StandardInputEncoding=new System.Text.UTF8Encoding(false),RedirectStandardOutput=true,RedirectStandardError=true};
        start.Environment.Clear();
        foreach(var name in new[]{"SystemRoot","windir","SystemDrive","TEMP","TMP"})
            if(Environment.GetEnvironmentVariable(name) is string value)start.Environment[name]=value;
        foreach(var argument in new[]{"exec","--fx-version","8.0.28",Assembly.GetExecutingAssembly().Location,"--own-project-client","cooperative-stop"})
            start.ArgumentList.Add(argument);
        using var child=Process.Start(start)??throw new IOException("Ordinary stop fixture did not start");
        try
        {
            if(await child.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5))!="OWN_CLIENT_READY")
                throw new IOException("Ordinary stop fixture not ready");
            using var cancel=new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
            var result=await BackendClient.WaitProjectClient(child,host,cancel.Token,cooperativeStop:true).WaitAsync(TimeSpan.FromSeconds(8));
            if(!cancel.IsCancellationRequested || result.ExitCode!=3 || result.Output.Trim()!="OWN_CLIENT_STOP_RECEIPT" || result.Error.Length!=0)
                throw new InvalidDataException("Cooperative stop discarded the client's terminal receipt");
        }
        finally
        {
            if(!child.WaitForExit(0)){child.StandardInput.Close();if(!child.WaitForExit(5000))throw new IOException("Ordinary stop fixture not terminal");}
        }
        var pipeName="CpcProjectStopTest-"+Guid.NewGuid().ToString("N");
        using var server=new NamedPipeServerStream(pipeName,PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous|PipeOptions.CurrentUserOnly);
        using var client=new NamedPipeClientStream(".",pipeName,PipeDirection.InOut,PipeOptions.Asynchronous);
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await Task.WhenAll(server.WaitForConnectionAsync(deadline.Token),client.ConnectAsync(deadline.Token));
        using var pendingCancellation=new CancellationTokenSource();
        var idle=WorkspaceStopControl.ReadRequest(client,pendingCancellation.Token);
        pendingCancellation.Cancel();
        try{await idle.WaitAsync(deadline.Token);throw new InvalidDataException("Idle read did not cancel");}
        catch(OperationCanceledException)when(idle.IsCanceled){}
        // Normal completion still has a writable channel after draining the
        // unused read. A new read accepts only the fixed byte.
        var response=new byte[1];
        var receiveReply=server.ReadExactlyAsync(response,deadline.Token);
        await client.WriteAsync(new byte[]{0x53},deadline.Token);
        await receiveReply;
        if(response[0]!=0x53)throw new InvalidDataException("Reply channel changed after cancellation");
        var receiveStop=WorkspaceStopControl.ReadRequest(client,deadline.Token);
        await server.WriteAsync(new[]{WorkspaceStopControl.Request},deadline.Token);
        if(!await receiveStop)throw new InvalidDataException("Fixed stop byte rejected");
        var receiveInvalid=WorkspaceStopControl.ReadRequest(client,deadline.Token);
        await server.WriteAsync(new byte[]{0x01},deadline.Token);
        try{await receiveInvalid;}
        catch(InvalidDataException){return 4;}
        throw new InvalidDataException("Unknown control byte accepted");
    }
    internal static async Task<int> Run()
    {
        var checks=0;
        void Require(bool condition,string reason){if(!condition)throw new InvalidDataException(reason);checks++;}
        var originalHost=@"C:\Program Files\dotnet\dotnet.exe";
        Require(BackendClient.SameProjectClientImage(originalHost,originalHost.Replace('\\','/')),"mixed fixed image separators normalize");
        Require(BackendClient.SameProjectClientImage(originalHost.ToUpperInvariant(),originalHost),"Windows image case is canonical");
        Require(!BackendClient.SameProjectClientImage(originalHost+".other",originalHost) && !BackendClient.SameProjectClientImage("dotnet.exe",originalHost) && !BackendClient.SameProjectClientImage(null,originalHost),"relative/foreign/missing image cannot authorize stop");
        using(var cancelled=new CancellationTokenSource())
        {
            cancelled.Cancel();var refused=false;
            try{await BackendClient.BuildCallerProject("unused","unused","unused",cancelled.Token);}catch(OperationCanceledException){refused=true;}
            Require(refused,"pre-cancelled request refuses before installation lookup or launch");
        }
        Process Start(string mode)
        {
            var info=new ProcessStartInfo(originalHost){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=AppContext.BaseDirectory,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
            info.Environment.Clear();foreach(var name in new[]{"SystemRoot","windir","SystemDrive","TEMP","TMP"})if(Environment.GetEnvironmentVariable(name) is string value)info.Environment[name]=value;
            foreach(var arg in new[]{"exec","--fx-version","8.0.28",Assembly.GetExecutingAssembly().Location,"--own-project-client",mode})info.ArgumentList.Add(arg);
            return Process.Start(info)??throw new IOException("Own ordinary child not created");
        }
        using(var complete=Start("complete"))
        {
            var result=await BackendClient.WaitProjectClient(complete,originalHost,CancellationToken.None);
            Require(complete.WaitForExit(0) && result.ExitCode==259 && result.Output.Trim()=="OWN_CLIENT_COMPLETE" && result.Error.Length==0,"signaled process handle preserves natural exit259 and output without cancellation");
        }
        using(var excessive=Start("overflow"))
        {
            try
            {
                using var limit=new CancellationTokenSource(TimeSpan.FromSeconds(10));
                var rejected=false;
                try{await BackendClient.WaitProjectClient(excessive,originalHost,limit.Token);}
                catch(IOException error)when(error.Message=="项目调用输出超出上限"){rejected=true;}
                Require(rejected && excessive.WaitForExit(0),"overflow stops the held own client before its exit deadline");
            }
            finally{if(!excessive.WaitForExit(0)){excessive.StandardInput.Close();if(!excessive.WaitForExit(5000))throw new IOException("Own child not terminal; retained for exact observation");}}
        }
        using(var owned=Start("wait"))
        {
            try
            {
                Require(await owned.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5))=="OWN_CLIENT_READY","only this newly started ordinary child is ready");
                using var cancel=new CancellationTokenSource(TimeSpan.FromMilliseconds(100));var cancelled=false;
                try{await BackendClient.WaitProjectClient(owned,originalHost.Replace('\\','/'),cancel.Token);}catch(OperationCanceledException)when(cancel.IsCancellationRequested){cancelled=true;}
                Require(cancelled && owned.WaitForExit(0),"requested cancellation ends the held own ordinary client with canonical image binding");
            }
            finally{if(!owned.WaitForExit(0)){owned.StandardInput.Close();if(!owned.WaitForExit(5000))throw new IOException("Own child not terminal; retained for exact observation");}}
        }
        using(var refused=Start("wait"))
        {
            try
            {
                Require(await refused.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5))=="OWN_CLIENT_READY","foreign-image refusal fixture ready");
                using var cancel=new CancellationTokenSource();cancel.Cancel();var denied=false;
                try{await BackendClient.WaitProjectClient(refused,originalHost+".other",cancel.Token);}catch(IOException error)when(error.Message=="普通调用身份无法核对，未结束任何进程。"){denied=true;}
                Require(denied && !refused.WaitForExit(0),"wrong image refuses stop and does not terminate even this own child");
                refused.StandardInput.WriteLine("finish");refused.StandardInput.Close();
                Require(refused.WaitForExit(5000) && refused.ExitCode==0,"refused child exits only through own fixed stdin completion");
            }
            finally{if(!refused.WaitForExit(0)){refused.StandardInput.Close();if(!refused.WaitForExit(5000))throw new IOException("Own child not terminal; retained for exact observation");}}
        }
        var cancellationReport=BackendClient.CancelledProjectResult();using var json=JsonDocument.Parse(cancellationReport.Output);
        Require(cancellationReport.ExitCode==130 && !json.RootElement.GetProperty("OwnerClosureConfirmed").GetBoolean() && !json.RootElement.GetProperty("ResultAutomaticallyExtracted").GetBoolean() && !json.RootElement.GetProperty("AutomaticRetry").GetBoolean(),"cancellation metadata never grants closure, extraction, retry or success");
        return checks;
    }
}
