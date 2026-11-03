using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using ProtectionCenter;

internal static class ProjectClientCancellationCases
{
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
            Require(result.ExitCode==259 && result.Output.Trim()=="OWN_CLIENT_COMPLETE" && result.Error.Length==0,"natural exit259 and output preserved without cancellation");
        }
        using(var owned=Start("wait"))
        {
            try
            {
                Require(await owned.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5))=="OWN_CLIENT_READY","only this newly started ordinary child is ready");
                using var cancel=new CancellationTokenSource(TimeSpan.FromMilliseconds(100));var cancelled=false;
                try{await BackendClient.WaitProjectClient(owned,originalHost.Replace('\\','/'),cancel.Token);}catch(OperationCanceledException)when(cancel.IsCancellationRequested){cancelled=true;}
                Require(cancelled && owned.HasExited,"requested cancellation ends the held own ordinary client with canonical image binding");
            }
            finally{if(!owned.HasExited){owned.StandardInput.Close();if(!owned.WaitForExit(5000))throw new IOException("Own child not terminal; retained for exact observation");}}
        }
        using(var refused=Start("wait"))
        {
            try
            {
                Require(await refused.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5))=="OWN_CLIENT_READY","foreign-image refusal fixture ready");
                using var cancel=new CancellationTokenSource();cancel.Cancel();var denied=false;
                try{await BackendClient.WaitProjectClient(refused,originalHost+".other",cancel.Token);}catch(IOException error)when(error.Message=="普通调用身份无法核对，未结束任何进程。"){denied=true;}
                Require(denied && !refused.HasExited,"wrong image refuses stop and does not terminate even this own child");
                refused.StandardInput.WriteLine("finish");refused.StandardInput.Close();
                Require(refused.WaitForExit(5000) && refused.ExitCode==0,"refused child exits only through own fixed stdin completion");
            }
            finally{if(!refused.HasExited){refused.StandardInput.Close();if(!refused.WaitForExit(5000))throw new IOException("Own child not terminal; retained for exact observation");}}
        }
        var cancellationReport=BackendClient.CancelledProjectResult();using var json=JsonDocument.Parse(cancellationReport.Output);
        Require(cancellationReport.ExitCode==130 && !json.RootElement.GetProperty("OwnerClosureConfirmed").GetBoolean() && !json.RootElement.GetProperty("ResultAutomaticallyExtracted").GetBoolean() && !json.RootElement.GetProperty("AutomaticRetry").GetBoolean(),"cancellation metadata never grants closure, extraction, retry or success");
        return checks;
    }
}
