using System.Runtime.InteropServices;

namespace ProtectionLifecycle;

// Inherited only by children created in this small serialized window. Never
// edits WER/registry/global UI settings or swallows an exception/exit result.
// The original owner still records failure and closes its exact Job.
internal sealed class ToolFaultMode : IDisposable
{
    private static readonly object gate=new();
    private const uint unattended=0x8003; // critical, GP-fault and OpenFile boxes.
    private readonly uint prior;
    private bool disposed;
    private ToolFaultMode()
    {
        Monitor.Enter(gate);
        try{prior=GetErrorMode();_=SetErrorMode(prior|unattended);}
        catch{Monitor.Exit(gate);throw;}
    }
    internal static ToolFaultMode Enter()=>new();
    internal static uint CurrentMode()=>GetErrorMode();
    public void Dispose()
    {if(disposed)return;disposed=true;try{_=SetErrorMode(prior);}finally{Monitor.Exit(gate);}}
    [DllImport("kernel32.dll",ExactSpelling=true)] private static extern uint GetErrorMode();
    [DllImport("kernel32.dll",ExactSpelling=true)] private static extern uint SetErrorMode(uint mode);
}

// Keep bounded partial stderr even when a child is blocked in a fatal dialog
// or has not closed its pipes. Raw text remains in private owner evidence.
internal sealed class ToolOutputCapture
{
    private readonly object gate=new();
    private readonly System.Text.StringBuilder text=new();
    internal Task<string> Completion {get;}
    internal ToolOutputCapture(StreamReader reader){Completion=Read(reader);}
    private async Task<string> Read(StreamReader reader)
    {
        var buffer=new char[512];
        while(true)
        {
            var count=await reader.ReadAsync(buffer.AsMemory());
            if(count==0)return Snapshot();
            lock(gate){if(text.Length+count>4096)throw WfpNative.Contract("ResourceReportTooLarge");text.Append(buffer,0,count);}
        }
    }
    internal string Snapshot(){lock(gate)return text.ToString();}
    internal static string Classify(string stdout,string stderr)
    {
        var match=System.Text.RegularExpressions.Regex.Match(stderr,@"(?:Unhandled exception\.\s+|Exception:\s+)(System\.[A-Za-z0-9_.]{1,160})(?:[:\s]|$)");
        return match.Success?"MANAGED_UNHANDLED_TYPE="+match.Groups[1].Value:
            "UNCLASSIFIED_OUTPUT_SHA256="+Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(stdout+"\0"+stderr)));
    }
}
