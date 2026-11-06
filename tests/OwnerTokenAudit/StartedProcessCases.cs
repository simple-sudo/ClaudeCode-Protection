using System.Diagnostics;
using System.Reflection;
using System.Reflection.Emit;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace OwnerTokenAudit;

internal static class StartedProcessCases
{
    internal static object Run(Action<bool> check)
    {
        // Reflect metadata only. Do not run this initializer, EnterDebugMode
        // or an arbitrary framework method just to reproduce a side effect.
        var library=typeof(Process).Assembly;
        var initializer=library.GetType("System.Diagnostics.ProcessManager",true)!.TypeInitializer!;
        var bytes=initializer.GetMethodBody()!.GetILAsByteArray()!;
        var opcodes=typeof(OpCodes).GetFields(BindingFlags.Public|BindingFlags.Static)
            .Select(f=>(OpCode)f.GetValue(null)!).ToDictionary(o=>unchecked((ushort)o.Value));
        var calls=new List<string>();
        for(int i=0;i<bytes.Length;)
        {
            ushort key=bytes[i++];if(key==0xfe)key=(ushort)(0xfe00|bytes[i++]);var op=opcodes[key];
            if(op.OperandType==OperandType.InlineMethod)
            {var method=initializer.Module.ResolveMethod(BitConverter.ToInt32(bytes,i))!;calls.Add(method.DeclaringType!.FullName+"."+method.Name);}
            int size=op.OperandType switch{
                OperandType.InlineNone=>0,
                OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar=>1,
                OperandType.InlineVar=>2,
                OperandType.InlineI8 or OperandType.InlineR=>8,
                OperandType.InlineSwitch=>4+4*BitConverter.ToInt32(bytes,i),_=>4};
            i=checked(i+size);if(i>bytes.Length)throw new InvalidDataException("RuntimeInitializerIlBounds");
        }
        check(calls.Any(c=>c.EndsWith(".AdjustTokenPrivileges",StringComparison.Ordinal)));
        check(calls.Any(c=>c.EndsWith(".OpenProcessToken",StringComparison.Ordinal)));
        check(calls.Any(c=>c.EndsWith(".LookupPrivilegeValue",StringComparison.Ordinal)));
        using(var invalid=new SafeProcessHandle(IntPtr.Zero,false))
        {bool refused=false;try{StartedProcessObservation.Terminal(invalid);}catch(ArgumentException){refused=true;}check(refused);}
        var before=OwnTokenObservation.Capture();check(before.Complete);
        var outcomes=new List<object>();
        foreach(var mode in new[]{"--fixed-child-259","--fixed-child-blocked"})
        {
            var info=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,CreateNoWindow=true,
                RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
            info.ArgumentList.Add(mode);info.Environment.Clear();
            foreach(var name in new[]{"SystemRoot","windir","ProgramFiles","ProgramFiles(x86)","ProgramW6432"})
                if(Environment.GetEnvironmentVariable(name) is string value)info.Environment[name]=value;
            using var child=Process.Start(info)??throw new InvalidOperationException("FixedOrdinaryChildMissing");
            var handle=child.SafeHandle;uint pid=StartedProcessObservation.Id(handle);long created=StartedProcessObservation.CreatedFileTime(handle);
            check(pid!=0 && created>0);
            var stderr=child.StandardError.ReadToEndAsync();
            if(mode=="--fixed-child-blocked")
            {
                check(child.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(3)).GetAwaiter().GetResult()=="ready");
                check(!StartedProcessObservation.Terminal(handle));bool refused=false;
                try{StartedProcessObservation.ExitCode(handle);}catch(InvalidOperationException){refused=true;}check(refused);
                refused=false;try{StartedProcessObservation.Terminal(handle,1001);}catch(ArgumentOutOfRangeException){refused=true;}check(refused);
                child.StandardInput.WriteLine("release");child.StandardInput.Flush();
            }
            var stdout=child.StandardOutput.ReadToEndAsync();var timer=Stopwatch.StartNew();
            while(!StartedProcessObservation.Terminal(handle,1000))if(timer.ElapsedMilliseconds>10000)throw new TimeoutException("OriginalOrdinaryChildTerminalUnknownNoForceStop");
            uint code=StartedProcessObservation.ExitCode(handle);
            check(code==(mode=="--fixed-child-259"?259u:7u));
            check(stdout.WaitAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult()=="" && stderr.WaitAsync(TimeSpan.FromSeconds(2)).GetAwaiter().GetResult()=="");
            outcomes.Add(new{Mode=mode,ExitCode=code,OriginalHandleTerminal=true,CreationTimeObserved=true});
        }
        var after=OwnTokenObservation.Capture();var comparison=OwnTokenObservation.Compare(before,after);
        check(comparison.Status=="OBSERVED_FIELDS_EQUAL");
        return new{Scope="LOCAL_RUNTIME_METADATA_AND_TWO_FIXED_ORDINARY_CHILD_HANDLES_ONLY",RuntimePath=library.Location,
            RuntimeInformationalVersion=library.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion,
            RuntimeSHA256=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(library.Location))),
            ProcessManagerInitializerCalls=calls,InitializerInvokedReflectively=false,Outcomes=outcomes,Before=before,After=after,Comparison=comparison};
    }
}
