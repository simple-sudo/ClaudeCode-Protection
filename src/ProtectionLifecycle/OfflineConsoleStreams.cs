using System.IO.Pipes;
using System.Runtime.InteropServices;

namespace ProtectionLifecycle;

internal sealed record OfflineConsoleOutput(byte[] Bytes,bool Overflow);

// The owner keeps only the output readers after creating the suspended
// process. No input writer survives, even during process creation.
internal sealed class OfflineConsoleStreams : IDisposable
{
    internal const int MaximumBytes=4096;
    // DETACHED_PROCESS. This workload gets its console I/O only from the
    // three pipes. Do not allocate or inherit a Windows console.
    internal const uint DetachedCreationFlag=0x00000008;
    private readonly AnonymousPipeServerStream input,output,error;
    private bool released,disposed;

    internal OfflineConsoleStreams()
    {
        input=new(PipeDirection.Out,HandleInheritability.Inheritable);
        try
        {
            output=new(PipeDirection.In,HandleInheritability.Inheritable);
            try
            {
                error=new(PipeDirection.In,HandleInheritability.Inheritable);
                try{input.SafePipeHandle.Dispose();}
                catch{error.Dispose();throw;}
            }
            catch{output.Dispose();throw;}
        }
        catch{input.Dispose();throw;}
    }

    internal (IntPtr Input,IntPtr Output,IntPtr Error) ChildHandles()
    {
        if(released || disposed)throw WfpNative.Contract("OfflineConsoleHandlesUnavailable");
        var handles=(Input:input.ClientSafePipeHandle,Output:output.ClientSafePipeHandle,Error:error.ClientSafePipeHandle);
        if(new[]{handles.Input,handles.Output,handles.Error}.Any(h=>h.IsClosed || h.IsInvalid))
            throw WfpNative.Contract("OfflineConsoleHandleInvalid");
        var result=(handles.Input.DangerousGetHandle(),handles.Output.DangerousGetHandle(),handles.Error.DangerousGetHandle());
        if(result.Item1==result.Item2 || result.Item1==result.Item3 || result.Item2==result.Item3)
            throw WfpNative.Contract("OfflineConsoleHandlesNotDistinct");
        return result;
    }

    internal CreationAttributes PrepareCreationAttributes()=>new(ChildHandles());

    internal (Task<OfflineConsoleOutput> Output,Task<OfflineConsoleOutput> Error) ReadAfterCreate()
    {
        if(released || disposed)throw WfpNative.Contract("OfflineConsoleCaptureAlreadyStarted");
        released=true;
        input.DisposeLocalCopyOfClientHandle();
        output.DisposeLocalCopyOfClientHandle();
        error.DisposeLocalCopyOfClientHandle();
        return (ReadBounded(output),ReadBounded(error));
    }

    internal static async Task<OfflineConsoleOutput> ReadBounded(Stream stream)
    {
        var buffer=new byte[MaximumBytes+1];
        try
        {
            int used=0;
            while(used<buffer.Length)
            {
                var count=await stream.ReadAsync(buffer.AsMemory(used)).ConfigureAwait(false);
                if(count==0)return new(buffer[..used],false);
                used+=count;
            }
            return new(buffer[..MaximumBytes],true);
        }
        finally{Array.Clear(buffer);}
    }

    public void Dispose()
    {
        if(disposed)return;
        disposed=true;error.Dispose();output.Dispose();input.Dispose();
    }

    // The values stay allocated until the caller deletes its attribute list.
    internal sealed class CreationAttributes : IDisposable
    {
        private IntPtr handles,childPolicy;
        internal (IntPtr Input,IntPtr Output,IntPtr Error) Channels {get;}

        internal CreationAttributes((IntPtr Input,IntPtr Output,IntPtr Error) channels)
        {
            Channels=channels;
            try
            {
                handles=Marshal.AllocHGlobal(IntPtr.Size*3);
                Marshal.WriteIntPtr(handles,0,channels.Input);
                Marshal.WriteIntPtr(handles,IntPtr.Size,channels.Output);
                Marshal.WriteIntPtr(handles,IntPtr.Size*2,channels.Error);
                childPolicy=Marshal.AllocHGlobal(sizeof(uint));
                Marshal.WriteInt32(childPolicy,1);
            }
            catch{Dispose();throw;}
        }

        internal void Bind(IntPtr attributes)
        {
            if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)0x20002,handles,(nuint)(IntPtr.Size*3),IntPtr.Zero,IntPtr.Zero))
                throw WindowsPathSeal.Error("AtomicSetOnlyConsoleHandles");
            if(!UpdateProcThreadAttribute(attributes,0,(IntPtr)0x2000e,childPolicy,sizeof(uint),IntPtr.Zero,IntPtr.Zero))
                throw WindowsPathSeal.Error("AtomicRequireNoChildCreation");
        }

        public void Dispose()
        {
            if(handles!=IntPtr.Zero){Marshal.FreeHGlobal(handles);handles=IntPtr.Zero;}
            if(childPolicy!=IntPtr.Zero){Marshal.FreeHGlobal(childPolicy);childPolicy=IntPtr.Zero;}
        }

        [DllImport("kernel32.dll",SetLastError=true)]
        [return:MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,nuint size,IntPtr previous,IntPtr returned);
    }
}
