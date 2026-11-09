using System.Buffers.Binary;
using System.Security.Cryptography;

namespace ProtectionLifecycle;

internal static class SessionZeroCreatorTerminal
{
    internal const int CloseSize=20;
    private const int HeaderSize=28;
    private const uint CloseMagic=0x31534343,CleanedMagic=0x32444343; // CCS1, CCD2.
    private const uint OutputMagic=0x314f4343,OutputFailureMagic=0x31454343; // CCO1, CCE1.

    internal static byte[] CloseFrame(byte[] nonce)
    {
        var frame=new byte[CloseSize];
        WriteBinding(frame,nonce,CloseMagic);
        return frame;
    }
    internal static void AssertCloseFrame(byte[] frame,byte[] nonce)
    {
        if(frame.Length!=CloseSize || !MatchesBinding(frame,nonce,CloseMagic))throw WfpNative.Contract("CreatorCloseBindingMismatch");
    }

    internal static byte[] CleanedFrame(byte[] nonce)
    {
        var frame=new byte[CloseSize];
        WriteBinding(frame,nonce,CleanedMagic);
        return frame;
    }

    internal static void ReadCleaned(Stream stream,byte[] nonce,CancellationToken cancellation)
    {
        var frame=new byte[CloseSize];
        stream.ReadExactlyAsync(frame.AsMemory(),cancellation).AsTask().GetAwaiter().GetResult();
        if(!MatchesBinding(frame,nonce,CleanedMagic))throw WfpNative.Contract("CreatorCleanupReceiptBindingMismatch");
    }

    internal static byte[] CaptureFailure(byte[] nonce,uint code)
    {
        var frame=new byte[HeaderSize];
        WriteBinding(frame,nonce,OutputFailureMagic);
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(20),code==0?13u:code);
        return frame;
    }

    internal static byte[] CreateReceipt(byte[] nonce,OfflineConsoleOutput output,OfflineConsoleOutput error)
    {
        CheckLength(output.Bytes.Length,output.Overflow);
        CheckLength(error.Bytes.Length,error.Overflow);
        var frame=new byte[HeaderSize+output.Bytes.Length+error.Bytes.Length];
        WriteBinding(frame,nonce,OutputMagic);
        var flags=(output.Overflow?1u:0u)|(error.Overflow?2u:0u);
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(20),flags);
        BinaryPrimitives.WriteUInt16LittleEndian(frame.AsSpan(24),(ushort)output.Bytes.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(frame.AsSpan(26),(ushort)error.Bytes.Length);
        output.Bytes.CopyTo(frame,HeaderSize);
        error.Bytes.CopyTo(frame,HeaderSize+output.Bytes.Length);
        return frame;
    }
    internal static (OfflineConsoleOutput Output,OfflineConsoleOutput Error) ReadReceipt(Stream stream,byte[] nonce,CancellationToken cancellation)
    {
        var header=new byte[HeaderSize];
        stream.ReadExactlyAsync(header.AsMemory(),cancellation).AsTask().GetAwaiter().GetResult();
        var flags=BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(20));
        if(MatchesBinding(header,nonce,OutputFailureMagic))
        {
            if(flags==0 || BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(24))!=0)
                throw WfpNative.Contract("CreatorConsoleFailureFrameInvalid");
            throw new WfpFailure("CreatorConsoleCapture",flags);
        }
        if(!MatchesBinding(header,nonce,OutputMagic))throw WfpNative.Contract("CreatorConsoleReceiptBindingMismatch");
        if((flags&~3u)!=0)throw WfpNative.Contract("CreatorConsoleReceiptFlagsInvalid");
        var output=Read(24,(flags&1)!=0);
        var error=Read(26,(flags&2)!=0);
        return(output,error);

        OfflineConsoleOutput Read(int offset,bool overflow)
        {
            var length=BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(offset));
            CheckLength(length,overflow);
            var bytes=new byte[length];
            stream.ReadExactlyAsync(bytes.AsMemory(),cancellation).AsTask().GetAwaiter().GetResult();
            return new(bytes,overflow);
        }
    }
    private static void CheckLength(int length,bool overflow)
    {
        if(length>OfflineConsoleStreams.MaximumBytes || overflow && length!=OfflineConsoleStreams.MaximumBytes)
            throw WfpNative.Contract("CreatorConsoleReceiptLengthInvalid");
    }
    private static void WriteBinding(byte[] frame,byte[] nonce,uint magic)
    {
        if(nonce.Length!=16)throw WfpNative.Contract("CreatorTerminalNonceInvalid");
        BinaryPrimitives.WriteUInt32LittleEndian(frame,magic);
        nonce.CopyTo(frame,4);
    }
    private static bool MatchesBinding(byte[] frame,byte[] nonce,uint magic)=>nonce.Length==16 &&
        BinaryPrimitives.ReadUInt32LittleEndian(frame)==magic && CryptographicOperations.FixedTimeEquals(frame.AsSpan(4,16),nonce);
}
