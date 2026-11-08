using System.Security.Cryptography;

namespace ProtectionLifecycle;

internal enum FixedHeadResponseError
{
    HeaderCapacity=1, MalformedOctet=2, InvalidStatusLine=3, InvalidFieldName=4,
    ProtocolSwitch=5, InformationalCapacity=6, BytesAfterFinalHeader=7
}

internal enum FixedHeadTailKind
{
    EmptyLine=1, EmptyChunk=2, HttpPrefix=3, Other=4
}

// This describes only bytes already read alongside the final header.
// It must never be used to infer the rest of the stream or authorize reuse.
internal sealed record FixedHeadTrailingObservation(int FinalStatus,int Bytes,FixedHeadTailKind Kind)
{
    internal static FixedHeadTrailingObservation Observe(int status,ReadOnlySpan<byte> tail)
    {
        var kind=tail.SequenceEqual("\r\n"u8)?FixedHeadTailKind.EmptyLine:
            tail.SequenceEqual("0\r\n\r\n"u8)?FixedHeadTailKind.EmptyChunk:
            tail.StartsWith("HTTP/"u8)?FixedHeadTailKind.HttpPrefix:FixedHeadTailKind.Other;
        return new(status,tail.Length,kind);
    }

    internal static bool IsValid(int status,int bytes,int kind)=>status is >=200 and <=599 && bytes is >=1 and <FixedHeadResponse.ReadBatchBytes &&
        ((FixedHeadTailKind)kind switch {
            FixedHeadTailKind.EmptyLine=>bytes==2,
            FixedHeadTailKind.EmptyChunk=>bytes==5,
            FixedHeadTailKind.HttpPrefix=>bytes>=5,
            FixedHeadTailKind.Other=>true,
            _=>false
        });
}

internal sealed class FixedHeadResponseException(FixedHeadResponseError reason,FixedHeadTrailingObservation? trailing)
    : IOException("Fixed HEAD response refused")
{
    internal FixedHeadResponseError Reason {get;}=reason;
    internal FixedHeadTrailingObservation? Trailing {get;}=trailing;
}

internal static class FixedHeadResponse
{
    private const int MaxHeaderBytes=8192, MaxInterimResponses=4;
    internal const int ReadBatchBytes=512;

    internal static async Task<int> ReadStatus(OpenSslMemoryConnection tls,CancellationToken cancel)
    {
        var line=new byte[MaxHeaderBytes];
        var chunk=new byte[ReadBatchBytes];
        int total=0,length=0,interim=0;
        int? status=null;
        bool previousCr=false;
        try
        {
            while(total<MaxHeaderBytes)
            {
                var count=await tls.ReadAsync(chunk,cancel).ConfigureAwait(false);
                for(var index=0;index<count;index++)
                {
                    if(++total>MaxHeaderBytes)throw Refuse(FixedHeadResponseError.HeaderCapacity);
                    var value=chunk[index];
                    if(value==127 || value<32 && value is not (13 or 10 or 9) || (value==10)!=previousCr)
                        throw Refuse(FixedHeadResponseError.MalformedOctet);
                    previousCr=value==13;
                    if(previousCr)continue;
                    if(value!=10){line[length++]=value;continue;}
                    if(status is null)status=ParseStatus(line.AsSpan(0,length));
                    else if(length>0)RequireFieldName(line.AsSpan(0,length));
                    else if(status>=200)
                    {
                        if(index!=count-1)throw new FixedHeadResponseException(FixedHeadResponseError.BytesAfterFinalHeader,
                            FixedHeadTrailingObservation.Observe(status.Value,chunk.AsSpan(index+1,count-index-1)));
                        return status.Value;
                    }
                    else
                    {
                        if(status==101)throw Refuse(FixedHeadResponseError.ProtocolSwitch);
                        if(++interim>MaxInterimResponses)throw Refuse(FixedHeadResponseError.InformationalCapacity);
                        status=null;
                    }
                    length=0;
                }
            }
            throw Refuse(FixedHeadResponseError.HeaderCapacity);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(line);
            CryptographicOperations.ZeroMemory(chunk);
        }
    }

    private static int ParseStatus(ReadOnlySpan<byte> line)
    {
        if(line.Length<12 || !line.StartsWith("HTTP/1.1 "u8) || line[9] is <(byte)'1' or >(byte)'5' ||
            line[10] is <(byte)'0' or >(byte)'9' || line[11] is <(byte)'0' or >(byte)'9' ||
            line.Length>12 && line[12]!=(byte)' ')
            throw Refuse(FixedHeadResponseError.InvalidStatusLine);
        return (line[9]-'0')*100+(line[10]-'0')*10+line[11]-'0';
    }

    private static void RequireFieldName(ReadOnlySpan<byte> line)
    {
        var colon=line.IndexOf((byte)':');
        if(colon<1)throw Refuse(FixedHeadResponseError.InvalidFieldName);
        foreach(var value in line[..colon])
            if(!char.IsAsciiLetterOrDigit((char)value) && !"!#$%&'*+-.^_`|~"u8.Contains(value))
                throw Refuse(FixedHeadResponseError.InvalidFieldName);
    }

    private static FixedHeadResponseException Refuse(FixedHeadResponseError reason)=>new(reason,null);
}
