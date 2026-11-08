using System.Text;

namespace ProtectionLifecycle;

// The caller supplies a held tunnel and already authorized trust inputs.
// This does not acquire a tunnel or fetch any certificate material.
internal static class FixedOpenSslHead
{
    private const int MaxHeaderBytes=8192;
    private static readonly byte[] Request=Encoding.ASCII.GetBytes(
        "HEAD / HTTP/1.1\r\nHost: "+SessionProxy.Target+"\r\nConnection: close\r\n\r\n");

    internal static async Task<int> SendAsync(OpenSslModuleLease modules,Stream tunnel,byte[] root,
        IReadOnlyList<byte[]> crls,CancellationToken cancel,Action<string>? phase=null)
    {
        phase?.Invoke("HTTPS_TLS_POLICY");
        using var tls=OpenSslMemoryConnection.CreateRevocationCheckedClient(modules.SslHandle,modules.CryptoHandle,
            tunnel,SessionProxy.Target,root,crls);
        phase?.Invoke("HTTPS_TLS_HANDSHAKE");
        await tls.AuthenticateAsync(cancel).ConfigureAwait(false);
        phase?.Invoke("HTTPS_HTTP_EXCHANGE");
        await tls.WriteAsync(Request,cancel).ConfigureAwait(false);
        return await ReadStatus(tls,cancel).ConfigureAwait(false);
    }

    private static async Task<int> ReadStatus(OpenSslMemoryConnection tls,CancellationToken cancel)
    {
        var header=new byte[MaxHeaderBytes];
        var chunk=new byte[512];
        int length=0;
        while(length<MaxHeaderBytes)
        {
            var count=await tls.ReadAsync(chunk,cancel).ConfigureAwait(false);
            for(var index=0;index<count;index++)
            {
                if(length==MaxHeaderBytes)throw new InvalidDataException("Fixed HEAD response header is too large");
                var value=chunk[index];
                bool previousCr=length!=0 && header[length-1]==13;
                if(value>126 || value<32 && value is not (13 or 10 or 9) || (value==10)!=previousCr)
                    throw new InvalidDataException("Malformed fixed HEAD response");
                header[length++]=value;
                if(length>=4 && header.AsSpan(length-4,4).SequenceEqual("\r\n\r\n"u8))
                {
                    if(index!=count-1)throw new InvalidDataException("Unexpected fixed HEAD response body");
                    return ParseStatus(header.AsSpan(0,length));
                }
            }
        }
        throw new InvalidDataException("Fixed HEAD response header is too large");
    }

    private static int ParseStatus(ReadOnlySpan<byte> header)
    {
        var firstLine=header.IndexOf("\r\n"u8);
        if(firstLine<12 || !header.StartsWith("HTTP/1.1 "u8) || header[9] is <(byte)'2' or >(byte)'5' ||
            header[10] is <(byte)'0' or >(byte)'9' || header[11] is <(byte)'0' or >(byte)'9' ||
            firstLine>12 && header[12]!=(byte)' ')
            throw new InvalidDataException("Unexpected fixed HEAD response status");
        return (header[9]-'0')*100+(header[10]-'0')*10+header[11]-'0';
    }
}
