using System.Text;

namespace ProtectionLifecycle;

// The caller supplies a held tunnel and already authorized trust inputs.
// This does not acquire a tunnel or fetch any certificate material.
internal static class FixedOpenSslHead
{
    internal const string RequestPath="/robots.txt";
    internal const string UserAgent="ClaudeCode-Protection/1.0";
    private static readonly byte[] Request=Encoding.ASCII.GetBytes(
        "HEAD "+RequestPath+" HTTP/1.1\r\nHost: "+SessionProxy.Target+"\r\nUser-Agent: "+UserAgent+"\r\nConnection: close\r\n\r\n");

    internal static async Task<int> SendAsync(OpenSslModuleLease modules,Stream tunnel,byte[] root,
        IReadOnlyList<byte[]> crls,CancellationToken cancel,Action<string>? phase=null)
    {
        phase?.Invoke("HTTPS_TLS_POLICY");
        using var tls=OpenSslMemoryConnection.CreateRevocationCheckedClient(modules.SslHandle,modules.CryptoHandle,
            tunnel,SessionProxy.Target,root,crls);
        phase?.Invoke("HTTPS_TLS_HANDSHAKE");
        await tls.AuthenticateAsync(cancel).ConfigureAwait(false);
        phase?.Invoke("HTTPS_HTTP_WRITE");
        await tls.WriteAsync(Request,cancel).ConfigureAwait(false);
        phase?.Invoke("HTTPS_HTTP_EXCHANGE");
        return await FixedHeadResponse.ReadStatus(tls,cancel).ConfigureAwait(false);
    }
}
