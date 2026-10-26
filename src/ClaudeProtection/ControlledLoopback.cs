using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ClaudeProtection;

// Ordinary-user receivers establish actual UDP delivery, not SendTo return codes.
internal sealed class ControlledLoopback : IDisposable
{
    internal sealed record Targets(int Tcp4, int Tcp6, int Udp4, int Udp6, string Nonce);
    private readonly TcpListener tcp4 = new(IPAddress.Loopback, 0);
    private readonly TcpListener tcp6 = new(IPAddress.IPv6Loopback, 0);
    private readonly UdpClient udp4 = new(new IPEndPoint(IPAddress.Loopback, 0));
    private readonly UdpClient udp6 = new(new IPEndPoint(IPAddress.IPv6Loopback, 0));
    private readonly CancellationTokenSource stop = new();
    private readonly ConcurrentDictionary<string, byte> received4 = new();
    private readonly ConcurrentDictionary<string, byte> received6 = new();
    private readonly Task receive4, receive6;
    internal Targets Endpoints { get; }
    internal ControlledLoopback()
    {
        try
        {
            tcp6.Server.DualMode = false;
            tcp4.Start(); tcp6.Start();
            Endpoints = new(((IPEndPoint)tcp4.LocalEndpoint).Port, ((IPEndPoint)tcp6.LocalEndpoint).Port,
                ((IPEndPoint)udp4.Client.LocalEndPoint!).Port, ((IPEndPoint)udp6.Client.LocalEndPoint!).Port, Guid.NewGuid().ToString("N"));
            receive4 = Collect(udp4, received4);
            receive6 = Collect(udp6, received6);
        }
        catch { tcp4.Stop(); tcp6.Stop(); udp4.Dispose(); udp6.Dispose(); stop.Dispose(); throw; }
    }
    private async Task Collect(UdpClient receiver, ConcurrentDictionary<string, byte> found)
    {
        try
        {
            while (!stop.IsCancellationRequested)
            {
                var packet = await receiver.ReceiveAsync(stop.Token);
                if (packet.Buffer.Length > 64) continue;
                var value = Encoding.ASCII.GetString(packet.Buffer);
                foreach (var role in new[] { "parent", "child" })
                    if (value == Endpoints.Nonce + ":" + role) found.TryAdd(role, 0);
            }
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException) { }
        catch (SocketException) when (stop.IsCancellationRequested) { }
    }
    internal object Receipts() => new { ipv4ReceiptRoles = received4.Keys.Order().ToArray(), ipv6ReceiptRoles = received6.Keys.Order().ToArray() };
    public void Dispose()
    {
        stop.Cancel(); tcp4.Stop(); tcp6.Stop(); udp4.Dispose(); udp6.Dispose();
        try { Task.WhenAll(receive4, receive6).GetAwaiter().GetResult(); } finally { stop.Dispose(); }
    }
}
