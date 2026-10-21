using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Haukcode.SigNet.Keys;
using Haukcode.SigNet.Model;
using Xunit;

namespace Haukcode.SigNet.UnitTest;

internal sealed class MemorySessionIdStore : ISessionIdStore
{
    public MemorySessionIdStore(uint initial = 0)
    {
        SessionId = initial;
    }

    public uint SessionId { get; private set; }

    public int Saves { get; private set; }

    public uint LoadSessionId() => SessionId;

    public void SaveSessionId(uint sessionId)
    {
        SessionId = sessionId;
        Saves++;
    }
}

internal static class TestPorts
{
    /// <summary>
    /// A UDP port nothing is using, picked by the OS.
    /// </summary>
    public static int GetFreeUdpPort()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        return ((IPEndPoint)socket.LocalEndPoint!).Port;
    }
}

internal static class Wait
{
    public static async Task<T> For<T>(ConcurrentQueue<T> queue, Func<T, bool>? match = null, int timeoutMS = 3000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMS);
        while (DateTime.UtcNow < deadline)
        {
            while (queue.TryDequeue(out var item))
            {
                if (match == null || match(item))
                    return item;
            }

            await Task.Delay(10, TestContext.Current.CancellationToken);
        }

        throw new TimeoutException("Nothing matching arrived");
    }

    public static async Task Until(Func<bool> condition, int timeoutMS = 3000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMS);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
                throw new TimeoutException("Condition not met");

            await Task.Delay(10, TestContext.Current.CancellationToken);
        }
    }
}

/// <summary>
/// A client on 127.0.0.1 with a free port, capturing received frames and sent datagrams.
/// </summary>
internal sealed class TestClient : IDisposable
{
    public static readonly Tuid DefaultTuid = new(0x0744, 0x00000042);

    public TestClient(SigNetDeviceInfo? deviceInfo = null, MemorySessionIdStore? store = null, TimeProvider? timeProvider = null, Tuid? tuid = null)
    {
        Tuid = tuid ?? DefaultTuid;
        Keys = SigNetKeys.FromRootKey(Convert.FromHexString(KeyDerivationTests.AppendixGRootKey), Tuid);
        Store = store ?? new MemorySessionIdStore(41);
        Port = TestPorts.GetFreeUdpPort();
        Client = new SigNetClient(
            Keys,
            Tuid,
            deviceInfo ?? new SigNetDeviceInfo(SoemCode.Create(0x0744, 0x0001), "Test Model", "Test Label"),
            Store,
            IPAddress.Loopback,
            channelWriter: p =>
            {
                Received.Enqueue(p.Clone());

                return Task.CompletedTask;
            },
            port: Port,
            timeProvider: timeProvider);

        // Record everything; multicast is swallowed because a loopback-bound socket cannot send it
        Client.SendInterceptor = (destination, datagram) =>
        {
            Sent.Enqueue((destination, datagram));

            return Haukcode.Network.Utils.IsMulticast(destination.Address);
        };
        Client.OnError.Subscribe(Errors.Enqueue);
    }

    public ConcurrentQueue<Exception> Errors { get; } = new();

    public Tuid Tuid { get; }

    public SigNetKeys Keys { get; }

    public MemorySessionIdStore Store { get; }

    public int Port { get; }

    public SigNetClient Client { get; }

    public ConcurrentQueue<ReceiveDataPacket> Received { get; } = new();

    public ConcurrentQueue<(IPEndPoint Destination, byte[] Datagram)> Sent { get; } = new();

    /// <summary>
    /// Send raw bytes to the client's port on loopback, as another device would.
    /// </summary>
    public void Inject(byte[] datagram)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.SendTo(datagram, new IPEndPoint(IPAddress.Loopback, Port));
    }

    /// <summary>
    /// Parse a sent datagram, verify it with the key its URI selects and return path and payload.
    /// </summary>
    public (SigNetPath Path, SigNetPacket Packet) Decode(byte[] datagram)
    {
        var packet = new SigNetPacket();
        Assert.Equal(SigNetParseResult.Ok, SigNetPacketParser.TryParse(datagram, packet));
        Assert.Equal(SigNetUriParseResult.Ok, SigNetUri.TryParsePath(packet, null, out var path));
        Assert.True(Security.SigNetHmac.Verify(Keys.GetKey(path.KeyRole), packet), $"HMAC of {path}");

        return (path, packet);
    }

    public void Dispose()
    {
        Client.Dispose();
        Keys.Dispose();
    }
}
