using System.Net;
using System.Net.Sockets;
using System.Threading;
using Haukcode.SigNet.Model;

namespace Haukcode.SigNet;

/// <summary>
/// Beacon Mode for an offboarded device, one without keys (spec 7.2.2, 10.2.1): an
/// unauthenticated presence beacon (Security-Mode 0xFF) to &lt;mult_node_beacon&gt; on the local
/// scope, once every &lt;beacon_min_interval&gt;, so Managers can show the device as waiting to be
/// onboarded. An offboarded device discards everything it receives, so there is no receive side.
/// Dispose it once the device is onboarded and a <see cref="SigNetClient"/> takes over.
/// </summary>
public sealed class SigNetBeacon : IDisposable
{
    /// <summary>
    /// &lt;beacon_min_interval&gt; (spec Appendix B): never more often than this.
    /// </summary>
    public static readonly TimeSpan Interval = TimeSpan.FromSeconds(5);

    private readonly Socket socket;
    private readonly IPEndPoint destination;
    private readonly ITimer timer;
    private readonly object sendLock = new();
    private volatile SigNetDeviceInfo deviceInfo;
    private ushort messageId;
    private bool disposed;

    /// <param name="tuid">This device's TUID.</param>
    /// <param name="deviceInfo">SoemCode, label, roles and endpoint count reported in the beacon.</param>
    /// <param name="localAddress">The interface to send from.</param>
    public SigNetBeacon(Tuid tuid, SigNetDeviceInfo deviceInfo, IPAddress localAddress, int port = SigNetClient.DefaultPort, bool multicastLoopback = false, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(deviceInfo);
        ArgumentNullException.ThrowIfNull(localAddress);

        Tuid = tuid;
        this.deviceInfo = deviceInfo;
        this.destination = new IPEndPoint(SigNetMulticast.NodeBeacon, port);

        this.socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            Haukcode.Network.Utils.SetSocketOptions(this.socket);
            this.socket.MulticastLoopback = multicastLoopback;
            this.socket.Bind(new IPEndPoint(localAddress, 0));
            this.socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, SigNetClient.MulticastTtl);
            if (!localAddress.Equals(IPAddress.Any))
                this.socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, localAddress.GetAddressBytes());
        }
        catch
        {
            this.socket.Dispose();
            throw;
        }

        this.timer = (timeProvider ?? TimeProvider.System).CreateTimer(_ => SendBeacon(), null, TimeSpan.Zero, Interval);
    }

    public Tuid Tuid { get; }

    /// <summary>
    /// What the beacons report; replace it when the label or endpoints change.
    /// </summary>
    public SigNetDeviceInfo DeviceInfo
    {
        get => this.deviceInfo;
        set => this.deviceInfo = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>
    /// Raised when a beacon cannot be sent (the interface went away, for example). The next
    /// beacon is tried at the usual interval.
    /// </summary>
    public event EventHandler<Exception>? SendFailed;

    /// <summary>
    /// For tests: sees every beacon before it is sent, and returns true to swallow it.
    /// </summary>
    internal Func<IPEndPoint, byte[], bool>? SendInterceptor { get; set; }

    /// <summary>
    /// Write one beacon (spec 10.2.1): Security-Mode 0xFF, Sender-ID with endpoint 0, Mfg-Code,
    /// Session-ID and Seq-Num all zero, Sig-Net-Auth empty, then TID_POLL_REPLY with CHANGE_COUNT
    /// 0, TID_RT_DEVICE_LABEL, TID_RT_ROLE_CAPABILITY and TID_RT_ENDPOINT_COUNT, in that order.
    /// TID_RT_OTW_CAPABILITY is left out: over-the-wire onboarding is not supported. Returns the length.
    /// </summary>
    public static int WriteBeacon(Span<byte> destination, ushort messageId, Tuid tuid, SigNetDeviceInfo deviceInfo)
    {
        Span<byte> payload = stackalloc byte[Coap.MaxPayloadLength];
        var writer = new TlvWriter(payload);

        new PollReply(tuid, deviceInfo.SoemCode, 0).WriteTo(writer.Reserve(Tid.PollReply, PollReply.Length));
        TextPayload.WriteLabel(ref writer, Tid.RtDeviceLabel, deviceInfo.DeviceLabel);
        writer.WriteUInt32(Tid.RtRoleCapability, (uint)deviceInfo.Roles);
        writer.WriteUInt16(Tid.RtEndpointCount, (ushort)deviceInfo.Endpoints.Count);

        var header = new SigNetSecurityHeader(SecurityMode.Beacon, new SenderId(tuid, 0), 0, 0, 0);

        return SigNetPacketWriter.Write(destination, messageId, SigNetPath.NodeBeacon(tuid), header, writer.Written, ReadOnlySpan<byte>.Empty);
    }

    public void Dispose()
    {
        lock (this.sendLock)
        {
            if (this.disposed)
                return;

            this.disposed = true;
        }

        this.timer.Dispose();
        this.socket.Dispose();
    }

    private void SendBeacon()
    {
        lock (this.sendLock)
        {
            if (this.disposed)
                return;

            try
            {
                var buffer = new byte[SigNetPacketWriter.GetMaxLength(Coap.MaxPayloadLength)];
                int length = WriteBeacon(buffer, ++this.messageId, Tuid, this.deviceInfo);

                if (SendInterceptor?.Invoke(this.destination, buffer[..length]) == true)
                    return;

                this.socket.SendTo(buffer.AsSpan(0, length), SocketFlags.None, this.destination);
            }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
            {
                SendFailed?.Invoke(this, ex);
            }
        }
    }
}
