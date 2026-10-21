using System.Net;
using System.Net.Sockets;
using System.Reactive.Linq;
using System.Reactive.Subjects;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Haukcode.HighPerfComm;
using Haukcode.SigNet.Internal;
using Haukcode.SigNet.Keys;
using Haukcode.SigNet.Model;
using Haukcode.SigNet.Security;

namespace Haukcode.SigNet;

/// <summary>
/// A Sig-Net device on one network interface: the Sender role (levels, priority, sync, universe
/// announcements, discovery replies) and the receive side of the Node role (verified levels with
/// sync hold-and-release), on Haukcode.HighPerfComm's sharded send threads and kernel-timestamped
/// receive thread.
///
/// Partial files: SigNetClient.Send.cs (Sender role), SigNetClient.Receive.cs (levels and sync),
/// SigNetClient.Discovery.cs (polls, announcements, security events, Lost Mode).
/// </summary>
public partial class SigNetClient : Client<SigNetClient.SendData, ReceiveDataPacket>
{
    public class SendData : HighPerfComm.SendData
    {
        public IPEndPoint Destination { get; set; }

        /// <summary>
        /// The destination pre-serialized once, so the hot send path does not re-serialize the
        /// EndPoint on every SendTo.
        /// </summary>
        public SocketAddress DestinationAddress { get; set; }

        internal SendKind Kind { get; set; }

        public SendData(IPEndPoint destination)
        {
            Destination = destination;
            DestinationAddress = destination.Serialize();
        }
    }

    internal enum SendKind
    {
        Other,

        Level,

        Sync
    }

    /// <summary>
    /// &lt;coap_port&gt; (spec 9.3).
    /// </summary>
    public const int DefaultPort = 5683;

    /// <summary>
    /// &lt;mult_ttl&gt; (spec 9.6).
    /// </summary>
    public const int MulticastTtl = 32;

    /// <summary>
    /// Requested socket receive buffer, in bytes. Compare with <see cref="ActualReceiveBufferSize"/>
    /// to see whether the OS capped it (net.core.rmem_max on Linux).
    /// </summary>
    public const int ReceiveBufferSize = 680 * 20 * 200;

    // Room for the largest legal message (1,400 bytes) plus slack; send buffers come from the same pool
    private const int PacketBufferSize = 1500;
    private const int SendBufferSize = 680 * 20 * 200;
    private static readonly IPEndPoint blankEndpoint = new(IPAddress.Any, 0);

    private readonly SigNetKeys keys;
    private readonly ISessionIdStore sessionIdStore;
    private readonly TimeProvider timeProvider;
    private readonly IPEndPoint localEndPoint;
    private readonly Socket[] sendSockets;
    private readonly DeliveryRelay relay;
    private readonly SigNetPacketVerifier verifier;
    private readonly CancellationTokenSource lifetimeCts = new();
    private readonly ISubject<UniverseLostEvent> universeLostSubject = new Subject<UniverseLostEvent>();
    private readonly ISubject<SecurityEvent> securityEventSubject = new Subject<SecurityEvent>();
    private readonly long[] verifyCounts = new long[Enum.GetValues<VerifyResult>().Length];
    private ITimer? housekeepingTimer;
    private volatile SigNetDeviceInfo deviceInfo;

    private Socket? listenSocket;

    // Linux only: IGMP memberships live on separate sockets so the listen socket's own membership
    // list stays empty on the per-packet delivery path (see SACNClient). The kernel caps
    // memberships per socket (net.ipv4.igmp_max_memberships, 20 by default), so another socket is
    // opened whenever one is full. Null elsewhere, where memberships go on the listen socket.
    private List<Socket>? membershipSockets;
    private readonly Dictionary<IPAddress, (Socket Socket, int References)> memberships = [];
    private readonly object subscriptionLock = new();

    private IReceiveTimestamping? timestampedReceiver;

    /// <param name="keys">Derived role keys. The client uses but does not own or dispose them.</param>
    /// <param name="tuid">This device's TUID (spec 6.6), supplied by the host.</param>
    /// <param name="deviceInfo">SoemCode, labels, roles and endpoints reported in discovery.</param>
    /// <param name="sessionIdStore">
    /// Non-volatile session id storage. The constructor increments and saves the session id before
    /// anything is sent (spec 8.3) and throws <see cref="SessionIdExhaustedException"/> when it is
    /// exhausted.
    /// </param>
    /// <param name="localAddress">The interface to send from and join multicast groups on.</param>
    /// <param name="channelWriter">
    /// Called on the receive thread for every verified level frame and sync. The packet is reused
    /// once this returns: process it here or keep <see cref="ReceiveDataPacket.Clone"/>.
    /// </param>
    /// <param name="scope">The URI scope (spec 8.2), "local" by default.</param>
    /// <param name="senderCount">Sender threads and sockets; packets are sharded by sender lane (the universe for levels).</param>
    /// <param name="multicastLoopback">Deliver our own multicast to sockets on this host (tests, loopback demos).</param>
    /// <param name="replayTableCapacity">Sender-ID records to track, at least 32 (spec 8.6 step 10c).</param>
    public SigNetClient(
        SigNetKeys keys,
        Tuid tuid,
        SigNetDeviceInfo deviceInfo,
        ISessionIdStore sessionIdStore,
        IPAddress localAddress,
        Func<ReceiveDataPacket, Task>? channelWriter = null,
        Action? channelWriterComplete = null,
        string scope = SigNetUri.DefaultScope,
        int port = DefaultPort,
        int senderCount = 1,
        bool multicastLoopback = false,
        int replayTableCapacity = ReplayProtection.MinimumCapacity,
        TimeProvider? timeProvider = null)
        // Arguments are checked first: the base constructor starts the sender threads
        : base(CheckArguments(keys, tuid, deviceInfo, sessionIdStore, localAddress, scope, port), DeliveryRelay.Create(channelWriter, out var relay), channelWriterComplete, senderCount)
    {
        this.keys = keys;
        Tuid = tuid;
        Scope = scope;
        this.deviceInfo = deviceInfo;
        this.sessionIdStore = sessionIdStore;
        this.relay = relay;
        this.timeProvider = timeProvider ?? TimeProvider.System;
        this.localEndPoint = new IPEndPoint(localAddress, port);
        this.verifier = new SigNetPacketVerifier(keys, scope, tuid, new ReplayProtection(replayTableCapacity, this.timeProvider), this.timeProvider);
        this.sendSockets = new Socket[SenderCount];

        this.levelPacketWriter = WritePendingLevelPacket;
        this.pendingSendDataFactory = BuildPendingSendData;

        try
        {
            // Spec 8.3: increment and persist before the first packet
            StartSession();

            for (int i = 0; i < SenderCount; i++)
            {
                var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                this.sendSockets[i] = socket;

                socket.SendBufferSize = SendBufferSize;
                Haukcode.Network.Utils.SetSocketOptions(socket);
                socket.DontFragment = true;
                socket.MulticastLoopback = multicastLoopback;
                socket.Bind(new IPEndPoint(localAddress, 0));
                socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, MulticastTtl);
                if (!localAddress.Equals(IPAddress.Any))
                    socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, localAddress.GetAddressBytes());
            }

            StartReceive();

            // Polls are answered by every role (spec 10.2.3); Nodes also take multicast commands (spec 9.2.2)
            AddMembership(SigNetMulticast.ManagerPoll);
            if (deviceInfo.Roles.HasFlag(SigNetRoles.Node))
                AddMembership(SigNetMulticast.ManagerSend);

            this.lastPollTimestamp = this.timeProvider.GetTimestamp();
            this.lastAnnounceTimestamp = this.lastPollTimestamp;
            this.housekeepingTimer = this.timeProvider.CreateTimer(_ => Housekeeping(), null, HousekeepingInterval, HousekeepingInterval);

            ScheduleOnBootNotification();
        }
        catch
        {
            // Stop the sender threads and close what was opened, or they outlive the failed constructor
            Dispose();
            throw;
        }
    }

    private static int CheckArguments(SigNetKeys keys, Tuid tuid, SigNetDeviceInfo deviceInfo, ISessionIdStore sessionIdStore, IPAddress localAddress, string scope, int port)
    {
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(deviceInfo);
        ArgumentNullException.ThrowIfNull(sessionIdStore);
        ArgumentNullException.ThrowIfNull(localAddress);
        SigNetUri.CheckScope(scope);
        if (tuid.IsReserved)
            throw new ArgumentException("Device ids 0xFFFFFFF0 to 0xFFFFFFFF are reserved (spec 6.6)", nameof(tuid));
        if (port <= 0 || port > IPEndPoint.MaxPort)
            throw new ArgumentException("Invalid port", nameof(port));

        return PacketBufferSize;
    }

    public Tuid Tuid { get; }

    public string Scope { get; }

    public IPEndPoint LocalEndPoint => this.localEndPoint;

    /// <summary>
    /// What discovery replies report. Replace it (records are immutable) when a label or endpoint
    /// changes; the host owns CHANGE_COUNT.
    /// </summary>
    public SigNetDeviceInfo DeviceInfo
    {
        get => this.deviceInfo;
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            if (value.SoemCode != this.deviceInfo.SoemCode)
                throw new ArgumentException("The SoemCode cannot change while running", nameof(value));

            this.deviceInfo = value;
        }
    }

    /// <summary>
    /// The receive-side anti-replay table, e.g. to <see cref="ReplayProtection.Forget"/> a device
    /// that recovered from Session ID exhaustion.
    /// </summary>
    public ReplayProtection ReplayProtection => this.verifier.ReplayProtection;

    /// <summary>
    /// A joined universe went 3 s without a valid TID_LEVEL from a sender (spec 10.6.4).
    /// </summary>
    public IObservable<UniverseLostEvent> OnUniverseLost => this.universeLostSubject.AsObservable();

    /// <summary>
    /// Every detected security event (HMAC failure, replay, table saturation), before the
    /// one-per-second network rate limit of spec 10.9.3. Count is the running total for the code.
    /// </summary>
    public IObservable<SecurityEvent> OnSecurityEvent => this.securityEventSubject.AsObservable();

    /// <summary>
    /// True when packets are stamped by the kernel on arrival (Linux SO_TIMESTAMPNS, Windows
    /// SIO_TIMESTAMPING, macOS SO_TIMESTAMP) rather than by the receive loop.
    /// </summary>
    public bool KernelReceiveTimestampsActive => this.timestampedReceiver != null;

    /// <summary>
    /// True once a received packet actually carried a kernel timestamp. On Windows the socket
    /// option can be accepted while the adapter driver never stamps, so this is the
    /// after-the-fact answer where <see cref="KernelReceiveTimestampsActive"/> only means requested.
    /// </summary>
    public bool KernelReceiveTimestampsObserved => this.timestampedReceiver?.KernelTimestampsObserved == true;

    /// <summary>
    /// The receive buffer the OS granted, or null while not receiving.
    /// </summary>
    public int? ActualReceiveBufferSize
    {
        get
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                // Linux reports the internal buffer size, which is double the requested size
                return this.listenSocket?.ReceiveBufferSize / 2;
            else
                return this.listenSocket?.ReceiveBufferSize;
        }
    }

    /// <summary>
    /// How many received datagrams ended with each verification result since the client started.
    /// </summary>
    public IReadOnlyDictionary<VerifyResult, long> GetVerifyCounts()
    {
        var counts = new Dictionary<VerifyResult, long>();
        foreach (var result in Enum.GetValues<VerifyResult>())
            counts[result] = Interlocked.Read(ref this.verifyCounts[(int)result]);

        return counts;
    }

    /// <summary>
    /// Restart the 2 s post-link-up window during which /manager SET commands are refused
    /// (spec 8.6.4), for a host that tracks the interface's link state.
    /// </summary>
    public void SignalLinkUp() => this.verifier.SignalLinkUp();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            this.lifetimeCts.Cancel();
            this.housekeepingTimer?.Dispose();
        }

        base.Dispose(disposing);

        if (disposing)
        {
            foreach (var socket in this.sendSockets ?? [])
            {
                if (socket == null)
                    continue;

                try
                {
                    socket.Shutdown(SocketShutdown.Both);
                }
                catch
                {
                }

                socket.Close();
                socket.Dispose();
            }

            this.lifetimeCts.Dispose();
        }
    }

    /// <summary>
    /// For tests: sees every datagram before it is handed to the socket, and returns true to
    /// swallow it (a socket bound to 127.0.0.1 cannot send multicast on Windows).
    /// </summary>
    internal Func<IPEndPoint, byte[], bool>? SendInterceptor { get; set; }

    protected override int SendPacket(SendData sendData, ReadOnlyMemory<byte> payload, int senderIndex)
    {
        PaceSend(sendData.Kind);

        int sent = SendInterceptor?.Invoke(sendData.Destination, payload.ToArray()) == true
            ? payload.Length
            : this.sendSockets[senderIndex].SendTo(payload.Span, SocketFlags.None, sendData.DestinationAddress);

        NoteSent(sendData.Kind);

        return sent;
    }

    protected override int ReceiveData(Memory<byte> memory, out IPEndPoint? remoteEndPoint, out IPAddress? destinationAddress)
    {
        if (!MemoryMarshal.TryGetArray<byte>(memory, out var segment))
            throw new InvalidOperationException("Expected an array-backed receive buffer");

        if (this.timestampedReceiver != null)
        {
            int received = this.timestampedReceiver.Receive(segment, out remoteEndPoint, out destinationAddress, out long kernelTimestampNS);
            KernelReceiveTimestampNS = kernelTimestampNS;

            return received;
        }

        var socketFlags = SocketFlags.None;
        EndPoint endPoint = blankEndpoint;
        int receivedBytes = this.listenSocket!.ReceiveMessageFrom(segment.Array!, segment.Offset, segment.Count, ref socketFlags, ref endPoint, out IPPacketInformation packetInformation);

        remoteEndPoint = endPoint as IPEndPoint;
        destinationAddress = packetInformation.Address;

        return receivedBytes;
    }

    protected override void InitializeReceiveSocket()
    {
        this.listenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        this.listenSocket.ReceiveBufferSize = ReceiveBufferSize;

        Haukcode.Network.Utils.SetSocketOptions(this.listenSocket);

        // Linux wants IPAddress.Any to get unicast, multicast and broadcast
        this.listenSocket.Bind(new IPEndPoint(IPAddress.Any, this.localEndPoint.Port));

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            this.membershipSockets = [];

        this.timestampedReceiver = ReceiveTimestamping.TryCreate(this.listenSocket);
    }

    protected override void DisposeReceiveSocket()
    {
        try
        {
            this.listenSocket?.Shutdown(SocketShutdown.Both);
        }
        catch
        {
        }

        this.listenSocket?.Close();
        this.listenSocket?.Dispose();
        this.listenSocket = null;

        if (this.membershipSockets != null)
        {
            foreach (var socket in this.membershipSockets)
                socket.Dispose();

            this.membershipSockets = null;
        }

        lock (this.subscriptionLock)
        {
            this.memberships.Clear();
        }

        this.timestampedReceiver = null;
    }

    /// <summary>
    /// Join a multicast group, reference counted (folded universes share groups). Throws the
    /// SocketException when the kernel refuses; the caller decides what that means.
    /// </summary>
    private void AddMembership(IPAddress group)
    {
        lock (this.subscriptionLock)
        {
            ObjectDisposedException.ThrowIf(this.listenSocket == null, this);

            if (this.memberships.TryGetValue(group, out var existing))
            {
                this.memberships[group] = (existing.Socket, existing.References + 1);

                return;
            }

            var option = new MulticastOption(group, this.localEndPoint.Address);
            Socket socket;
            if (this.membershipSockets == null)
            {
                socket = this.listenSocket;
                socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, option);
            }
            else
            {
                socket = AddLinuxMembership(option);
            }

            this.memberships[group] = (socket, 1);
        }
    }

    private Socket AddLinuxMembership(MulticastOption option)
    {
        if (this.membershipSockets!.Count > 0)
        {
            var current = this.membershipSockets[^1];
            try
            {
                current.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, option);

                return current;
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.NoBufferSpaceAvailable)
            {
                // This socket hit igmp_max_memberships; continue on a fresh one
            }
        }

        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, option);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        this.membershipSockets.Add(socket);

        return socket;
    }

    private void DropMembership(IPAddress group)
    {
        lock (this.subscriptionLock)
        {
            if (!this.memberships.TryGetValue(group, out var existing))
                return;

            if (existing.References > 1)
            {
                this.memberships[group] = (existing.Socket, existing.References - 1);

                return;
            }

            this.memberships.Remove(group);
            try
            {
                existing.Socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.DropMembership, new MulticastOption(group, this.localEndPoint.Address));
            }
            catch (SocketException ex)
            {
                this.errorSubject.OnNext(ex);
            }
        }
    }

    private void CountVerifyResult(VerifyResult result)
    {
        Interlocked.Increment(ref this.verifyCounts[(int)result]);
    }
}
