using System.Collections.Concurrent;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Haukcode.SigNet.Model;

namespace Haukcode.SigNet;

// Sender role: levels, priority, sync, and the session and lane sequence counters
public partial class SigNetClient
{
    /// <summary>
    /// Minimum gap between the last level packet of a frame and the TID_SYNC (spec 10.7.1).
    /// </summary>
    public static readonly TimeSpan SyncDelay = TimeSpan.FromMilliseconds(5);

    /// <summary>
    /// The administrative lane: discovery replies, announcements and sync use Sender endpoint 0
    /// (spec 8.6.2).
    /// </summary>
    public const ushort AdminLane = 0;

    // Serializes everything that assigns a sequence number: the counters themselves, the pending*
    // arguments of the cached level writer, and the enqueue, so that per lane the order of
    // sequence numbers is the order on the send queue.
    private readonly object sendLock = new();

    // Per-lane sequence counters indexed by Sender endpoint: 0 for admin, the universe number for
    // its level stream (spec 8.6.2: one lane per stream, endpoints 0x0001 to 0xFF00).
    // TODO (spec 8.6.2): V1.16 has TID_LEVEL streams use the Device's data endpoints 1..N rather
    // than the universe; see TID_RT_ENDPOINT_COUNT in SigNetClient.Discovery.cs
    private readonly uint[] laneSequence = new uint[ushort.MaxValue + 1];
    private uint sessionId;
    private bool sessionExhausted;
    private ushort messageId;

    // Stopwatch timestamp of the last level datagram handed to a socket, for the sync gap
    private long lastLevelSentTimestamp;

    private readonly HashSet<ushort> activeUniverses = [];

    private readonly ConcurrentDictionary<IPAddress, IPEndPoint> endPointCache = new();
    private readonly ConcurrentDictionary<IPEndPoint, System.Net.SocketAddress> socketAddressCache = new();

    // Arguments of the cached level writer and send-data factory, set under sendLock right before
    // QueuePacket, which calls both synchronously
    private readonly Func<Memory<byte>, int> levelPacketWriter;
    private readonly Func<SendData> pendingSendDataFactory;
    private IPEndPoint pendingDestination = null!;
    private SigNetPath pendingPath;
    private SigNetSecurityHeader pendingHeader;
    private ushort pendingMessageId;
    private ReadOnlyMemory<byte> pendingLevels;
    private ReadOnlyMemory<byte> pendingSlotPriorities;
    private byte pendingUniversePriority;
    private bool pendingHasUniversePriority;

    /// <summary>
    /// The session id in use (spec 8.3).
    /// </summary>
    public uint SessionId
    {
        get
        {
            lock (this.sendLock)
            {
                return this.sessionId;
            }
        }
    }

    /// <summary>
    /// Universes this client is currently transmitting (announced with TID_UNIVERSE Join).
    /// </summary>
    public IReadOnlyCollection<ushort> ActiveUniverses
    {
        get
        {
            lock (this.sendLock)
            {
                return [.. this.activeUniverses];
            }
        }
    }

    /// <summary>
    /// Send one frame of levels to a universe: TID_PRIORITY (when given) before TID_LEVEL in one
    /// packet (spec 10.6), to the universe's folded multicast group, signed with Ks. The first
    /// frame for a universe also announces it with TID_UNIVERSE (spec 11.2.6).
    ///
    /// Pacing is the caller's: at most 44 frames per second by default, three identical frames
    /// when the data stops changing, then a full keep-alive frame at least once a second
    /// (spec 10.6.3). <see cref="LevelRefreshPolicy"/> implements the repeat and keep-alive rules.
    /// </summary>
    /// <param name="levels">1 to 512 slots, zero start code.</param>
    /// <param name="priority">Universe priority 0-200 as a 1-byte TID_PRIORITY, or null to send none.</param>
    /// <param name="destination">Unicast to one node instead of multicast (allowed, but discouraged by spec 10.6.2).</param>
    /// <param name="important">Never dropped by the send queue's age cut-off or bound.</param>
    public Task SendLevels(ushort universe, ReadOnlyMemory<byte> levels, byte? priority = null, IPAddress? destination = null, bool important = false)
    {
        if (priority > 200)
            throw new ArgumentOutOfRangeException(nameof(priority), priority, "Priority must be 0-200");

        return SendLevelsCore(universe, levels, ReadOnlyMemory<byte>.Empty, priority, destination, important);
    }

    /// <summary>
    /// Send levels with per-slot priority (ETC 0xDD style): <paramref name="slotPriorities"/> maps
    /// to slots from slot 1, values 0-200; slots it does not cover have priority 0 (spec 11.2.2).
    /// Receivers using the Constrained Node Fallback only use the first byte.
    /// </summary>
    public Task SendLevels(ushort universe, ReadOnlyMemory<byte> levels, ReadOnlyMemory<byte> slotPriorities, IPAddress? destination = null, bool important = false)
    {
        if (slotPriorities.Length < 1 || slotPriorities.Length > 512)
            throw new ArgumentOutOfRangeException(nameof(slotPriorities), slotPriorities.Length, "1 to 512 priority values");

        foreach (byte value in slotPriorities.Span)
        {
            if (value > 200)
                throw new ArgumentOutOfRangeException(nameof(slotPriorities), value, "Priority values must be 0-200");
        }

        return SendLevelsCore(universe, levels, slotPriorities, null, destination, important);
    }

    private Task SendLevelsCore(ushort universe, ReadOnlyMemory<byte> levels, ReadOnlyMemory<byte> slotPriorities, byte? universePriority, IPAddress? destination, bool important)
    {
        SigNetMulticast.CheckUniverse(universe);
        if (levels.Length < 1 || levels.Length > 512)
            throw new ArgumentOutOfRangeException(nameof(levels), levels.Length, "1 to 512 slots");

        if (!IsOperational)
            return Task.CompletedTask;

        lock (this.sendLock)
        {
            if (this.activeUniverses.Add(universe))
                QueueUniverseAnnouncementLocked([new UniverseAnnouncement(universe, UniverseCommand.Join, null, universe)]);

            NextSequenceLocked(universe, out uint session, out uint sequence);

            this.pendingPath = SigNetPath.Level(Scope, universe);
            this.pendingHeader = new SigNetSecurityHeader(SecurityMode.HmacSha256, new SenderId(Tuid, universe), 0, session, sequence);
            this.pendingMessageId = ++this.messageId;
            this.pendingLevels = levels;
            this.pendingSlotPriorities = slotPriorities;
            this.pendingHasUniversePriority = universePriority.HasValue;
            this.pendingUniversePriority = universePriority ?? 0;
            this.pendingDestination = ResolveDestination(this.pendingPath, destination);

            int payloadLength = TlvReader.HeaderLength + levels.Length +
                (slotPriorities.IsEmpty ? (universePriority.HasValue ? TlvReader.HeaderLength + 1 : 0) : TlvReader.HeaderLength + slotPriorities.Length);

            return QueuePacket(SigNetPacketWriter.GetMaxLength(payloadLength), important, this.pendingSendDataFactory, this.levelPacketWriter, shardKey: universe).AsTask();
        }
    }

    /// <summary>
    /// Stop transmitting a universe: announces TID_UNIVERSE Leave. Sending levels again rejoins.
    /// </summary>
    public void StopUniverse(ushort universe)
    {
        SigNetMulticast.CheckUniverse(universe);

        lock (this.sendLock)
        {
            if (this.activeUniverses.Remove(universe) && IsOperational)
                QueueUniverseAnnouncementLocked([new UniverseAnnouncement(universe, UniverseCommand.Leave, null, universe)]);
        }
    }

    /// <summary>
    /// Stop transmitting every active universe: one TID_UNIVERSE Leave announcement covering all
    /// of them. Call it before <see cref="Client{TSendData,TPacketType}.Dispose()"/> when stopping
    /// gracefully; disposing alone does not announce anything.
    /// </summary>
    public void StopAllUniverses()
    {
        lock (this.sendLock)
        {
            if (this.activeUniverses.Count == 0)
                return;

            var announcements = new List<UniverseAnnouncement>(this.activeUniverses.Count);
            foreach (ushort universe in this.activeUniverses)
                announcements.Add(new UniverseAnnouncement(universe, UniverseCommand.Leave, null, universe));

            this.activeUniverses.Clear();

            if (IsOperational)
                QueueUniverseAnnouncementLocked(announcements);
        }
    }

    /// <summary>
    /// Send TID_SYNC to /sync on &lt;mult_time&gt;, signed with Ks (spec 10.7.1). It goes out as an
    /// ordering barrier, so it cannot overtake level packets still queued on any sender shard, and
    /// the sender thread holds it until at least 5 ms after the last level datagram was handed to
    /// the socket.
    /// </summary>
    public Task SendSync(IPAddress? destination = null)
    {
        if (!IsOperational)
            return Task.CompletedTask;

        lock (this.sendLock)
        {
            var path = SigNetPath.Sync(Scope);
            NextSequenceLocked(AdminLane, out uint session, out uint sequence);
            var header = new SigNetSecurityHeader(SecurityMode.HmacSha256, new SenderId(Tuid, AdminLane), 0, session, sequence);
            ushort id = ++this.messageId;
            var target = ResolveDestination(path, destination);

            // Barrier: with more than one shard, it waits until every other shard has drained
            return QueueBarrierPacket(SigNetPacketWriter.GetMaxLength(0), () => BuildSendData(target, SendKind.Sync),
                memory => SigNetPacketWriter.Write(memory.Span, id, path, header, ReadOnlySpan<byte>.Empty, this.keys.SenderKey),
                shardKey: AdminLane).AsTask();
        }
    }

    /// <summary>
    /// Queue a signed packet on a lane: assigns the lane's next sequence number and keeps the
    /// lane's packets on one shard. Called under sendLock.
    /// </summary>
    private void QueueSignedLocked(SigNetPath path, ushort lane, byte[] payload, IPAddress? destination = null)
    {
        if (!IsOperational)
            return;

        NextSequenceLocked(lane, out uint session, out uint sequence);
        var header = new SigNetSecurityHeader(SecurityMode.HmacSha256, new SenderId(Tuid, lane), 0, session, sequence);
        ushort id = ++this.messageId;
        var target = ResolveDestination(path, destination);
        var role = path.KeyRole;

        QueuePacket(SigNetPacketWriter.GetMaxLength(payload.Length), important: true, () => BuildSendData(target),
            memory => SigNetPacketWriter.Write(memory.Span, id, path, header, payload, this.keys.GetKey(role)),
            shardKey: lane);
    }

    private void QueueSigned(SigNetPath path, ushort lane, byte[] payload, IPAddress? destination = null)
    {
        lock (this.sendLock)
        {
            QueueSignedLocked(path, lane, payload, destination);
        }
    }

    private int WritePendingLevelPacket(Memory<byte> memory)
    {
        Span<byte> payload = stackalloc byte[Coap.MaxPayloadLength];
        var writer = new TlvWriter(payload);

        // Priority first so a node has the context before the levels (spec 10.6)
        if (!this.pendingSlotPriorities.IsEmpty)
            writer.Write(Tid.Priority, this.pendingSlotPriorities.Span);
        else if (this.pendingHasUniversePriority)
            writer.WriteByte(Tid.Priority, this.pendingUniversePriority);

        writer.Write(Tid.Level, this.pendingLevels.Span);

        return SigNetPacketWriter.Write(memory.Span, this.pendingMessageId, this.pendingPath, this.pendingHeader, writer.Written, this.keys.SenderKey);
    }

    private SendData BuildPendingSendData() => BuildSendData(this.pendingDestination, SendKind.Level);

    private SendData BuildSendData(IPEndPoint destination, SendKind kind = SendKind.Other)
    {
        var pooled = RentSendData();
        if (pooled != null)
        {
            pooled.Destination = destination;
            pooled.DestinationAddress = this.socketAddressCache.GetOrAdd(destination, static endPoint => endPoint.Serialize());
            pooled.Kind = kind;

            return pooled;
        }

        return new SendData(destination) { Kind = kind };
    }

    /// <summary>
    /// On the sender thread, before a datagram goes out: hold a sync until 5 ms after the last
    /// level datagram, and note when level datagrams leave.
    /// </summary>
    private void PaceSend(SendKind kind)
    {
        if (kind == SendKind.Sync)
        {
            long last = Interlocked.Read(ref this.lastLevelSentTimestamp);
            if (last == 0)
                return;

            long due = last + (long)(SyncDelay.TotalSeconds * System.Diagnostics.Stopwatch.Frequency);
            while (System.Diagnostics.Stopwatch.GetTimestamp() < due)
            {
                long remaining = due - System.Diagnostics.Stopwatch.GetTimestamp();
                if (remaining > System.Diagnostics.Stopwatch.Frequency / 500)
                    Thread.Sleep(1);
                else
                    Thread.SpinWait(100);
            }
        }
    }

    private void NoteSent(SendKind kind)
    {
        if (kind == SendKind.Level)
            Interlocked.Exchange(ref this.lastLevelSentTimestamp, System.Diagnostics.Stopwatch.GetTimestamp());
    }

    /// <summary>
    /// The URI decides the multicast group (spec 9.2.1); a unicast address overrides it.
    /// </summary>
    private IPEndPoint ResolveDestination(in SigNetPath path, IPAddress? destination)
    {
        var address = destination != null && !Haukcode.Network.Utils.IsMulticast(destination) ? destination : SigNetMulticast.GetAddress(path);

        return this.endPointCache.GetOrAdd(address, static (address, port) => new IPEndPoint(address, port), this.localEndPoint.Port);
    }

    private void StartSession()
    {
        lock (this.sendLock)
        {
            uint stored = this.sessionIdStore.LoadSessionId();
            this.sessionId = AdvanceSessionId(stored);
        }
    }

    // Next value, saved before use (spec 8.3). 0xFFFFFFFF is the exhausted state, never used.
    private uint AdvanceSessionId(uint current)
    {
        if (current >= uint.MaxValue - 1)
        {
            this.sessionExhausted = true;

            throw new SessionIdExhaustedException();
        }

        uint next = current + 1;
        this.sessionIdStore.SaveSessionId(next);

        return next;
    }

    private void NextSequenceLocked(ushort lane, out uint session, out uint sequence)
    {
        if (this.sessionExhausted)
            throw new SessionIdExhaustedException();

        uint next = this.laneSequence[lane] + 1;

        // TODO (spec 8.3): "when the counter reaches 0xFFFFFFFF" is read as 0xFFFFFFFF never being
        // sent: the session advances and every lane restarts at 1.
        if (next == uint.MaxValue)
        {
            this.sessionId = AdvanceSessionId(this.sessionId);
            Array.Clear(this.laneSequence);
            next = 1;
        }

        this.laneSequence[lane] = next;
        session = this.sessionId;
        sequence = next;
    }

    /// <summary>
    /// For tests: start a lane just below the wrap point.
    /// </summary>
    internal void SetLaneSequenceForTest(ushort lane, uint value)
    {
        lock (this.sendLock)
        {
            this.laneSequence[lane] = value;
        }
    }
}
