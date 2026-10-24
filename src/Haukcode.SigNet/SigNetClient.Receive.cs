using System.Net;
using Haukcode.SigNet.Model;
using Haukcode.SigNet.Security;

namespace Haukcode.SigNet;

// Receive side of the Node role: verified levels, priority, sync hold-and-release, stream loss
public partial class SigNetClient
{
    /// <summary>
    /// &lt;sync_lost_timeout&gt; (spec 10.7.3, Appendix B).
    /// </summary>
    public static readonly TimeSpan SyncLostTimeout = TimeSpan.FromMilliseconds(250);

    /// <summary>
    /// &lt;universe_lost_timeout&gt; (spec 10.6.4, Appendix B).
    /// </summary>
    public static readonly TimeSpan UniverseLostTimeout = TimeSpan.FromSeconds(3);

    /// <summary>
    /// Priority assumed when a sender has not sent TID_PRIORITY this session (spec 10.6).
    /// </summary>
    public const byte DefaultPriority = 100;

    private sealed class StreamState
    {
        public uint SessionId;
        public byte Priority = DefaultPriority;
        public bool HasPriority;
        public long LastSeenTimestamp;

        // The latest frame held while the sender is in SYNC_ACTIVE
        public readonly byte[] Held = new byte[512];
        public int HeldLength;
        public bool HeldValid;
        public double HeldTimestampMS;
        public IPEndPoint HeldSource = null!;
        public IPEndPoint? HeldDestination;
        public uint HeldSequence;
    }

    private sealed class SyncState
    {
        public bool Active;
        public long LastSyncTimestamp;
    }

    // What each universe is joined for, indexed by universe id. Written under subscriptionLock,
    // read on the receive thread without it (whole-element writes).
    private readonly SubscribeModes[] subscriptions = new SubscribeModes[ushort.MaxValue + 1];
    private int subscribedUniverseCount;

    // Receive state, guarded by relay.Lock: keyed by (Sender-ID, universe) and by sender TUID
    private readonly Dictionary<(ulong SenderId, ushort Universe), StreamState> streams = [];
    private readonly Dictionary<ulong, SyncState> syncStates = [];

    private readonly SigNetPacket receivePacket = new();
    private readonly ReceiveDataPacket receiveScratch = new();
    private readonly ReceiveDataPacket releaseScratch = new();
    private readonly Dictionary<IPAddress, IPEndPoint?> receiveDestinationCache = [];

    /// <summary>
    /// Receive a universe as input: joins its folded multicast group (shared with every universe
    /// 109 apart) and, for the first subscribed universe, &lt;mult_time&gt; for sync. Packets for
    /// universes that are not subscribed are discarded by URI even when they arrive on a shared
    /// group (spec 9.2.3). Throws if the universe is already joined as input.
    ///
    /// If the kernel refuses the multicast join (IGMP membership cap), the universe still counts
    /// as joined, so unicast to it is received, and the SocketException is thrown.
    /// </summary>
    public void JoinUniverse(ushort universe)
    {
        SigNetMulticast.CheckUniverse(universe);
        ObjectDisposedException.ThrowIf(this.listenSocket == null, this);

        lock (this.subscriptionLock)
        {
            if ((this.subscriptions[universe] & SubscribeModes.DmxData) != 0)
                throw new InvalidOperationException($"Universe {universe} is already joined");

            Subscribe(universe, SubscribeModes.DmxData);
        }
    }

    /// <summary>
    /// Stop receiving a universe as input. Throws if it is not joined as input; the multicast
    /// group is left once nothing else needs it.
    /// </summary>
    public void DropUniverse(ushort universe)
    {
        if (this.listenSocket == null)
            return;

        lock (this.subscriptionLock)
        {
            if ((this.subscriptions[universe] & SubscribeModes.DmxData) == 0)
                throw new InvalidOperationException($"Universe {universe} is not joined");

            Unsubscribe(universe, SubscribeModes.DmxData);
        }
    }

    /// <summary>
    /// Receive a universe for triggers. Joining again is fine; input and trigger subscriptions
    /// to the same universe are independent.
    /// </summary>
    public void JoinUniverseForTrigger(ushort universe)
    {
        SigNetMulticast.CheckUniverse(universe);
        ObjectDisposedException.ThrowIf(this.listenSocket == null, this);

        lock (this.subscriptionLock)
        {
            if ((this.subscriptions[universe] & SubscribeModes.Trigger) == 0)
                Subscribe(universe, SubscribeModes.Trigger);
        }
    }

    /// <summary>
    /// Stop receiving a universe for triggers. Dropping one that is not joined is fine.
    /// </summary>
    public void DropUniverseForTrigger(ushort universe)
    {
        if (this.listenSocket == null)
            return;

        lock (this.subscriptionLock)
        {
            if ((this.subscriptions[universe] & SubscribeModes.Trigger) != 0)
                Unsubscribe(universe, SubscribeModes.Trigger);
        }
    }

    public void DropAllInputUniverses() => DropAll(SubscribeModes.DmxData);

    public void DropAllTriggerUniverses() => DropAll(SubscribeModes.Trigger);

    /// <summary>
    /// True when the universe is joined as input.
    /// </summary>
    public bool IsJoined(ushort universe) => (this.subscriptions[universe] & SubscribeModes.DmxData) != 0;

    /// <summary>
    /// What the universe is currently joined for.
    /// </summary>
    public SubscribeModes GetSubscription(ushort universe) => this.subscriptions[universe];

    // Add a mode, joining the groups if nothing had subscribed the universe. Called under subscriptionLock.
    private void Subscribe(ushort universe, SubscribeModes mode)
    {
        var current = this.subscriptions[universe];
        this.subscriptions[universe] = current | mode;

        if (current != SubscribeModes.None)
            return;

        if (++this.subscribedUniverseCount == 1)
            AddMembership(SigNetMulticast.Time);

        AddMembership(SigNetMulticast.GetUniverseAddress(universe));
    }

    // Remove a mode, leaving the groups once nothing needs them. Called under subscriptionLock.
    private void Unsubscribe(ushort universe, SubscribeModes mode)
    {
        var remaining = this.subscriptions[universe] & ~mode;
        this.subscriptions[universe] = remaining;

        if (remaining != SubscribeModes.None)
            return;

        DropMembership(SigNetMulticast.GetUniverseAddress(universe));
        if (--this.subscribedUniverseCount == 0)
            DropMembership(SigNetMulticast.Time);
    }

    private void DropAll(SubscribeModes mode)
    {
        if (this.listenSocket == null)
            return;

        lock (this.subscriptionLock)
        {
            for (int universe = SigNetUri.MinUniverse; universe <= SigNetUri.MaxUniverse; universe++)
            {
                if ((this.subscriptions[universe] & mode) != 0)
                    Unsubscribe((ushort)universe, mode);
            }
        }
    }

    protected override ReceiveDataPacket? TryParseObject(ReadOnlyMemory<byte> buffer, double timestampMS, IPEndPoint sourceIP, IPAddress destinationIP)
    {
        var result = this.verifier.Verify(buffer, this.receivePacket, out var path);
        CountVerifyResult(result);

        if (result != VerifyResult.Accepted)
        {
            ReportRejected(result, sourceIP.Address);

            return null;
        }

        switch (path.Resource)
        {
            case SigNetResource.Level:
                return ReceiveLevels(path.Index, timestampMS, sourceIP, destinationIP);

            case SigNetResource.Sync:
                return ReceiveSync(timestampMS, sourceIP, destinationIP);

            case SigNetResource.Poll:
                ReceivePoll(this.receivePacket.Payload.Span);
                break;

            case SigNetResource.Manager:
                ReceiveManagerCommand(path.Endpoint, this.receivePacket.Payload.Span);
                break;
        }

        return null;
    }

    // TODO (spec 11.8.1): code 0x0002 "Replay Attack Detected" overlaps 0x0006 (session regression),
    // 0x0007 (sequence violation) and 0x0005 (table saturated). The specific code is reported, and
    // 0x0002 as well, since the SDK and the managers built on it only know 0x0002.
    private void ReportRejected(VerifyResult result, IPAddress source)
    {
        var code = result switch
        {
            VerifyResult.HmacFailure => SecurityEventCode.HmacFailure,
            VerifyResult.EpochRegression => SecurityEventCode.EpochRegression,
            VerifyResult.SequenceReplay => SecurityEventCode.SequenceViolation,
            VerifyResult.TableSaturated => SecurityEventCode.SenderTableSaturated,
            _ => (SecurityEventCode)0
        };

        if (code == 0)
            return;

        RaiseSecurityEvent(code, source);
        if (code != SecurityEventCode.HmacFailure)
            RaiseSecurityEvent(SecurityEventCode.ReplayDetected, source);
    }

    private ReceiveDataPacket? ReceiveLevels(ushort universe, double timestampMS, IPEndPoint source, IPAddress destinationIP)
    {
        // Folded groups carry other universes too; the URI is the filter (spec 9.2.3)
        var subscription = this.subscriptions[universe];
        if (subscription == SubscribeModes.None)
            return null;

        ReadOnlySpan<byte> priority = default;
        bool hasPriority = false;
        ReadOnlyMemory<byte> levels = default;
        bool hasLevels = false;

        var payload = this.receivePacket.Payload;
        var reader = new TlvReader(payload.Span);
        int offset = 0;
        while (reader.TryRead(out ushort tid, out var value))
        {
            offset += TlvReader.HeaderLength;
            if (tid == Tid.Priority)
            {
                priority = value;
                hasPriority = true;
            }
            else if (tid == Tid.Level)
            {
                levels = payload.Slice(offset, value.Length);
                hasLevels = true;
            }

            offset += value.Length;
        }

        var header = this.receivePacket.Header;
        var destination = ResolveReceiveDestination(destinationIP);

        lock (this.relay.Lock)
        {
            var key = (header.SenderId.Value, universe);
            if (!this.streams.TryGetValue(key, out var stream))
            {
                stream = new StreamState { SessionId = header.SessionId };
                this.streams.Add(key, stream);
            }

            // Priority holds until updated or until the sender's session changes (spec 10.6)
            if (stream.SessionId != header.SessionId)
            {
                stream.SessionId = header.SessionId;
                stream.Priority = DefaultPriority;
                stream.HasPriority = false;
            }

            // Constrained Node Fallback: the first byte is the universe priority (spec 10.6)
            if (hasPriority)
            {
                stream.Priority = priority[0];
                stream.HasPriority = true;
            }

            if (!hasLevels)
                return null;

            stream.LastSeenTimestamp = this.timeProvider.GetTimestamp();

            if (this.syncStates.TryGetValue(header.SenderId.Tuid.Value, out var sync) && sync.Active)
            {
                // SYNC_ACTIVE: hold until this sender's next TID_SYNC (spec 10.7.2)
                levels.Span.CopyTo(stream.Held);
                stream.HeldLength = levels.Length;
                stream.HeldValid = true;
                stream.HeldTimestampMS = timestampMS;
                stream.HeldSource = source;
                stream.HeldDestination = destination;
                stream.HeldSequence = header.SequenceNumber;

                return null;
            }

            var packet = this.receiveScratch;
            packet.Kind = ReceiveDataKind.Levels;
            packet.TimestampMS = timestampMS;
            packet.Source = source;
            packet.Destination = destination;
            packet.SenderId = header.SenderId;
            packet.SessionId = header.SessionId;
            packet.SequenceNumber = header.SequenceNumber;
            packet.Universe = universe;
            packet.Levels = levels;
            packet.Priority = stream.Priority;
            packet.HasPriority = stream.HasPriority;
            packet.Synchronized = false;
            packet.SubscribeMode = subscription;

            return packet;
        }
    }

    // TODO (spec 10.7.2): sync is matched to "the active Sender" by the full 8-byte Sender-ID, but
    // each universe is its own lane (endpoint) and TID_SYNC carries one Sender-ID, so a full match
    // could only ever cover one universe. Sync is matched by sender TUID instead, and senders here
    // send it on the admin lane.
    private ReceiveDataPacket? ReceiveSync(double timestampMS, IPEndPoint source, IPAddress destinationIP)
    {
        var header = this.receivePacket.Header;
        ulong tuid = header.SenderId.Tuid.Value;

        lock (this.relay.Lock)
        {
            if (!this.syncStates.TryGetValue(tuid, out var sync))
            {
                sync = new SyncState();
                this.syncStates.Add(tuid, sync);
            }

            if (sync.Active)
                ReleaseHeldLocked(tuid);

            sync.Active = true;
            sync.LastSyncTimestamp = this.timeProvider.GetTimestamp();

            var packet = this.receiveScratch;
            packet.Kind = ReceiveDataKind.Sync;
            packet.TimestampMS = timestampMS;
            packet.Source = source;
            packet.Destination = ResolveReceiveDestination(destinationIP);
            packet.SenderId = header.SenderId;
            packet.SessionId = header.SessionId;
            packet.SequenceNumber = header.SequenceNumber;
            packet.Universe = 0;
            packet.Levels = ReadOnlyMemory<byte>.Empty;
            packet.Priority = 0;
            packet.HasPriority = false;
            packet.Synchronized = true;
            packet.SubscribeMode = SubscribeModes.None;

            return packet;
        }
    }

    // Deliver every frame held for a sender. Called under relay.Lock.
    private void ReleaseHeldLocked(ulong tuid)
    {
        foreach (var ((senderIdValue, universe), stream) in this.streams)
        {
            if (!stream.HeldValid || SenderId.FromValue(senderIdValue).Tuid.Value != tuid)
                continue;

            stream.HeldValid = false;

            var packet = this.releaseScratch;
            packet.Kind = ReceiveDataKind.Levels;
            packet.TimestampMS = stream.HeldTimestampMS;
            packet.Source = stream.HeldSource;
            packet.Destination = stream.HeldDestination;
            packet.SenderId = SenderId.FromValue(senderIdValue);
            packet.SessionId = stream.SessionId;
            packet.SequenceNumber = stream.HeldSequence;
            packet.Universe = universe;
            packet.Levels = stream.Held.AsMemory(0, stream.HeldLength);
            packet.Priority = stream.Priority;
            packet.HasPriority = stream.HasPriority;
            packet.Synchronized = true;
            packet.SubscribeMode = this.subscriptions[universe];

            try
            {
                this.relay.DeliverLocked(packet);
            }
            catch (Exception ex)
            {
                this.errorSubject.OnNext(ex);
            }
        }
    }

    /// <summary>
    /// Sync timeout and stream loss, run from the housekeeping timer.
    /// </summary>
    private void CheckReceiveTimeouts()
    {
        List<UniverseLostEvent>? lost = null;

        lock (this.relay.Lock)
        {
            foreach (var (tuid, sync) in this.syncStates)
            {
                // No sync for 250 ms: back to asynchronous output, flushing what was held (spec 10.7.3)
                if (sync.Active && this.timeProvider.GetElapsedTime(sync.LastSyncTimestamp) >= SyncLostTimeout)
                {
                    sync.Active = false;
                    ReleaseHeldLocked(tuid);
                }
            }

            List<(ulong, ushort)>? expired = null;
            foreach (var (key, stream) in this.streams)
            {
                if (this.timeProvider.GetElapsedTime(stream.LastSeenTimestamp) >= UniverseLostTimeout)
                {
                    (expired ??= []).Add(key);
                    (lost ??= []).Add(new UniverseLostEvent(key.Universe, SenderId.FromValue(key.SenderId)));
                }
            }

            if (expired != null)
            {
                foreach (var key in expired)
                    this.streams.Remove(key);
            }

            if (this.syncStates.Count > 0 && this.streams.Count == 0)
            {
                List<ulong>? idle = null;
                foreach (var (tuid, sync) in this.syncStates)
                {
                    if (!sync.Active)
                        (idle ??= []).Add(tuid);
                }

                if (idle != null)
                {
                    foreach (var tuid in idle)
                        this.syncStates.Remove(tuid);
                }
            }
        }

        if (lost != null)
        {
            foreach (var item in lost)
                this.universeLostSubject.OnNext(item);
        }
    }

    // TID_EP_STATUS bits from the streams currently feeding a universe
    private uint GetEndpointStatus(ushort universe)
    {
        if (universe == 0)
            return 0;

        int sources = 0;
        lock (this.relay.Lock)
        {
            foreach (var key in this.streams.Keys)
            {
                if (key.Universe == universe)
                    sources++;
            }
        }

        uint status = 0;
        if (sources > 0)
            status |= 0x01 | 0x08;
        if (sources > 1)
            status |= 0x10;

        return status;
    }

    private IPEndPoint? ResolveReceiveDestination(IPAddress destinationIP)
    {
        // Only touched on the receive thread
        if (!this.receiveDestinationCache.TryGetValue(destinationIP, out var destination))
        {
            destination = Haukcode.Network.Utils.IsMulticast(destinationIP) ? null : new IPEndPoint(destinationIP, this.localEndPoint.Port);
            this.receiveDestinationCache.Add(destinationIP, destination);
        }

        return destination;
    }
}
