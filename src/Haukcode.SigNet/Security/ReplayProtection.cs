namespace Haukcode.SigNet.Security;

public enum FreshnessResult
{
    /// <summary>Known sender, newer session or higher sequence number.</summary>
    Fresh = 0,

    /// <summary>No record for this TUID: accepted as the new baseline (spec 8.6.3).</summary>
    Bootstrap,

    /// <summary>Session id lower than recorded for the TUID (spec 8.6 step 8a, event 0x0006).</summary>
    EpochRegression,

    /// <summary>Same session, sequence number not above the recorded one (step 8b, event 0x0007).</summary>
    SequenceReplay,

    /// <summary>New Sender-ID, table full and the LRU entry younger than an hour (step 10c, event 0x0005).</summary>
    TableSaturated
}

/// <summary>
/// Receive-side anti-replay state of spec 8.6 steps 7 to 10: session ids tracked per sender TUID,
/// sequence numbers per 8-byte Sender-ID (one lane per endpoint), RAM only.
///
/// Use it in two phases around HMAC verification: <see cref="Evaluate"/> before (no state
/// change), <see cref="Commit"/> only after the HMAC has verified, so forged packets can never
/// move the window.
/// </summary>
public sealed class ReplayProtection
{
    /// <summary>
    /// Minimum number of Sender-ID records a Node must track (spec 8.6 step 10c).
    /// </summary>
    public const int MinimumCapacity = 32;

    /// <summary>
    /// A full table may only drop its least recently used record if that sender has been
    /// silent this long (spec 8.6 step 10c).
    /// </summary>
    public static readonly TimeSpan EvictionAge = TimeSpan.FromSeconds(3600);

    private sealed class Lane
    {
        public uint SessionId;
        public uint SequenceNumber;
        public long LastValidTimestamp;
    }

    private sealed class Device
    {
        public uint SessionId;
        public int LaneCount;
    }

    private readonly Dictionary<ulong, Lane> lanes = [];
    private readonly Dictionary<ulong, Device> devices = [];
    private readonly TimeProvider timeProvider;
    private readonly long evictionAgeTicks;
    private readonly object lockObject = new();

    /// <param name="capacity">
    /// Sender-ID records to keep. At least 32 for a Node; Managers and Visualisers should size it
    /// for every device in their scope.
    /// </param>
    public ReplayProtection(int capacity = MinimumCapacity, TimeProvider? timeProvider = null)
    {
        if (capacity < MinimumCapacity)
            throw new ArgumentOutOfRangeException(nameof(capacity), capacity, $"At least {MinimumCapacity} Sender-ID records (spec 8.6 step 10c)");

        Capacity = capacity;
        this.timeProvider = timeProvider ?? TimeProvider.System;
        this.evictionAgeTicks = (long)(EvictionAge.TotalSeconds * this.timeProvider.TimestampFrequency);
    }

    public int Capacity { get; }

    public int Count
    {
        get
        {
            lock (this.lockObject)
            {
                return this.lanes.Count;
            }
        }
    }

    /// <summary>
    /// Freshness check (spec 8.6 step 8). Changes nothing.
    /// </summary>
    public FreshnessResult Evaluate(SenderId senderId, uint sessionId, uint sequenceNumber)
    {
        lock (this.lockObject)
        {
            var result = FreshnessResult.Bootstrap;

            if (this.devices.TryGetValue(senderId.Tuid.Value, out var device))
            {
                if (sessionId < device.SessionId)
                    return FreshnessResult.EpochRegression;

                result = FreshnessResult.Fresh;

                if (sessionId == device.SessionId &&
                    this.lanes.TryGetValue(senderId.Value, out var lane) &&
                    lane.SessionId == sessionId &&
                    sequenceNumber <= lane.SequenceNumber)
                {
                    return FreshnessResult.SequenceReplay;
                }
            }

            if (!this.lanes.ContainsKey(senderId.Value) && this.lanes.Count >= Capacity && FindEvictable() == null)
                return FreshnessResult.TableSaturated;

            return result;
        }
    }

    /// <summary>
    /// Record a verified packet (spec 8.6 step 10). Returns false if the table filled up since
    /// <see cref="Evaluate"/> and nothing could be evicted.
    /// </summary>
    public bool Commit(SenderId senderId, uint sessionId, uint sequenceNumber)
    {
        lock (this.lockObject)
        {
            long now = this.timeProvider.GetTimestamp();

            if (!this.lanes.TryGetValue(senderId.Value, out var lane))
            {
                if (this.lanes.Count >= Capacity)
                {
                    var evict = FindEvictable();
                    if (evict == null)
                        return false;

                    Remove(evict.Value);
                }

                lane = new Lane();
                this.lanes.Add(senderId.Value, lane);

                if (!this.devices.TryGetValue(senderId.Tuid.Value, out var newDevice))
                {
                    newDevice = new Device { SessionId = sessionId };
                    this.devices.Add(senderId.Tuid.Value, newDevice);
                }

                newDevice.LaneCount++;
            }

            var device = this.devices[senderId.Tuid.Value];
            if (sessionId > device.SessionId)
                device.SessionId = sessionId;

            lane.SessionId = sessionId;
            lane.SequenceNumber = sequenceNumber;
            lane.LastValidTimestamp = now;

            return true;
        }
    }

    /// <summary>
    /// Discard every record for a TUID, so a device recovered from Session ID exhaustion can be
    /// accepted again without rebooting this one (spec 8.3 "Operational Recovery").
    /// </summary>
    public bool Forget(Tuid tuid)
    {
        lock (this.lockObject)
        {
            if (!this.devices.Remove(tuid.Value))
                return false;

            var stale = new List<ulong>();
            foreach (var key in this.lanes.Keys)
            {
                if (SenderId.FromValue(key).Tuid == tuid)
                    stale.Add(key);
            }

            foreach (var key in stale)
                this.lanes.Remove(key);

            return true;
        }
    }

    public void Clear()
    {
        lock (this.lockObject)
        {
            this.lanes.Clear();
            this.devices.Clear();
        }
    }

    // The least recently used lane, if it is old enough to be dropped
    private ulong? FindEvictable()
    {
        ulong? oldestKey = null;
        long oldest = long.MaxValue;
        foreach (var (key, lane) in this.lanes)
        {
            if (lane.LastValidTimestamp < oldest)
            {
                oldest = lane.LastValidTimestamp;
                oldestKey = key;
            }
        }

        if (oldestKey == null || this.timeProvider.GetTimestamp() - oldest < this.evictionAgeTicks)
            return null;

        return oldestKey;
    }

    private void Remove(ulong senderIdValue)
    {
        this.lanes.Remove(senderIdValue);

        ulong tuid = SenderId.FromValue(senderIdValue).Tuid.Value;
        if (this.devices.TryGetValue(tuid, out var device) && --device.LaneCount == 0)
            this.devices.Remove(tuid);
    }
}
