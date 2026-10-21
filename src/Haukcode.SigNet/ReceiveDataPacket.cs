using System.Net;

namespace Haukcode.SigNet;

/// <summary>
/// What a universe is joined for (same meaning as in Haukcode.sACN).
/// </summary>
[Flags]
public enum SubscribeModes
{
    None = 0,

    /// <summary>Input: <see cref="SigNetClient.JoinUniverse"/>.</summary>
    DmxData = 1,

    /// <summary>Triggers: <see cref="SigNetClient.JoinUniverseForTrigger"/>.</summary>
    Trigger = 2
}

public enum ReceiveDataKind
{
    /// <summary>A verified TID_LEVEL frame for a joined universe.</summary>
    Levels,

    /// <summary>A verified TID_SYNC. Held frames it released were delivered just before it.</summary>
    Sync
}

/// <summary>
/// A verified packet handed to the client's channel writer. The object and its
/// <see cref="Levels"/> are reused once the writer returns: use them inside the writer, or keep
/// a <see cref="Clone"/>.
/// </summary>
public class ReceiveDataPacket
{
    public ReceiveDataKind Kind { get; set; }

    /// <summary>
    /// Arrival time on the client's receive clock (kernel timestamp where the platform has one).
    /// For a frame released by sync, the arrival time of the level packet, not of the sync.
    /// </summary>
    public double TimestampMS { get; set; }

    public IPEndPoint Source { get; set; } = null!;

    /// <summary>
    /// Null for multicast, the local endpoint for unicast.
    /// </summary>
    public IPEndPoint? Destination { get; set; }

    /// <summary>
    /// The 8-byte Sig-Net-Sender-ID: sender TUID and the lane (endpoint) it sent on. Use it as the
    /// source identity for merging (spec 10.6).
    /// </summary>
    public SenderId SenderId { get; set; }

    public uint SessionId { get; set; }

    public uint SequenceNumber { get; set; }

    /// <summary>
    /// The universe, for <see cref="ReceiveDataKind.Levels"/>.
    /// </summary>
    public ushort Universe { get; set; }

    /// <summary>
    /// 1 to 512 slots, zero start code.
    /// </summary>
    public ReadOnlyMemory<byte> Levels { get; set; }

    /// <summary>
    /// Universe priority: the first byte of the most recent TID_PRIORITY from this sender on this
    /// universe (the Constrained Node Fallback of spec 10.6), or 100 if none has been received
    /// this session.
    /// </summary>
    public byte Priority { get; set; }

    /// <summary>
    /// True when <see cref="Priority"/> came from a TID_PRIORITY rather than the default.
    /// </summary>
    public bool HasPriority { get; set; }

    /// <summary>
    /// True when the frame was held for this sender's sync and released by a TID_SYNC (or by the
    /// 250 ms sync timeout), false when applied as it arrived (spec 10.7.2).
    /// </summary>
    public bool Synchronized { get; set; }

    /// <summary>
    /// What the frame's universe is joined for. None for sync, which belongs to no universe.
    /// </summary>
    public SubscribeModes SubscribeMode { get; set; }

    public ReceiveDataPacket Clone()
    {
        var clone = (ReceiveDataPacket)MemberwiseClone();
        clone.Levels = Levels.ToArray();

        return clone;
    }
}

/// <summary>
/// No valid TID_LEVEL from a sender on a joined universe for &lt;universe_lost_timeout&gt;
/// (3 s, spec 10.6.4). Reported only; what to output is the application's choice.
/// </summary>
public readonly record struct UniverseLostEvent(ushort Universe, SenderId SenderId);
