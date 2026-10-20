namespace Haukcode.SigNet;

/// <summary>
/// The Sender transmission rules of spec 10.6.3, for callers that tick every universe at their
/// frame rate (44 Hz by default) and want to know whether this tick's frame should go out:
/// changed data is sent, unchanged data is repeated until three identical frames have been sent,
/// then a keep-alive frame at least once a second. Rate limiting is the caller's tick.
/// Not thread-safe; use one per sending thread.
/// </summary>
public sealed class LevelRefreshPolicy
{
    /// <summary>
    /// Identical frames sent with the final state before dropping to keep-alive.
    /// </summary>
    // TODO (spec 10.6.3): "three identical packets containing the final state" is read as three
    // in total, the frame that carried the change being the first.
    public const int IdenticalFrameCount = 3;

    public static readonly TimeSpan KeepAliveInterval = TimeSpan.FromSeconds(1);

    private sealed class UniverseState
    {
        public readonly byte[] Levels = new byte[512];
        public int Length;
        public int Priority = -1;
        public int Remaining;
        public long LastSentTimestamp;
    }

    private readonly Dictionary<ushort, UniverseState> universes = [];
    private readonly TimeProvider timeProvider;

    public LevelRefreshPolicy(TimeProvider? timeProvider = null)
    {
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// True when this frame should be sent. Call once per universe per tick with the current data.
    /// </summary>
    public bool ShouldSend(ushort universe, ReadOnlySpan<byte> levels, byte? priority = null)
    {
        if (levels.Length > 512)
            throw new ArgumentOutOfRangeException(nameof(levels), levels.Length, "At most 512 slots");

        long now = this.timeProvider.GetTimestamp();
        int priorityValue = priority ?? -1;

        if (!this.universes.TryGetValue(universe, out var state))
        {
            state = new UniverseState();
            this.universes.Add(universe, state);
        }
        else if (state.Length == levels.Length && state.Priority == priorityValue && levels.SequenceEqual(state.Levels.AsSpan(0, state.Length)))
        {
            if (state.Remaining > 0)
            {
                state.Remaining--;
                state.LastSentTimestamp = now;

                return true;
            }

            if (this.timeProvider.GetElapsedTime(state.LastSentTimestamp, now) >= KeepAliveInterval)
            {
                state.LastSentTimestamp = now;

                return true;
            }

            return false;
        }

        levels.CopyTo(state.Levels);
        state.Length = levels.Length;
        state.Priority = priorityValue;
        state.Remaining = IdenticalFrameCount - 1;
        state.LastSentTimestamp = now;

        return true;
    }

    /// <summary>
    /// Forget a universe, e.g. after <see cref="SigNetClient.StopUniverse"/>.
    /// </summary>
    public void Forget(ushort universe)
    {
        this.universes.Remove(universe);
    }
}
