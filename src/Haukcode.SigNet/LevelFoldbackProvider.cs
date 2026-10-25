namespace Haukcode.SigNet;

/// <summary>
/// Supplies TID_DG_LEVEL_FOLDBACK (spec 11.8.3): the current [DMX512] levels an input endpoint is
/// processing, after merging. Write the slots, start code excluded, into
/// <paramref name="levels"/> (512 bytes) and return how many were written. Return 0 when the
/// endpoint has no levels yet (for example after a reboot); the client then replies with a single
/// 0, as the spec requires. Called on a reply thread, so it must be thread-safe.
/// </summary>
/// <param name="endpoint">The data endpoint number, 1 to N, as in <see cref="SigNetClient.Endpoints"/>.</param>
/// <param name="universe">The endpoint's universe (TID_EP_UNIVERSE).</param>
/// <param name="levels">512 bytes to write the levels into.</param>
/// <returns>The number of slots written, 0 to 512.</returns>
public delegate int LevelFoldbackProvider(ushort endpoint, ushort universe, Span<byte> levels);
