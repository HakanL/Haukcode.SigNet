namespace Haukcode.SigNet;

/// <summary>
/// Supplies TID_DG_LEVEL_FOLDBACK (spec 11.8.3): the current [DMX512] levels a data endpoint is
/// processing or generating, after merging. Write the slots, start code excluded, into
/// <paramref name="levels"/> (512 bytes) and return how many were written. Return 0 when the
/// endpoint has no levels yet (for example after a reboot); the client then replies with a single
/// 0, as the spec requires. Called on a reply thread, so it must be thread-safe.
/// </summary>
/// <param name="endpoint">The data endpoint, 1 to N.</param>
/// <param name="levels">512 bytes to write the levels into.</param>
/// <returns>The number of slots written, 0 to 512.</returns>
public delegate int LevelFoldbackProvider(ushort endpoint, Span<byte> levels);
