using System.Buffers.Binary;

namespace Haukcode.SigNet;

/// <summary>
/// The 8-byte Sig-Net-Sender-ID option (spec 8.3): the transmitting device's TUID followed by the
/// 16-bit endpoint (lane) the payload originates from. Session ids are tracked per TUID, sequence
/// numbers per full Sender-ID (spec 8.6 step 7).
/// </summary>
public readonly record struct SenderId
{
    public const int Length = 8;

    public SenderId(Tuid tuid, ushort endpoint)
    {
        Tuid = tuid;
        Endpoint = endpoint;
    }

    public Tuid Tuid { get; }

    public ushort Endpoint { get; }

    /// <summary>
    /// The 64-bit value as it appears on the wire (big-endian TUID then endpoint).
    /// </summary>
    public ulong Value => (Tuid.Value << 16) | Endpoint;

    public static SenderId FromValue(ulong value)
    {
        return new SenderId(Tuid.FromValue(value >> 16), (ushort)value);
    }

    public static SenderId Read(ReadOnlySpan<byte> source)
    {
        return new SenderId(Tuid.Read(source), BinaryPrimitives.ReadUInt16BigEndian(source[Tuid.Length..]));
    }

    public void WriteTo(Span<byte> destination)
    {
        Tuid.WriteTo(destination);
        BinaryPrimitives.WriteUInt16BigEndian(destination[Tuid.Length..], Endpoint);
    }

    public override string ToString()
    {
        return $"{Tuid}/{Endpoint}";
    }
}
