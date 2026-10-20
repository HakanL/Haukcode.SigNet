using System.Buffers.Binary;

namespace Haukcode.SigNet.Model;

public enum TlvValidationResult
{
    Ok = 0,

    /// <summary>A TLV header or value runs past the end of the payload.</summary>
    Truncated,

    /// <summary>A known TID with a length its definition does not allow (spec 10.1.3).</summary>
    InvalidLength
}

/// <summary>
/// Sig-Net TLV payload reader (spec 10.1): 2-byte TID, 2-byte length, value, all big-endian.
/// Call <see cref="Validate"/> on the whole payload first: one malformed TLV makes the whole
/// packet invalid (spec 10.1.3), so nothing may be acted on before every TLV has been checked.
/// </summary>
public ref struct TlvReader
{
    public const int HeaderLength = 4;

    private readonly ReadOnlySpan<byte> payload;
    private int position;

    public TlvReader(ReadOnlySpan<byte> payload)
    {
        this.payload = payload;
        this.position = 0;
    }

    /// <summary>
    /// Structural check of a payload. Unknown and manufacturer TIDs only need to fit; known TIDs
    /// must also have a legal length.
    /// </summary>
    public static TlvValidationResult Validate(ReadOnlySpan<byte> payload)
    {
        int position = 0;
        while (position < payload.Length)
        {
            if (position + HeaderLength > payload.Length)
                return TlvValidationResult.Truncated;

            ushort tid = BinaryPrimitives.ReadUInt16BigEndian(payload[position..]);
            int length = BinaryPrimitives.ReadUInt16BigEndian(payload[(position + 2)..]);
            position += HeaderLength;

            if (position + length > payload.Length)
                return TlvValidationResult.Truncated;

            if (TidCatalogue.TryGet(tid, out var info) && !info.IsValidLength(length))
                return TlvValidationResult.InvalidLength;

            position += length;
        }

        return TlvValidationResult.Ok;
    }

    /// <summary>
    /// Read the next TLV. Returns false at the end of the payload or on a truncated TLV.
    /// </summary>
    public bool TryRead(out ushort tid, out ReadOnlySpan<byte> value)
    {
        tid = 0;
        value = default;

        if (this.position + HeaderLength > this.payload.Length)
            return false;

        tid = BinaryPrimitives.ReadUInt16BigEndian(this.payload[this.position..]);
        int length = BinaryPrimitives.ReadUInt16BigEndian(this.payload[(this.position + 2)..]);
        if (this.position + HeaderLength + length > this.payload.Length)
            return false;

        value = this.payload.Slice(this.position + HeaderLength, length);
        this.position += HeaderLength + length;

        return true;
    }
}

/// <summary>
/// Sig-Net TLV payload writer. Throws when the destination is full, so callers size it to the
/// 1,200-byte payload cap (spec 10.2.4) and split replies across packets themselves.
/// </summary>
public ref struct TlvWriter
{
    private readonly Span<byte> destination;
    private int position;

    public TlvWriter(Span<byte> destination)
    {
        this.destination = destination;
        this.position = 0;
    }

    public int Length => this.position;

    public int Remaining => this.destination.Length - this.position;

    public ReadOnlySpan<byte> Written => this.destination[..this.position];

    public bool CanWrite(int valueLength) => Remaining >= TlvReader.HeaderLength + valueLength;

    public void Write(ushort tid, ReadOnlySpan<byte> value)
    {
        var span = Reserve(tid, value.Length);
        value.CopyTo(span);
    }

    /// <summary>
    /// Write a TLV header and return its value area for the caller to fill.
    /// </summary>
    public Span<byte> Reserve(ushort tid, int valueLength)
    {
        if (valueLength > ushort.MaxValue || !CanWrite(valueLength))
            throw new InvalidOperationException($"TLV 0x{tid:X4} with {valueLength} bytes does not fit");

        BinaryPrimitives.WriteUInt16BigEndian(this.destination[this.position..], tid);
        BinaryPrimitives.WriteUInt16BigEndian(this.destination[(this.position + 2)..], (ushort)valueLength);
        var value = this.destination.Slice(this.position + TlvReader.HeaderLength, valueLength);
        this.position += TlvReader.HeaderLength + valueLength;

        return value;
    }

    public void WriteEmpty(ushort tid) => Reserve(tid, 0);

    public void WriteByte(ushort tid, byte value) => Reserve(tid, 1)[0] = value;

    public void WriteUInt16(ushort tid, ushort value) => BinaryPrimitives.WriteUInt16BigEndian(Reserve(tid, 2), value);

    public void WriteUInt32(ushort tid, uint value) => BinaryPrimitives.WriteUInt32BigEndian(Reserve(tid, 4), value);
}
