using System.Buffers.Binary;

namespace Haukcode.SigNet.Model;

/// <summary>
/// The five fixed-width Sig-Net option values, in wire and HMAC order (spec 8.3, 8.5). All are
/// CoAP "opaque": fixed width, big-endian, zero padded.
/// </summary>
public readonly record struct SigNetSecurityHeader(byte SecurityMode, SenderId SenderId, ushort MfgCode, uint SessionId, uint SequenceNumber)
{
    /// <summary>
    /// 1 + 8 + 2 + 4 + 4 bytes.
    /// </summary>
    public const int Length = 19;

    /// <summary>
    /// The option values concatenated, as they enter the HMAC (spec 8.5 items 2 to 6).
    /// </summary>
    public void WriteTo(Span<byte> destination)
    {
        destination[0] = SecurityMode;
        SenderId.WriteTo(destination[1..]);
        BinaryPrimitives.WriteUInt16BigEndian(destination[9..], MfgCode);
        BinaryPrimitives.WriteUInt32BigEndian(destination[11..], SessionId);
        BinaryPrimitives.WriteUInt32BigEndian(destination[15..], SequenceNumber);
    }
}
