using System.Buffers.Binary;
using Haukcode.SigNet.Security;

namespace Haukcode.SigNet.Model;

/// <summary>
/// Builds Sig-Net CoAP NON POST messages (spec 8.4): header without token, Uri-Path options,
/// the five security options, Sig-Net-Auth, then the payload marker and TLV payload. The marker
/// is omitted when the payload is empty.
/// </summary>
public static class SigNetPacketWriter
{
    // 4-byte header, then options. Uri-Path segments are at most 32 bytes (scope) so their
    // header is at most 2 bytes; the jump from 11 to 2076 needs a 3-byte option header.
    private const int MaxOptionsOverhead = 6 * (2 + 32) + 3 + 1 + (1 + 1 + 8) + (1 + 1 + 2) + (1 + 1 + 4) + (1 + 1 + 4) + (2 + 1 + SigNetHmac.TagLength);

    /// <summary>
    /// An upper bound on the message size for a payload, for sizing buffers.
    /// </summary>
    public static int GetMaxLength(int payloadLength) => Coap.HeaderLength + MaxOptionsOverhead + 1 + payloadLength;

    /// <summary>
    /// Write a message and sign it. For Security-Mode 0x00 <paramref name="key"/> is the 32-byte
    /// role key for the path; for Open Mode and beacons the key is ignored and Sig-Net-Auth is
    /// written with zero length. Returns the message length.
    /// </summary>
    public static int Write(Span<byte> destination, ushort messageId, in SigNetPath path, in SigNetSecurityHeader header, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> key)
    {
        if (payload.Length > Coap.MaxPayloadLength)
            throw new ArgumentException($"Payload exceeds {Coap.MaxPayloadLength} bytes (spec 10.2.4)", nameof(payload));

        bool signed = header.SecurityMode == SecurityMode.HmacSha256;
        if (signed && key.Length != SigNetHmac.KeyLength)
            throw new ArgumentException($"A {SigNetHmac.KeyLength}-byte key is required for Security-Mode 0x00", nameof(key));

        // Header: Ver 1, NON, TKL 0, POST
        destination[0] = (byte)((Coap.Version << 6) | (Coap.TypeNonConfirmable << 4));
        destination[1] = Coap.CodePost;
        BinaryPrimitives.WriteUInt16BigEndian(destination[2..], messageId);
        int position = Coap.HeaderLength;

        // Uri-Path segments: option 11 once, then delta 0 for each further segment
        int previous = 0;
        Span<byte> segment = stackalloc byte[SigNetUri.MaxScopeLength];
        int segmentCount = path.SegmentCount;
        for (int i = 0; i < segmentCount; i++)
        {
            int segmentLength = path.WriteSegment(i, segment);
            position += WriteOption(destination[position..], CoapOption.UriPath - previous, segment[..segmentLength]);
            previous = CoapOption.UriPath;
        }

        Span<byte> securityValues = stackalloc byte[SigNetSecurityHeader.Length];
        header.WriteTo(securityValues);

        position += WriteOption(destination[position..], CoapOption.SecurityMode - previous, securityValues[..1]);
        position += WriteOption(destination[position..], CoapOption.SenderId - CoapOption.SecurityMode, securityValues.Slice(1, 8));
        position += WriteOption(destination[position..], CoapOption.MfgCode - CoapOption.SenderId, securityValues.Slice(9, 2));
        position += WriteOption(destination[position..], CoapOption.SessionId - CoapOption.MfgCode, securityValues.Slice(11, 4));
        position += WriteOption(destination[position..], CoapOption.SequenceNumber - CoapOption.SessionId, securityValues.Slice(15, 4));

        // TODO (spec 10.2.1 vs Appendix A note 1): beacons "omit" Sig-Net-Auth in 10.2.1 but carry
        // it with zero length in Appendix A. A zero-length option is written for Open Mode and
        // beacons, which is what the SDK parser requires.
        int authLength = signed ? SigNetHmac.TagLength : 0;
        int authHeaderLength = WriteOptionHeader(destination[position..], CoapOption.Auth - CoapOption.SequenceNumber, authLength);
        var tag = destination.Slice(position + authHeaderLength, authLength);
        position += authHeaderLength + authLength;

        if (!payload.IsEmpty)
        {
            destination[position++] = Coap.PayloadMarker;
            payload.CopyTo(destination[position..]);
            position += payload.Length;
        }

        if (position > Coap.MaxMessageLength)
            throw new ArgumentException($"Message exceeds {Coap.MaxMessageLength} bytes (spec 10.2.4)", nameof(payload));

        if (signed)
        {
            Span<byte> uri = stackalloc byte[SigNetUri.MaxUriStringLength];
            int uriLength = path.WriteUriString(uri);
            SigNetHmac.Compute(key, uri[..uriLength], header, payload, tag);
        }

        return position;
    }

    private static int WriteOption(Span<byte> destination, int delta, ReadOnlySpan<byte> value)
    {
        int headerLength = WriteOptionHeader(destination, delta, value.Length);
        value.CopyTo(destination[headerLength..]);

        return headerLength + value.Length;
    }

    // RFC 7252 section 3.1 option header with extended delta and length
    private static int WriteOptionHeader(Span<byte> destination, int delta, int length)
    {
        int position = 1;
        int deltaNibble = EncodeNibble(delta, destination, ref position);
        int lengthNibble = EncodeNibble(length, destination, ref position);
        destination[0] = (byte)((deltaNibble << 4) | lengthNibble);

        return position;
    }

    private static int EncodeNibble(int value, Span<byte> destination, ref int position)
    {
        if (value <= 12)
            return value;

        if (value < 269)
        {
            destination[position++] = (byte)(value - 13);

            return 13;
        }

        BinaryPrimitives.WriteUInt16BigEndian(destination[position..], (ushort)(value - 269));
        position += 2;

        return 14;
    }
}
