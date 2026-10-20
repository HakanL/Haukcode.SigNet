using System.Buffers.Binary;

namespace Haukcode.SigNet.Model;

/// <summary>
/// CoAP message parser for the subset Sig-Net uses (RFC 7252 section 3, spec 8.1 to 8.4, 8.6
/// steps 2 to 4). Structural checks only: security mode, URI routing, freshness and HMAC are the
/// receiver's job.
/// </summary>
public static class SigNetPacketParser
{
    private const int SeenSecurityMode = 1;
    private const int SeenSenderId = 2;
    private const int SeenMfgCode = 4;
    private const int SeenSessionId = 8;
    private const int SeenSequenceNumber = 16;
    private const int SeenAuth = 32;
    private const int SeenAllRequired = SeenSecurityMode | SeenSenderId | SeenMfgCode | SeenSessionId | SeenSequenceNumber;

    public static SigNetParseResult TryParse(ReadOnlyMemory<byte> datagram, SigNetPacket packet)
    {
        ArgumentNullException.ThrowIfNull(packet);

        packet.Reset(datagram);
        var data = datagram.Span;

        if (data.Length < Coap.HeaderLength)
            return SigNetParseResult.TooShort;

        int version = data[0] >> 6;
        if (version != Coap.Version)
            return SigNetParseResult.UnsupportedCoapVersion;

        int tokenLength = data[0] & 0x0F;
        if (tokenLength > 8)
            return SigNetParseResult.InvalidTokenLength;

        packet.CoapType = (data[0] >> 4) & 0x03;
        packet.TokenLength = tokenLength;
        packet.Code = data[1];
        packet.MessageId = BinaryPrimitives.ReadUInt16BigEndian(data[2..]);

        if (packet.Code != Coap.CodePost)
            return SigNetParseResult.NotPost;

        // Tokens are not used by Sig-Net but must not cause rejection (spec 8.6 step 3)
        int position = Coap.HeaderLength + tokenLength;
        if (position > data.Length)
            return SigNetParseResult.TooShort;

        byte securityMode = 0;
        SenderId senderId = default;
        ushort mfgCode = 0;
        uint sessionId = 0;
        uint sequenceNumber = 0;
        int seen = 0;
        int optionNumber = 0;

        while (position < data.Length)
        {
            byte first = data[position];
            if (first == Coap.PayloadMarker)
            {
                position++;
                if (position == data.Length)
                    return SigNetParseResult.EmptyPayloadAfterMarker;

                packet.Payload = datagram[position..];
                break;
            }

            position++;
            if (!TryReadExtended(data, ref position, first >> 4, out int delta) ||
                !TryReadExtended(data, ref position, first & 0x0F, out int length) ||
                position + length > data.Length)
            {
                return SigNetParseResult.MalformedOption;
            }

            optionNumber += delta;
            var value = data.Slice(position, length);

            switch (optionNumber)
            {
                case CoapOption.UriPath:
                    if (!packet.AddUriSegment(position, length))
                        return SigNetParseResult.TooManyUriSegments;
                    break;

                case CoapOption.UriQuery:
                    if (!packet.AddUriQuery(position, length))
                        return SigNetParseResult.TooManyUriSegments;
                    break;

                case CoapOption.SecurityMode:
                    if (!CheckFixed(ref seen, SeenSecurityMode, length, 1, out var result))
                        return result;
                    securityMode = value[0];
                    break;

                case CoapOption.SenderId:
                    if (!CheckFixed(ref seen, SeenSenderId, length, SenderId.Length, out result))
                        return result;
                    senderId = SenderId.Read(value);
                    break;

                case CoapOption.MfgCode:
                    if (!CheckFixed(ref seen, SeenMfgCode, length, 2, out result))
                        return result;
                    mfgCode = BinaryPrimitives.ReadUInt16BigEndian(value);
                    break;

                case CoapOption.SessionId:
                    if (!CheckFixed(ref seen, SeenSessionId, length, 4, out result))
                        return result;
                    sessionId = BinaryPrimitives.ReadUInt32BigEndian(value);
                    break;

                case CoapOption.SequenceNumber:
                    if (!CheckFixed(ref seen, SeenSequenceNumber, length, 4, out result))
                        return result;
                    sequenceNumber = BinaryPrimitives.ReadUInt32BigEndian(value);
                    break;

                case CoapOption.Auth:
                    if ((seen & SeenAuth) != 0)
                        return SigNetParseResult.DuplicateOption;
                    seen |= SeenAuth;
                    packet.HasAuth = true;
                    packet.Auth = datagram.Slice(position, length);
                    break;

                case CoapOption.UriHost:
                case CoapOption.UriPort:
                    // Recognized; Sig-Net routes by URI-Path only
                    break;

                default:
                    // RFC 7252 section 5.4.1: unrecognized critical options reject the message,
                    // unrecognized elective ones are ignored
                    if ((optionNumber & 1) != 0)
                        return SigNetParseResult.UnsupportedCriticalOption;
                    break;
            }

            position += length;
        }

        // TODO (spec 8.3): Open Mode and beacons "shall transmit 0x00000000" for Session-ID and
        // Seq-Num, but NETworkshop v0.11 omits both options in its Open Mode polls. Neither mode is
        // ever verified here, so the omission is tolerated (read as zero) to classify the packet.
        const int SeenUnauthenticatedRequired = SeenSecurityMode | SeenSenderId | SeenMfgCode;
        bool unauthenticated = (seen & SeenSecurityMode) != 0 && securityMode is SecurityMode.Open or SecurityMode.Beacon;
        if ((seen & (unauthenticated ? SeenUnauthenticatedRequired : SeenAllRequired)) != (unauthenticated ? SeenUnauthenticatedRequired : SeenAllRequired))
            return SigNetParseResult.MissingSecurityOption;

        // Auth width follows the security mode (spec 8.3). Beacons may omit Auth entirely
        // (spec 10.2.1) or carry it empty (Appendix A note 1); both are accepted.
        int authLength = packet.Auth.Length;
        switch (securityMode)
        {
            case SecurityMode.HmacSha256:
                if (!packet.HasAuth || authLength != 32)
                    return SigNetParseResult.InvalidOptionLength;
                break;

            case SecurityMode.Open:
                if (!packet.HasAuth || authLength != 0)
                    return SigNetParseResult.InvalidOptionLength;
                break;

            case SecurityMode.Beacon:
                if (authLength != 0)
                    return SigNetParseResult.InvalidOptionLength;
                break;
        }

        packet.Header = new SigNetSecurityHeader(securityMode, senderId, mfgCode, sessionId, sequenceNumber);

        return SigNetParseResult.Ok;
    }

    private static bool CheckFixed(ref int seen, int flag, int length, int expected, out SigNetParseResult result)
    {
        if ((seen & flag) != 0)
        {
            result = SigNetParseResult.DuplicateOption;

            return false;
        }

        seen |= flag;
        if (length != expected)
        {
            result = SigNetParseResult.InvalidOptionLength;

            return false;
        }

        result = SigNetParseResult.Ok;

        return true;
    }

    // RFC 7252 section 3.1: 0-12 inline, 13 = one extra byte + 13, 14 = two extra bytes + 269, 15 reserved
    private static bool TryReadExtended(ReadOnlySpan<byte> data, ref int position, int nibble, out int value)
    {
        switch (nibble)
        {
            case <= 12:
                value = nibble;

                return true;

            case 13:
                if (position + 1 > data.Length)
                    break;
                value = data[position] + 13;
                position += 1;

                return true;

            case 14:
                if (position + 2 > data.Length)
                    break;
                value = BinaryPrimitives.ReadUInt16BigEndian(data[position..]) + 269;
                position += 2;

                return true;
        }

        value = 0;

        return false;
    }
}
