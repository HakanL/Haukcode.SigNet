namespace Haukcode.SigNet.Model;

/// <summary>
/// The CoAP option numbers Sig-Net uses (spec 8.3). The Sig-Net options are taken from the private
/// use range as Elective, Safe-to-Forward and NoCacheKey, in the order they must appear.
/// </summary>
public static class CoapOption
{
    public const int UriHost = 3;

    public const int UriPort = 7;

    public const int UriPath = 11;

    public const int UriQuery = 15;

    public const int SecurityMode = 2076;

    public const int SenderId = 2108;

    public const int MfgCode = 2140;

    public const int SessionId = 2172;

    public const int SequenceNumber = 2204;

    public const int Auth = 2236;
}

/// <summary>
/// CoAP header values (RFC 7252 section 3) used by Sig-Net: version 1, NON, POST (spec 9.4).
/// </summary>
public static class Coap
{
    public const int Version = 1;

    public const int TypeConfirmable = 0;

    public const int TypeNonConfirmable = 1;

    public const byte CodePost = 0x02;

    public const byte PayloadMarker = 0xFF;

    public const int HeaderLength = 4;

    /// <summary>
    /// Largest CoAP message a Sig-Net device may send (spec 10.2.4).
    /// </summary>
    public const int MaxMessageLength = 1400;

    /// <summary>
    /// Largest application payload after the 0xFF marker (spec 10.2.4).
    /// </summary>
    public const int MaxPayloadLength = 1200;
}

/// <summary>
/// Sig-Net-Security-Mode values (spec 8.3).
/// </summary>
public static class SecurityMode
{
    /// <summary>Plaintext payload authenticated with HMAC-SHA256.</summary>
    public const byte HmacSha256 = 0x00;

    /// <summary>Open Mode, unauthenticated.</summary>
    public const byte Open = 0x01;

    /// <summary>Offboarded device beacon.</summary>
    public const byte Beacon = 0xFF;
}
