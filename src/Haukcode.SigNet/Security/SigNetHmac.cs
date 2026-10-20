using System.Buffers;
using System.Security.Cryptography;
using Haukcode.SigNet.Model;

namespace Haukcode.SigNet.Security;

/// <summary>
/// The packet HMAC of spec 8.5: HMAC-SHA256 over the URI string, the five Sig-Net option values
/// and the application payload, in that order. CoAP header, token and Message ID are excluded.
/// </summary>
public static class SigNetHmac
{
    public const int TagLength = 32;

    public const int KeyLength = 32;

    // Large enough for the URI, options and a maximum payload, so the common case never rents
    private const int StackInputLimit = 1536;

    /// <summary>
    /// Write the HMAC input message (spec 8.5 item 1 to 7). Returns its length.
    /// </summary>
    public static int BuildInput(ReadOnlySpan<byte> uriString, in SigNetSecurityHeader header, ReadOnlySpan<byte> payload, Span<byte> destination)
    {
        uriString.CopyTo(destination);
        int position = uriString.Length;
        header.WriteTo(destination[position..]);
        position += SigNetSecurityHeader.Length;
        payload.CopyTo(destination[position..]);

        return position + payload.Length;
    }

    public static int GetInputLength(int uriLength, int payloadLength) => uriLength + SigNetSecurityHeader.Length + payloadLength;

    public static void Compute(ReadOnlySpan<byte> key, ReadOnlySpan<byte> uriString, in SigNetSecurityHeader header, ReadOnlySpan<byte> payload, Span<byte> tag)
    {
        int inputLength = GetInputLength(uriString.Length, payload.Length);
        byte[]? rented = null;
        Span<byte> input = inputLength <= StackInputLimit
            ? stackalloc byte[StackInputLimit]
            : (rented = ArrayPool<byte>.Shared.Rent(inputLength));

        try
        {
            BuildInput(uriString, header, payload, input);
            HMACSHA256.HashData(key, input[..inputLength], tag);
        }
        finally
        {
            if (rented != null)
                ArrayPool<byte>.Shared.Return(rented);
        }
    }

    /// <summary>
    /// Recompute and compare in constant time (spec 8.6 step 9).
    /// </summary>
    public static bool Verify(ReadOnlySpan<byte> key, ReadOnlySpan<byte> uriString, in SigNetSecurityHeader header, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> receivedTag)
    {
        if (key.Length != KeyLength || receivedTag.Length != TagLength)
            return false;

        Span<byte> expected = stackalloc byte[TagLength];
        Compute(key, uriString, header, payload, expected);

        return CryptographicOperations.FixedTimeEquals(expected, receivedTag);
    }

    /// <summary>
    /// Verify a parsed packet against a key, rebuilding the URI string from its options.
    /// </summary>
    public static bool Verify(ReadOnlySpan<byte> key, SigNetPacket packet)
    {
        Span<byte> uri = stackalloc byte[256];
        int uriLength = packet.WriteUriString(uri);
        if (uriLength < 0)
            return false;

        return Verify(key, uri[..uriLength], packet.Header, packet.Payload.Span, packet.Auth.Span);
    }
}
