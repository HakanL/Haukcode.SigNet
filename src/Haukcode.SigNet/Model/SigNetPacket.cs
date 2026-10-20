namespace Haukcode.SigNet.Model;

public enum SigNetParseResult
{
    Ok = 0,

    TooShort,

    /// <summary>CoAP Ver is not 1 (spec 8.6 step 2).</summary>
    UnsupportedCoapVersion,

    /// <summary>TKL 9 to 15 is a CoAP message format error.</summary>
    InvalidTokenLength,

    /// <summary>Code is not POST (spec 8.6 step 4).</summary>
    NotPost,

    /// <summary>Option delta or length uses the reserved nibble 15, or runs past the end.</summary>
    MalformedOption,

    /// <summary>An unrecognized critical (odd-numbered) option (RFC 7252 section 5.4.1).</summary>
    UnsupportedCriticalOption,

    TooManyUriSegments,

    /// <summary>One of the five fixed Sig-Net options is missing (spec 8.3).</summary>
    MissingSecurityOption,

    /// <summary>A Sig-Net option has the wrong width, or Auth does not fit the security mode.</summary>
    InvalidOptionLength,

    DuplicateOption,

    /// <summary>A payload marker followed by no payload (RFC 7252 section 3).</summary>
    EmptyPayloadAfterMarker
}

/// <summary>
/// A received Sig-Net CoAP message, parsed in place: segments, auth and payload are slices of the
/// receive buffer and are only valid as long as that buffer is. Reused for every datagram.
/// </summary>
public sealed class SigNetPacket
{
    public const int MaxUriSegments = 16;

    public const int MaxUriQueries = 8;

    private readonly int[] uriSegmentStart = new int[MaxUriSegments];
    private readonly int[] uriSegmentLength = new int[MaxUriSegments];
    private readonly int[] uriQueryStart = new int[MaxUriQueries];
    private readonly int[] uriQueryLength = new int[MaxUriQueries];

    public ReadOnlyMemory<byte> Datagram { get; internal set; }

    public int CoapType { get; internal set; }

    public byte Code { get; internal set; }

    public ushort MessageId { get; internal set; }

    public int TokenLength { get; internal set; }

    public int UriSegmentCount { get; private set; }

    public int UriQueryCount { get; private set; }

    public SigNetSecurityHeader Header { get; internal set; }

    public byte SecurityMode => Header.SecurityMode;

    public SenderId SenderId => Header.SenderId;

    /// <summary>
    /// True when the Auth option was present (possibly zero length).
    /// </summary>
    public bool HasAuth { get; internal set; }

    public ReadOnlyMemory<byte> Auth { get; internal set; }

    public ReadOnlyMemory<byte> Payload { get; internal set; }

    public ReadOnlySpan<byte> GetUriSegment(int index)
    {
        if ((uint)index >= (uint)UriSegmentCount)
            throw new ArgumentOutOfRangeException(nameof(index));

        return Datagram.Span.Slice(this.uriSegmentStart[index], this.uriSegmentLength[index]);
    }

    public ReadOnlySpan<byte> GetUriQuery(int index)
    {
        if ((uint)index >= (uint)UriQueryCount)
            throw new ArgumentOutOfRangeException(nameof(index));

        return Datagram.Span.Slice(this.uriQueryStart[index], this.uriQueryLength[index]);
    }

    /// <summary>
    /// The URI string the HMAC covers, rebuilt from the Uri-Path and Uri-Query options as
    /// RFC 7252 section 6.5 steps 6 to 8 do (percent-encoding anything outside the allowed
    /// characters), without scheme or authority (spec 8.5 item 1). Returns the byte count, or -1
    /// when <paramref name="destination"/> is too small.
    /// </summary>
    public int WriteUriString(Span<byte> destination)
    {
        int length = 0;
        for (int i = 0; i < UriSegmentCount; i++)
        {
            if (!TryAppend(destination, ref length, (byte)'/') || !TryAppendEncoded(destination, ref length, GetUriSegment(i), query: false))
                return -1;
        }

        if (UriSegmentCount == 0 && !TryAppend(destination, ref length, (byte)'/'))
            return -1;

        for (int i = 0; i < UriQueryCount; i++)
        {
            if (!TryAppend(destination, ref length, i == 0 ? (byte)'?' : (byte)'&') || !TryAppendEncoded(destination, ref length, GetUriQuery(i), query: true))
                return -1;
        }

        return length;
    }

    internal void Reset(ReadOnlyMemory<byte> datagram)
    {
        Datagram = datagram;
        UriSegmentCount = 0;
        UriQueryCount = 0;
        Header = default;
        HasAuth = false;
        Auth = ReadOnlyMemory<byte>.Empty;
        Payload = ReadOnlyMemory<byte>.Empty;
    }

    internal bool AddUriSegment(int start, int length)
    {
        if (UriSegmentCount == MaxUriSegments)
            return false;

        this.uriSegmentStart[UriSegmentCount] = start;
        this.uriSegmentLength[UriSegmentCount] = length;
        UriSegmentCount++;

        return true;
    }

    internal bool AddUriQuery(int start, int length)
    {
        if (UriQueryCount == MaxUriQueries)
            return false;

        this.uriQueryStart[UriQueryCount] = start;
        this.uriQueryLength[UriQueryCount] = length;
        UriQueryCount++;

        return true;
    }

    private static bool TryAppend(Span<byte> destination, ref int length, byte value)
    {
        if (length >= destination.Length)
            return false;

        destination[length++] = value;

        return true;
    }

    private static bool TryAppendEncoded(Span<byte> destination, ref int length, ReadOnlySpan<byte> value, bool query)
    {
        foreach (byte b in value)
        {
            // A query also allows "/" and "?", but "&" is its separator and must be encoded
            bool allowed = query
                ? (IsPathCharacter(b) && b != '&') || b == '/' || b == '?'
                : IsPathCharacter(b);

            if (allowed)
            {
                if (!TryAppend(destination, ref length, b))
                    return false;
            }
            else
            {
                if (length + 3 > destination.Length)
                    return false;

                destination[length++] = (byte)'%';
                destination[length++] = (byte)"0123456789ABCDEF"[b >> 4];
                destination[length++] = (byte)"0123456789ABCDEF"[b & 0x0F];
            }
        }

        return true;
    }

    // RFC 3986 pchar: unreserved / sub-delims / ":" / "@"
    private static bool IsPathCharacter(byte b)
    {
        return SigNetUri.IsUnreserved(b) || b is (byte)'!' or (byte)'$' or (byte)'&' or (byte)'\'' or (byte)'(' or (byte)')' or (byte)'*' or (byte)'+' or (byte)',' or (byte)';' or (byte)'=' or (byte)':' or (byte)'@';
    }
}
