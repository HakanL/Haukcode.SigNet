using System.Text;
using Haukcode.SigNet.Model;

namespace Haukcode.SigNet;

public enum SigNetUriParseResult
{
    Ok = 0,

    /// <summary>Not a /sig-net/... path at all.</summary>
    NotSigNet,

    /// <summary>A Sig-Net path for a major version other than v1 (spec 12.2: discard).</summary>
    UnsupportedVersion,

    /// <summary>The scope is not the configured one (spec 8.6 step 6a: discard).</summary>
    WrongScope,

    /// <summary>Resource name not known to this implementation.</summary>
    UnknownResource,

    /// <summary>Wrong segment count, bad number, leading zeros or a malformed TUID.</summary>
    Malformed
}

/// <summary>
/// Sig-Net URI-Path constants and parsing (spec 8.2).
/// </summary>
public static class SigNetUri
{
    public const string Prefix = "sig-net";

    /// <summary>
    /// The URI version string of this implementation, from the specification's major version (spec 12.1).
    /// </summary>
    public const string Version = "v1";

    public const byte ProtocolVersion = 1;

    public const string DefaultScope = "local";

    public const int MaxScopeLength = 32;

    public const ushort MinUniverse = 1;

    public const ushort MaxUniverse = 63999;

    /// <summary>
    /// Room for the longest URI string this implementation produces (targeted path, 32-character scope).
    /// </summary>
    internal const int MaxUriStringLength = 96;

    private static readonly byte[] prefixBytes = Encoding.ASCII.GetBytes(Prefix);
    private static readonly byte[] versionBytes = Encoding.ASCII.GetBytes(Version);

    /// <summary>
    /// A scope is 1 to 32 URL-safe unreserved characters (RFC 3986 section 2.3:
    /// ALPHA / DIGIT / "-" / "." / "_" / "~").
    /// </summary>
    public static bool IsValidScope(string? scope)
    {
        if (string.IsNullOrEmpty(scope) || scope.Length > MaxScopeLength)
            return false;

        foreach (char c in scope)
        {
            if (!IsUnreserved(c))
                return false;
        }

        return true;
    }

    public static void CheckScope(string? scope)
    {
        if (!IsValidScope(scope))
            throw new ArgumentException($"Invalid scope '{scope}': 1 to {MaxScopeLength} unreserved URI characters (A-Z a-z 0-9 - . _ ~)", nameof(scope));
    }

    /// <summary>
    /// Route a received packet's Uri-Path. With <paramref name="expectedScope"/> set, a different
    /// scope returns <see cref="SigNetUriParseResult.WrongScope"/> and a match reuses the given
    /// string, so the receive path does not allocate; without it the scope is decoded.
    /// </summary>
    public static SigNetUriParseResult TryParsePath(SigNetPacket packet, string? expectedScope, out SigNetPath path)
    {
        path = default;

        int count = packet.UriSegmentCount;
        if (count < 4 || !packet.GetUriSegment(0).SequenceEqual(prefixBytes))
            return SigNetUriParseResult.NotSigNet;

        if (!packet.GetUriSegment(1).SequenceEqual(versionBytes))
            return SigNetUriParseResult.UnsupportedVersion;

        var scopeSegment = packet.GetUriSegment(2);
        string scope;
        if (expectedScope != null)
        {
            if (!AsciiEquals(scopeSegment, expectedScope))
                return SigNetUriParseResult.WrongScope;

            scope = expectedScope;
        }
        else
        {
            if (scopeSegment.Length < 1 || scopeSegment.Length > MaxScopeLength)
                return SigNetUriParseResult.Malformed;

            scope = Encoding.ASCII.GetString(scopeSegment);
            if (!IsValidScope(scope))
                return SigNetUriParseResult.Malformed;
        }

        var resource = ParseResourceName(packet.GetUriSegment(3));
        if (resource == SigNetResource.Unknown)
            return SigNetUriParseResult.UnknownResource;

        if (SigNetPath.IsTargetedResource(resource))
        {
            if (count != 6 ||
                !TryParseTuid(packet.GetUriSegment(4), out var tuid) ||
                !TryParseDecimal(packet.GetUriSegment(5), ushort.MaxValue, out int endpoint))
            {
                return SigNetUriParseResult.Malformed;
            }

            path = SigNetPath.CreateUnchecked(resource, scope, 0, tuid, (ushort)endpoint);
        }
        else if (SigNetPath.IsIndexedResource(resource))
        {
            int max = resource == SigNetResource.Timecode ? 255 : MaxUniverse;
            if (count != 5 || !TryParseDecimal(packet.GetUriSegment(4), max, out int index) || index < 1)
                return SigNetUriParseResult.Malformed;

            path = SigNetPath.CreateUnchecked(resource, scope, (ushort)index, default, 0);
        }
        else
        {
            if (count != 4)
                return SigNetUriParseResult.Malformed;

            path = SigNetPath.CreateUnchecked(resource, scope, 0, default, 0);
        }

        return SigNetUriParseResult.Ok;
    }

    internal static SigNetResource ParseResourceName(ReadOnlySpan<byte> name)
    {
        return name switch
        {
            _ when name.SequenceEqual("level"u8) => SigNetResource.Level,
            _ when name.SequenceEqual("sync"u8) => SigNetResource.Sync,
            _ when name.SequenceEqual("poll"u8) => SigNetResource.Poll,
            _ when name.SequenceEqual("node"u8) => SigNetResource.Node,
            _ when name.SequenceEqual("manager"u8) => SigNetResource.Manager,
            _ when name.SequenceEqual("preview"u8) => SigNetResource.Preview,
            _ when name.SequenceEqual("timecode"u8) => SigNetResource.Timecode,
            _ when name.SequenceEqual("node_lost"u8) => SigNetResource.NodeLost,
            _ when name.SequenceEqual("node_beacon"u8) => SigNetResource.NodeBeacon,
            _ when name.SequenceEqual("aux"u8) => SigNetResource.Aux,
            _ => SigNetResource.Unknown
        };
    }

    /// <summary>
    /// Base-10 without leading zeros (spec 8.2), so only one spelling of a number routes.
    /// </summary>
    internal static bool TryParseDecimal(ReadOnlySpan<byte> text, int max, out int value)
    {
        value = 0;
        if (text.IsEmpty || text.Length > 5 || (text[0] == '0' && text.Length > 1))
            return false;

        foreach (byte b in text)
        {
            if (b < '0' || b > '9')
                return false;

            value = value * 10 + (b - '0');
        }

        return value <= max;
    }

    /// <summary>
    /// 12 hex digits. The canonical form is uppercase (spec 8.2); lowercase is rejected so the
    /// TUID in the URI has one spelling.
    /// </summary>
    internal static bool TryParseTuid(ReadOnlySpan<byte> text, out Tuid tuid)
    {
        tuid = default;
        if (text.Length != Tuid.Length * 2)
            return false;

        ulong value = 0;
        foreach (byte b in text)
        {
            int digit = b switch
            {
                >= (byte)'0' and <= (byte)'9' => b - '0',
                >= (byte)'A' and <= (byte)'F' => b - 'A' + 10,
                _ => -1
            };

            if (digit < 0)
                return false;

            value = (value << 4) | (uint)digit;
        }

        tuid = Tuid.FromValue(value);

        return true;
    }

    private static bool AsciiEquals(ReadOnlySpan<byte> bytes, string text)
    {
        if (bytes.Length != text.Length)
            return false;

        for (int i = 0; i < bytes.Length; i++)
        {
            if (bytes[i] != text[i])
                return false;
        }

        return true;
    }

    internal static bool IsUnreserved(int c)
    {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~';
    }
}
