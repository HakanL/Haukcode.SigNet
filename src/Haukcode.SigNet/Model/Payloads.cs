using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Haukcode.SigNet.Model;

/// <summary>
/// TID_POLL (spec 11.1.1), 25 bytes.
/// </summary>
public readonly record struct PollRequest(Tuid ManagerTuid, uint ManagerSoemCode, Tuid TuidLow, Tuid TuidHigh, ushort Endpoint, QueryLevel QueryLevel)
{
    public const int Length = 25;

    public const ushort AllEndpoints = 0xFFFF;

    /// <summary>
    /// TUID_LO == TUID_HI: a poll for one device, answered without the random backoff (spec 10.2.3).
    /// </summary>
    public bool IsTargeted => TuidLow == TuidHigh;

    public bool Includes(Tuid tuid) => tuid.Value >= TuidLow.Value && tuid.Value <= TuidHigh.Value;

    public static PollRequest Read(ReadOnlySpan<byte> value)
    {
        return new PollRequest(
            Tuid.Read(value),
            BinaryPrimitives.ReadUInt32BigEndian(value[6..]),
            Tuid.Read(value[10..]),
            Tuid.Read(value[16..]),
            BinaryPrimitives.ReadUInt16BigEndian(value[22..]),
            (QueryLevel)value[24]);
    }

    public void WriteTo(Span<byte> destination)
    {
        ManagerTuid.WriteTo(destination);
        BinaryPrimitives.WriteUInt32BigEndian(destination[6..], ManagerSoemCode);
        TuidLow.WriteTo(destination[10..]);
        TuidHigh.WriteTo(destination[16..]);
        BinaryPrimitives.WriteUInt16BigEndian(destination[22..], Endpoint);
        destination[24] = (byte)QueryLevel;
    }
}

/// <summary>
/// TID_POLL_REPLY (spec 11.1.2), 12 bytes.
/// </summary>
public readonly record struct PollReply(Tuid Tuid, uint SoemCode, ushort ChangeCount)
{
    public const int Length = 12;

    public static PollReply Read(ReadOnlySpan<byte> value)
    {
        return new PollReply(Tuid.Read(value), BinaryPrimitives.ReadUInt32BigEndian(value[6..]), BinaryPrimitives.ReadUInt16BigEndian(value[10..]));
    }

    public void WriteTo(Span<byte> destination)
    {
        Tuid.WriteTo(destination);
        BinaryPrimitives.WriteUInt32BigEndian(destination[6..], SoemCode);
        BinaryPrimitives.WriteUInt16BigEndian(destination[10..], ChangeCount);
    }
}

public enum UniverseCommand : byte
{
    Join = 0x01,

    Leave = 0x02
}

/// <summary>
/// TID_UNIVERSE (spec 11.2.6), 9 bytes. A zero multicast address means the default folded group.
/// </summary>
public readonly record struct UniverseAnnouncement(ushort Universe, UniverseCommand Command, IPAddress? MulticastAddress, ushort SenderEndpoint)
{
    public const int Length = 9;

    public static UniverseAnnouncement Read(ReadOnlySpan<byte> value)
    {
        uint address = BinaryPrimitives.ReadUInt32BigEndian(value[3..]);

        return new UniverseAnnouncement(
            BinaryPrimitives.ReadUInt16BigEndian(value),
            (UniverseCommand)value[2],
            address == 0 ? null : new IPAddress(value.Slice(3, 4)),
            BinaryPrimitives.ReadUInt16BigEndian(value[7..]));
    }

    public void WriteTo(Span<byte> destination)
    {
        BinaryPrimitives.WriteUInt16BigEndian(destination, Universe);
        destination[2] = (byte)Command;
        if (MulticastAddress == null)
            destination.Slice(3, 4).Clear();
        else if (!MulticastAddress.TryWriteBytes(destination.Slice(3, 4), out _))
            throw new ArgumentException("TID_UNIVERSE carries an IPv4 address");
        BinaryPrimitives.WriteUInt16BigEndian(destination[7..], SenderEndpoint);
    }
}

/// <summary>
/// TID_DG_SECURITY_EVENT codes (spec 11.8.1).
/// </summary>
public enum SecurityEventCode : ushort
{
    HmacFailure = 0x0001,

    ReplayDetected = 0x0002,

    DosRateLimiting = 0x0003,

    UnauthorisedOnboarding = 0x0004,

    SenderTableSaturated = 0x0005,

    EpochRegression = 0x0006,

    SequenceViolation = 0x0007,

    FailedOffboard = 0x0008
}

/// <summary>
/// TID_DG_SECURITY_EVENT (spec 11.8.1): 7 bytes without an address, 11 with IPv4, 23 with IPv6.
/// </summary>
public readonly record struct SecurityEvent(SecurityEventCode Code, uint Count, IPAddress? SourceAddress)
{
    public int Length => SourceAddress == null ? 7 : SourceAddress.AddressFamily == AddressFamily.InterNetworkV6 ? 23 : 11;

    public static SecurityEvent Read(ReadOnlySpan<byte> value)
    {
        IPAddress? address = value[6] switch
        {
            0x01 when value.Length >= 11 => new IPAddress(value.Slice(7, 4)),
            0x02 when value.Length >= 23 => new IPAddress(value.Slice(7, 16)),
            _ => null
        };

        return new SecurityEvent((SecurityEventCode)BinaryPrimitives.ReadUInt16BigEndian(value), BinaryPrimitives.ReadUInt32BigEndian(value[2..]), address);
    }

    public void WriteTo(Span<byte> destination)
    {
        BinaryPrimitives.WriteUInt16BigEndian(destination, (ushort)Code);
        BinaryPrimitives.WriteUInt32BigEndian(destination[2..], Count);
        if (SourceAddress == null)
        {
            destination[6] = 0x00;
        }
        else
        {
            destination[6] = SourceAddress.AddressFamily == AddressFamily.InterNetworkV6 ? (byte)0x02 : (byte)0x01;
            SourceAddress.TryWriteBytes(destination[7..], out _);
        }
    }
}

/// <summary>
/// Helpers for the "encoding byte + text" TIDs (TID_RT_DEVICE_LABEL, TID_RT_MODEL_NAME,
/// TID_EP_LABEL) and TID_RT_FIRMWARE_VERSION.
/// </summary>
public static class TextPayload
{
    public const byte EncodingAscii = 0x00;

    public const int MaxTextLength = 64;

    /// <summary>
    /// Encoding byte 0x00 then up to 64 ASCII bytes, not null-terminated. Longer text is cut.
    /// </summary>
    public static void WriteLabel(ref TlvWriter writer, ushort tid, string text)
    {
        int length = Math.Min(text.Length, MaxTextLength);
        var value = writer.Reserve(tid, 1 + length);
        value[0] = EncodingAscii;
        WriteAscii(text.AsSpan(0, length), value[1..]);
    }

    /// <summary>
    /// 32-bit machine version (RDM convention) then up to 64 ASCII bytes.
    /// </summary>
    public static void WriteFirmwareVersion(ref TlvWriter writer, uint versionId, string text)
    {
        int length = Math.Min(text.Length, MaxTextLength);
        var value = writer.Reserve(Tid.RtFirmwareVersion, 4 + length);
        BinaryPrimitives.WriteUInt32BigEndian(value, versionId);
        WriteAscii(text.AsSpan(0, length), value[4..]);
    }

    public static string ReadLabel(ReadOnlySpan<byte> value)
    {
        return value.Length <= 1 ? string.Empty : Encoding.ASCII.GetString(value[1..]);
    }

    private static void WriteAscii(ReadOnlySpan<char> text, Span<byte> destination)
    {
        for (int i = 0; i < text.Length; i++)
            destination[i] = text[i] < 0x80 ? (byte)text[i] : (byte)'?';
    }
}
