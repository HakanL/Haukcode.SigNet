using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;

namespace Haukcode.SigNet;

/// <summary>
/// Transport Unique Identifier (spec 6.6): a 16-bit ESTA manufacturer id in the upper two bytes
/// and a 32-bit device id in the lower four. Device ids with the MSB clear are static (hardware,
/// assigned in production); MSB set means dynamic (software, generated with a CSPRNG).
/// 0xFFFFFFF0 to 0xFFFFFFFF are reserved.
/// </summary>
public readonly record struct Tuid
{
    public const int Length = 6;

    public const uint DynamicFlag = 0x8000_0000;

    public const uint FirstReservedDeviceId = 0xFFFF_FFF0;

    public Tuid(ushort manufacturerId, uint deviceId)
    {
        ManufacturerId = manufacturerId;
        DeviceId = deviceId;
    }

    public ushort ManufacturerId { get; }

    public uint DeviceId { get; }

    /// <summary>
    /// True for a dynamic (software) device id, MSB set.
    /// </summary>
    public bool IsDynamic => (DeviceId & DynamicFlag) != 0;

    /// <summary>
    /// True when the device id falls in the reserved administrative range.
    /// </summary>
    public bool IsReserved => DeviceId >= FirstReservedDeviceId;

    /// <summary>
    /// The 48-bit value, manufacturer id in bits 32 to 47.
    /// </summary>
    public ulong Value => ((ulong)ManufacturerId << 32) | DeviceId;

    /// <summary>
    /// A static (hardware) TUID. The device id must have its MSB clear.
    /// </summary>
    public static Tuid CreateStatic(ushort manufacturerId, uint deviceId)
    {
        if ((deviceId & DynamicFlag) != 0)
            throw new ArgumentOutOfRangeException(nameof(deviceId), deviceId, "A static device id must have its most significant bit clear (0x00000000 to 0x7FFFFFFF)");

        return new Tuid(manufacturerId, deviceId);
    }

    /// <summary>
    /// A new dynamic (software) TUID: 31 random bits from the CSPRNG with the MSB set, kept out
    /// of the reserved range. Permanent installations should persist it and reuse it.
    /// </summary>
    public static Tuid CreateDynamic(ushort manufacturerId)
    {
        uint deviceId;
        do
        {
            deviceId = (uint)RandomNumberGenerator.GetInt32(int.MaxValue) | DynamicFlag;
        }
        while (deviceId >= FirstReservedDeviceId);

        return new Tuid(manufacturerId, deviceId);
    }

    public static Tuid FromValue(ulong value)
    {
        if (value > 0xFFFF_FFFF_FFFF)
            throw new ArgumentOutOfRangeException(nameof(value), value, "A TUID is 48 bits");

        return new Tuid((ushort)(value >> 32), (uint)value);
    }

    public static Tuid Read(ReadOnlySpan<byte> source)
    {
        return new Tuid(BinaryPrimitives.ReadUInt16BigEndian(source), BinaryPrimitives.ReadUInt32BigEndian(source[2..]));
    }

    public void WriteTo(Span<byte> destination)
    {
        BinaryPrimitives.WriteUInt16BigEndian(destination, ManufacturerId);
        BinaryPrimitives.WriteUInt32BigEndian(destination[2..], DeviceId);
    }

    /// <summary>
    /// The canonical URI and key derivation form (spec 8.2, 7.3): 12 uppercase hex digits, no separator.
    /// </summary>
    public string ToHexString()
    {
        return $"{ManufacturerId:X4}{DeviceId:X8}";
    }

    /// <summary>
    /// The human readable form (spec 6.6): mmmm:dddddddd, uppercase.
    /// </summary>
    public override string ToString()
    {
        return $"{ManufacturerId:X4}:{DeviceId:X8}";
    }

    /// <summary>
    /// Parse either the 12-digit hex form or the mmmm:dddddddd form, case-insensitive.
    /// </summary>
    public static Tuid Parse(string text)
    {
        if (!TryParse(text, out var tuid))
            throw new FormatException($"Invalid TUID '{text}'");

        return tuid;
    }

    public static bool TryParse(ReadOnlySpan<char> text, out Tuid tuid)
    {
        tuid = default;

        ReadOnlySpan<char> manufacturer;
        ReadOnlySpan<char> device;
        if (text.Length == 12)
        {
            manufacturer = text[..4];
            device = text[4..];
        }
        else if (text.Length == 13 && text[4] == ':')
        {
            manufacturer = text[..4];
            device = text[5..];
        }
        else
        {
            return false;
        }

        if (!ushort.TryParse(manufacturer, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out ushort manufacturerId) ||
            !uint.TryParse(device, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out uint deviceId))
        {
            return false;
        }

        tuid = new Tuid(manufacturerId, deviceId);

        return true;
    }
}
