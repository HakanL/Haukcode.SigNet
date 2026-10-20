namespace Haukcode.SigNet;

/// <summary>
/// SoemCode (spec 6.5): a 32-bit product code with the ESTA manufacturer id in the upper 16 bits
/// and a manufacturer-managed product variant id in the lower 16. Zero is reserved. Reporting a
/// correct SoemCode is a Sig-Net license condition, so the library always takes it from the caller.
/// </summary>
public static class SoemCode
{
    public static uint Create(ushort manufacturerId, ushort productVariant)
    {
        uint soemCode = ((uint)manufacturerId << 16) | productVariant;
        if (soemCode == 0)
            throw new ArgumentException("SoemCode 0x00000000 is reserved");

        return soemCode;
    }

    public static ushort GetManufacturerId(uint soemCode)
    {
        return (ushort)(soemCode >> 16);
    }

    public static ushort GetProductVariant(uint soemCode)
    {
        return (ushort)soemCode;
    }
}
