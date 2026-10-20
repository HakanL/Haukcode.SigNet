using System;
using Xunit;

namespace Haukcode.SigNet.UnitTest;

public class IdentityTests
{
    [Fact]
    public void Tuid_FormatsAndParses()
    {
        var tuid = new Tuid(0x0744, 0x00ABCDEF);

        Assert.Equal("074400ABCDEF", tuid.ToHexString());
        Assert.Equal("0744:00ABCDEF", tuid.ToString());
        Assert.Equal(tuid, Tuid.Parse("074400abcdef"));
        Assert.Equal(tuid, Tuid.Parse("0744:00ABCDEF"));
        Assert.Equal(0x074400ABCDEFUL, tuid.Value);
        Assert.Equal(tuid, Tuid.FromValue(tuid.Value));
        Assert.False(Tuid.TryParse("0744:00ABCDE", out _));
    }

    [Fact]
    public void Tuid_ReadsAndWritesBigEndian()
    {
        var tuid = Tuid.Parse("123456789ABC");
        var buffer = new byte[6];

        tuid.WriteTo(buffer);

        Assert.Equal(new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC }, buffer);
        Assert.Equal(tuid, Tuid.Read(buffer));
    }

    [Fact]
    public void Tuid_StaticRejectsDynamicRange()
    {
        Assert.False(Tuid.CreateStatic(0x0744, 1).IsDynamic);
        Assert.Throws<ArgumentOutOfRangeException>(() => Tuid.CreateStatic(0x0744, 0x80000000));
    }

    [Fact]
    public void Tuid_DynamicHasMsbSetAndAvoidsReservedRange()
    {
        for (int i = 0; i < 1000; i++)
        {
            var tuid = Tuid.CreateDynamic(0x0744);

            Assert.True(tuid.IsDynamic);
            Assert.False(tuid.IsReserved);
            Assert.Equal(0x0744, tuid.ManufacturerId);
        }
    }

    [Fact]
    public void SenderId_IsTuidThenEndpoint()
    {
        var senderId = new SenderId(Tuid.Parse("123456789ABC"), 1);
        var buffer = new byte[8];

        senderId.WriteTo(buffer);

        Assert.Equal(Convert.FromHexString("123456789ABC0001"), buffer);
        Assert.Equal(senderId, SenderId.Read(buffer));
        Assert.Equal(0x123456789ABC0001UL, senderId.Value);
        Assert.Equal(senderId, SenderId.FromValue(senderId.Value));
    }

    [Fact]
    public void SoemCode_IsManufacturerThenVariant()
    {
        uint soemCode = SoemCode.Create(0x0744, 0x0010);

        Assert.Equal(0x07440010U, soemCode);
        Assert.Equal(0x0744, SoemCode.GetManufacturerId(soemCode));
        Assert.Equal(0x0010, SoemCode.GetProductVariant(soemCode));
        Assert.Throws<ArgumentException>(() => SoemCode.Create(0, 0));
    }
}
