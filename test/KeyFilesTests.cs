using System;
using Haukcode.SigNet.Keys;
using Xunit;

namespace Haukcode.SigNet.UnitTest;

public class KeyFilesTests
{
    [Fact]
    public void EqualKeys_RoundTripAsUppercaseHex()
    {
        byte[] rootKey = Convert.FromHexString(KeyDerivationTests.AppendixGRootKey);

        string json = KeyFiles.WriteEqualKeys(new EqualKeysFile("Hall_A", rootKey));

        Assert.Contains("\"sig-net_equal_keys\"", json);
        Assert.Contains(KeyDerivationTests.AppendixGRootKey.ToUpperInvariant(), json);

        var file = KeyFiles.ReadEqualKeys(json);
        Assert.Equal("Hall_A", file.Scope);
        Assert.Equal(rootKey, file.RootKey);
    }

    [Fact]
    public void EqualKeys_ParseHexCaseInsensitively()
    {
        string json = "{ \"sig-net_equal_keys\": { \"scope\": \"local\", \"k0\": \"" + KeyDerivationTests.AppendixGRootKey + "\" } }";

        Assert.Equal(Convert.FromHexString(KeyDerivationTests.AppendixGRootKey), KeyFiles.ReadEqualKeys(json).RootKey);
    }

    [Fact]
    public void GuestKeys_RoundTripIntoUsableKeys()
    {
        var file = new GuestKeysFile("local",
            Convert.FromHexString(KeyDerivationTests.AppendixGManagerGlobalKey),
            Convert.FromHexString(KeyDerivationTests.AppendixGSenderKey),
            Convert.FromHexString(KeyDerivationTests.AppendixGCitizenKey));

        string json = KeyFiles.WriteGuestKeys(file);
        Assert.Contains("\"km_global\"", json);
        Assert.DoesNotContain("k0", json);

        using var keys = KeyFiles.ReadGuestKeys(json).ToKeys();
        Assert.Equal(KeyDerivationTests.AppendixGSenderKey, Convert.ToHexStringLower(keys.SenderKey));
        Assert.False(keys.HasManagerLocalKey);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{ \"sig-net_equal_keys\": { \"scope\": \"local\", \"k0\": \"1234\" } }")]
    [InlineData("{ \"sig-net_equal_keys\": { \"scope\": \"bad scope\", \"k0\": \"06577c606a72282988c7919752b72a52380b57ff49118091dea5815dc148d3e3\" } }")]
    public void EqualKeys_RejectMalformed(string json)
    {
        Assert.ThrowsAny<Exception>(() => KeyFiles.ReadEqualKeys(json));
    }
}
