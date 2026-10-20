using System;
using Haukcode.SigNet.Keys;
using Xunit;

namespace Haukcode.SigNet.UnitTest;

/// <summary>
/// Spec Appendix G (normative) key derivation vectors, plus the vector published in the
/// reference SDK's README.
/// </summary>
public class KeyDerivationTests
{
    internal const string AppendixGPassphrase = "SigNetT3stVector1!";
    internal const string AppendixGRootKey = "06577c606a72282988c7919752b72a52380b57ff49118091dea5815dc148d3e3";
    internal const string AppendixGSenderKey = "23ffd543990f2253c884af7fc6c47255aa1606a4f2f30e082381bb17c9a6c242";
    internal const string AppendixGCitizenKey = "eac261f8782065387816c0c9ea72aa8083565eb871a3392363a5b31611a26f81";
    internal const string AppendixGManagerGlobalKey = "c00b7fefaaff7ba30821019bc99526c6be58ad0fba3ea3f27f378db344043457";
    internal const string AppendixGManagerLocalKey = "8f41d6df9a5ac9d8f8c7c0580a0c5fb90026154dd2dca6469cc3929ec5bb4889";
    internal static readonly Tuid AppendixGTuid = Tuid.Parse("123456789ABC");

    [Fact]
    public void RootKey_FromPassphrase_MatchesAppendixG()
    {
        Assert.Equal(AppendixGRootKey, Convert.ToHexStringLower(KeyDerivation.DeriveRootKey(AppendixGPassphrase)));
    }

    [Fact]
    public void RoleKeys_MatchAppendixG()
    {
        byte[] rootKey = Convert.FromHexString(AppendixGRootKey);

        Assert.Equal(AppendixGSenderKey, Convert.ToHexStringLower(KeyDerivation.DeriveSenderKey(rootKey)));
        Assert.Equal(AppendixGCitizenKey, Convert.ToHexStringLower(KeyDerivation.DeriveCitizenKey(rootKey)));
        Assert.Equal(AppendixGManagerGlobalKey, Convert.ToHexStringLower(KeyDerivation.DeriveManagerGlobalKey(rootKey)));
        Assert.Equal(AppendixGManagerLocalKey, Convert.ToHexStringLower(KeyDerivation.DeriveManagerLocalKey(rootKey, AppendixGTuid)));
    }

    [Fact]
    public void Keys_FromPassphrase_MatchAppendixG()
    {
        using var keys = SigNetKeys.FromPassphrase(AppendixGPassphrase, AppendixGTuid);

        Assert.Equal(AppendixGSenderKey, Convert.ToHexStringLower(keys.SenderKey));
        Assert.Equal(AppendixGCitizenKey, Convert.ToHexStringLower(keys.CitizenKey));
        Assert.Equal(AppendixGManagerGlobalKey, Convert.ToHexStringLower(keys.ManagerGlobalKey));
        Assert.Equal(AppendixGManagerLocalKey, Convert.ToHexStringLower(keys.ManagerLocalKey));
        Assert.Equal(AppendixGManagerLocalKey, Convert.ToHexStringLower(keys.GetKey(SigNetKeyRole.ManagerLocal)));
    }

    [Fact]
    public void Keys_MatchSdkReadmeVector()
    {
        // WayneHowell/public-sig-net-sdk README, V0.3 notes
        byte[] rootKey = KeyDerivation.DeriveRootKey("Ge2p$E$4*A");
        Assert.Equal("52fcc2e7749f40358ba00b1d557dc11861e89868e139f23014f6a0cfe59cf173", Convert.ToHexStringLower(rootKey));

        Assert.Equal("78981fe02576b2e9e47d916853d5967f34f8ae8aaae46db0495b178a75620e89", Convert.ToHexStringLower(KeyDerivation.DeriveSenderKey(rootKey)));
        Assert.Equal("1973cecb72f2506f8b5c442c565f0c6a68aee8a873b8ef26e957b88a7fc54b80", Convert.ToHexStringLower(KeyDerivation.DeriveCitizenKey(rootKey)));
        Assert.Equal("2f6b76ffe666dc65504be86828277ec9ef8a04fe329652c233ab537ad434fa0d", Convert.ToHexStringLower(KeyDerivation.DeriveManagerGlobalKey(rootKey)));
    }

    [Fact]
    public void FromPassphrase_RejectsInvalidPassphraseWithSpecificMessage()
    {
        var ex = Assert.Throws<ArgumentException>(() => SigNetKeys.FromPassphrase("aaaBBB111!", AppendixGTuid));
        Assert.Contains("identical", ex.Message);
    }

    [Fact]
    public void Dispose_ZeroesAndBlocksAccess()
    {
        var keys = SigNetKeys.FromRootKey(Convert.FromHexString(AppendixGRootKey), AppendixGTuid);
        keys.Dispose();

        Assert.Throws<ObjectDisposedException>(() => keys.SenderKey.ToArray());
    }

    [Fact]
    public void GuestKeys_HaveNoManagerLocalKey()
    {
        using var keys = SigNetKeys.FromDerivedKeys(
            Convert.FromHexString(AppendixGSenderKey),
            Convert.FromHexString(AppendixGCitizenKey),
            Convert.FromHexString(AppendixGManagerGlobalKey));

        Assert.False(keys.HasManagerLocalKey);
        Assert.True(keys.ManagerLocalKey.IsEmpty);
    }
}
