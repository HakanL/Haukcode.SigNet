using System.Security.Cryptography;
using System.Text;

namespace Haukcode.SigNet.Keys;

/// <summary>
/// Root key and role key derivation (spec 7.2.3 and 7.3).
/// </summary>
public static class KeyDerivation
{
    public const int KeyLength = 32;

    public const int Pbkdf2Iterations = 100_000;

    public const string Pbkdf2Salt = "Sig-Net-K0-Salt-v1";

    public const string SenderInfo = "Sig-Net-Sender-v1";

    public const string CitizenInfo = "Sig-Net-Citizen-v1";

    public const string ManagerGlobalInfo = "Sig-Net-Manager-v1";

    public const string ManagerLocalInfoPrefix = "Sig-Net-Manager-v1-";

    /// <summary>
    /// K0 from a passphrase: PBKDF2-HMAC-SHA256, 100,000 iterations, fixed 18-byte ASCII salt.
    /// The passphrase is not validated here, see <see cref="PassphraseValidator"/>. The caller
    /// owns the returned key and should zero it once the role keys are derived (spec 7.3.2).
    /// </summary>
    public static byte[] DeriveRootKey(string passphrase)
    {
        ArgumentNullException.ThrowIfNull(passphrase);

        byte[] passphraseBytes = Encoding.ASCII.GetBytes(passphrase);
        try
        {
            return Rfc2898DeriveBytes.Pbkdf2(passphraseBytes, Encoding.ASCII.GetBytes(Pbkdf2Salt), Pbkdf2Iterations, HashAlgorithmName.SHA256, KeyLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passphraseBytes);
        }
    }

    /// <summary>
    /// HKDF-Expand (RFC 5869 section 2.3) with K0 as the PRK and L = 32, which reduces to
    /// HMAC-SHA256(K0, info || 0x01).
    /// </summary>
    public static byte[] Expand(ReadOnlySpan<byte> rootKey, string info)
    {
        CheckRootKey(rootKey);

        var output = new byte[KeyLength];
        HKDF.Expand(HashAlgorithmName.SHA256, rootKey, output, Encoding.ASCII.GetBytes(info));

        return output;
    }

    public static byte[] DeriveSenderKey(ReadOnlySpan<byte> rootKey) => Expand(rootKey, SenderInfo);

    public static byte[] DeriveCitizenKey(ReadOnlySpan<byte> rootKey) => Expand(rootKey, CitizenInfo);

    public static byte[] DeriveManagerGlobalKey(ReadOnlySpan<byte> rootKey) => Expand(rootKey, ManagerGlobalInfo);

    /// <summary>
    /// Km_local for one device: the info string is the prefix plus the 12-character uppercase hex TUID.
    /// </summary>
    public static byte[] DeriveManagerLocalKey(ReadOnlySpan<byte> rootKey, Tuid tuid) => Expand(rootKey, ManagerLocalInfoPrefix + tuid.ToHexString());

    internal static void CheckRootKey(ReadOnlySpan<byte> rootKey)
    {
        if (rootKey.Length != KeyLength)
            throw new ArgumentException($"K0 must be {KeyLength} bytes", nameof(rootKey));
    }
}
