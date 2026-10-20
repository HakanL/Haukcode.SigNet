using System.Security.Cryptography;

namespace Haukcode.SigNet.Keys;

/// <summary>
/// The derived key a packet is signed or verified with, chosen by its URI (spec Appendix A).
/// </summary>
public enum SigNetKeyRole
{
    /// <summary>No key: offboarded beacons (Security-Mode 0xFF).</summary>
    None = 0,

    /// <summary>Ks: level, priority, sync, timecode, preview and aux traffic.</summary>
    Sender,

    /// <summary>Kc: /node and /node_lost replies and announcements.</summary>
    Citizen,

    /// <summary>Km_global: /poll discovery requests.</summary>
    ManagerGlobal,

    /// <summary>Km_local: /manager/{tuid} commands to one device.</summary>
    ManagerLocal
}

/// <summary>
/// The role keys a Node, Sender or Visualiser keeps after onboarding (spec 7.6): Ks, Kc,
/// Km_global and, for a device that derived them from K0 itself, its own Km_local. K0 and the
/// passphrase are never kept. The arrays are zeroed on dispose.
///
/// Storage is the host application's job. Spec 7.6 requires hardware-protected or encrypted
/// storage and forbids exporting the derived keys in backups or over any interface.
/// </summary>
public sealed class SigNetKeys : IDisposable
{
    private readonly byte[] senderKey;
    private readonly byte[] citizenKey;
    private readonly byte[] managerGlobalKey;
    private readonly byte[]? managerLocalKey;
    private bool disposed;

    private SigNetKeys(byte[] senderKey, byte[] citizenKey, byte[] managerGlobalKey, byte[]? managerLocalKey)
    {
        this.senderKey = senderKey;
        this.citizenKey = citizenKey;
        this.managerGlobalKey = managerGlobalKey;
        this.managerLocalKey = managerLocalKey;
    }

    /// <summary>
    /// Derive all role keys, including Km_local for <paramref name="tuid"/>, from a passphrase.
    /// The passphrase must pass <see cref="PassphraseValidator"/>; K0 is zeroed before returning.
    /// </summary>
    public static SigNetKeys FromPassphrase(string passphrase, Tuid tuid)
    {
        var result = PassphraseValidator.Validate(passphrase);
        if (result != PassphraseValidationResult.Valid)
            throw new ArgumentException(PassphraseValidator.GetMessage(result), nameof(passphrase));

        byte[] rootKey = KeyDerivation.DeriveRootKey(passphrase);
        try
        {
            return FromRootKey(rootKey, tuid);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rootKey);
        }
    }

    /// <summary>
    /// Derive all role keys from a 32-byte K0 delivered out-of-band (spec 7.5). The caller should
    /// zero its copy of K0 afterwards (spec 7.3.2).
    /// </summary>
    public static SigNetKeys FromRootKey(ReadOnlySpan<byte> rootKey, Tuid tuid)
    {
        KeyDerivation.CheckRootKey(rootKey);

        return new SigNetKeys(
            KeyDerivation.DeriveSenderKey(rootKey),
            KeyDerivation.DeriveCitizenKey(rootKey),
            KeyDerivation.DeriveManagerGlobalKey(rootKey),
            KeyDerivation.DeriveManagerLocalKey(rootKey, tuid));
    }

    /// <summary>
    /// Keys loaded from the host's secure storage, or a guest key set (spec 7.5.1) when
    /// <paramref name="managerLocalKey"/> is empty. Without Km_local the device cannot verify
    /// /manager commands addressed to it.
    /// </summary>
    public static SigNetKeys FromDerivedKeys(ReadOnlySpan<byte> senderKey, ReadOnlySpan<byte> citizenKey, ReadOnlySpan<byte> managerGlobalKey, ReadOnlySpan<byte> managerLocalKey = default)
    {
        CheckKey(senderKey, nameof(senderKey));
        CheckKey(citizenKey, nameof(citizenKey));
        CheckKey(managerGlobalKey, nameof(managerGlobalKey));
        if (!managerLocalKey.IsEmpty)
            CheckKey(managerLocalKey, nameof(managerLocalKey));

        return new SigNetKeys(senderKey.ToArray(), citizenKey.ToArray(), managerGlobalKey.ToArray(), managerLocalKey.IsEmpty ? null : managerLocalKey.ToArray());
    }

    public ReadOnlySpan<byte> SenderKey => Check(this.senderKey);

    public ReadOnlySpan<byte> CitizenKey => Check(this.citizenKey);

    public ReadOnlySpan<byte> ManagerGlobalKey => Check(this.managerGlobalKey);

    /// <summary>
    /// Empty for a guest key set.
    /// </summary>
    public ReadOnlySpan<byte> ManagerLocalKey => this.managerLocalKey == null ? ReadOnlySpan<byte>.Empty : Check(this.managerLocalKey);

    public bool HasManagerLocalKey => this.managerLocalKey != null;

    /// <summary>
    /// The key for a role, or an empty span when this set does not hold it.
    /// </summary>
    public ReadOnlySpan<byte> GetKey(SigNetKeyRole role)
    {
        return role switch
        {
            SigNetKeyRole.Sender => SenderKey,
            SigNetKeyRole.Citizen => CitizenKey,
            SigNetKeyRole.ManagerGlobal => ManagerGlobalKey,
            SigNetKeyRole.ManagerLocal => ManagerLocalKey,
            _ => ReadOnlySpan<byte>.Empty
        };
    }

    public void Dispose()
    {
        if (this.disposed)
            return;

        this.disposed = true;
        CryptographicOperations.ZeroMemory(this.senderKey);
        CryptographicOperations.ZeroMemory(this.citizenKey);
        CryptographicOperations.ZeroMemory(this.managerGlobalKey);
        if (this.managerLocalKey != null)
            CryptographicOperations.ZeroMemory(this.managerLocalKey);
    }

    private ReadOnlySpan<byte> Check(byte[] key)
    {
        ObjectDisposedException.ThrowIf(this.disposed, this);

        return key;
    }

    private static void CheckKey(ReadOnlySpan<byte> key, string paramName)
    {
        if (key.Length != KeyDerivation.KeyLength)
            throw new ArgumentException($"Derived keys are {KeyDerivation.KeyLength} bytes", paramName);
    }
}
