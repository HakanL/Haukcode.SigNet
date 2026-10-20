namespace Haukcode.SigNet.Keys;

public enum PassphraseValidationResult
{
    Valid = 0,

    TooShort,

    TooLong,

    InsufficientClasses,

    ConsecutiveIdentical,

    ConsecutiveSequential,

    /// <summary>
    /// Not part of the reference routine: a character outside printable ASCII (0x20 to 0x7E).
    /// </summary>
    InvalidCharacter
}

/// <summary>
/// The individual checks behind a <see cref="PassphraseValidationResult"/>, for user interfaces
/// that show every rule's state rather than only the first failure.
/// </summary>
public readonly record struct PassphraseChecks(
    int Length,
    bool LengthOk,
    bool HasUpper,
    bool HasLower,
    bool HasDigit,
    bool HasSymbol,
    int ClassCount,
    bool ClassesOk,
    bool NoIdenticalRun,
    bool NoSequentialRun,
    bool AsciiOnly);

/// <summary>
/// Passphrase rules of spec 7.2.3, ported from the normative reference routine in the Sig-Net SDK
/// (AnalysePassphrase in sig-net-crypto.cpp, WayneHowell/public-sig-net-sdk at bc7c3fe). The spec
/// requires implementations to behave identically to that routine, including the order in which
/// a failing passphrase is reported: identical run, sequential run, character classes, length.
/// </summary>
public static class PassphraseValidator
{
    public const int MinLength = 10;

    public const int MaxLength = 64;

    /// <summary>
    /// The symbol class of spec 7.2.3, identical to PASSPHRASE_SYMBOLS in the SDK.
    /// </summary>
    public const string Symbols = "!@#$%^&*()-_=+[]{}|;:',.<>?/";

    public static PassphraseValidationResult Validate(string passphrase)
    {
        return Analyse(passphrase, out _);
    }

    public static PassphraseValidationResult Analyse(string passphrase, out PassphraseChecks checks)
    {
        ArgumentNullException.ThrowIfNull(passphrase);

        int length = passphrase.Length;
        bool lengthOk = length >= MinLength && length <= MaxLength;

        bool hasUpper = false, hasLower = false, hasDigit = false, hasSymbol = false, asciiOnly = true;
        foreach (char c in passphrase)
        {
            if (c >= 'A' && c <= 'Z')
                hasUpper = true;
            else if (c >= 'a' && c <= 'z')
                hasLower = true;
            else if (c >= '0' && c <= '9')
                hasDigit = true;
            else if (Symbols.Contains(c))
                hasSymbol = true;

            if (c < 0x20 || c > 0x7E)
                asciiOnly = false;
        }

        int classCount = (hasUpper ? 1 : 0) + (hasLower ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSymbol ? 1 : 0);
        bool noIdentical = !HasIdenticalRun(passphrase);
        bool noSequential = !HasSequentialRun(passphrase);

        checks = new PassphraseChecks(length, lengthOk, hasUpper, hasLower, hasDigit, hasSymbol, classCount, classCount >= 3, noIdentical, noSequential, asciiOnly);

        // The reference routine returns TOO_SHORT straight away for an empty passphrase
        if (length == 0)
            return PassphraseValidationResult.TooShort;

        // TODO (spec 7.2.3): the reference routine accepts any byte; the spec says the passphrase
        // is ASCII and PBKDF2 over anything else depends on the text encoding. Rejecting non-ASCII
        // here is the one deliberate difference from the reference.
        if (!asciiOnly)
            return PassphraseValidationResult.InvalidCharacter;

        if (!noIdentical)
            return PassphraseValidationResult.ConsecutiveIdentical;

        if (!noSequential)
            return PassphraseValidationResult.ConsecutiveSequential;

        if (classCount < 3)
            return PassphraseValidationResult.InsufficientClasses;

        if (!lengthOk)
            return length < MinLength ? PassphraseValidationResult.TooShort : PassphraseValidationResult.TooLong;

        return PassphraseValidationResult.Valid;
    }

    /// <summary>
    /// The specific message the spec requires instead of a generic "weak passphrase" (spec 7.2.3).
    /// Wording follows the reference implementation.
    /// </summary>
    public static string GetMessage(PassphraseValidationResult result)
    {
        return result switch
        {
            PassphraseValidationResult.Valid => "Passphrase valid.",
            PassphraseValidationResult.TooShort => $"Too short (minimum {MinLength} characters).",
            PassphraseValidationResult.TooLong => $"Too long (maximum {MaxLength} characters).",
            PassphraseValidationResult.InsufficientClasses => "Need 3+ character classes (Uppercase, Lowercase, Digits, Symbols).",
            PassphraseValidationResult.ConsecutiveIdentical => "More than 2 identical characters in a row.",
            PassphraseValidationResult.ConsecutiveSequential => "More than 3 sequential characters in a row.",
            PassphraseValidationResult.InvalidCharacter => "Only printable ASCII characters are allowed.",
            _ => "Passphrase not ready."
        };
    }

    // HasIdenticalRun in the reference: three equal characters in a row
    private static bool HasIdenticalRun(string p)
    {
        for (int i = 0; i + 2 < p.Length; i++)
        {
            if (p[i] == p[i + 1] && p[i] == p[i + 2])
                return true;
        }

        return false;
    }

    // HasSequentialRun in the reference: four characters ascending or descending by one code
    // point, over any characters (so "!\"#$" counts as well as "abcd" and "4321")
    private static bool HasSequentialRun(string p)
    {
        for (int i = 0; i + 3 < p.Length; i++)
        {
            int c = p[i];
            if (p[i + 1] == c + 1 && p[i + 2] == c + 2 && p[i + 3] == c + 3)
                return true;
            if (p[i + 1] == c - 1 && p[i + 2] == c - 2 && p[i + 3] == c - 3)
                return true;
        }

        return false;
    }
}
