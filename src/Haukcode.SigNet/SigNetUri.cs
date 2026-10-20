namespace Haukcode.SigNet;

/// <summary>
/// Sig-Net URI-Path helpers (spec 8.2).
/// </summary>
public static class SigNetUri
{
    public const string DefaultScope = "local";

    public const int MaxScopeLength = 32;

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

    private static bool IsUnreserved(char c)
    {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~';
    }
}
