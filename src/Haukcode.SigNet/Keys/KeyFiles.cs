using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Haukcode.SigNet.Keys;

/// <summary>
/// Contents of a .equalkeys file (spec 7.5): the scope and K0.
/// </summary>
public sealed record EqualKeysFile(string Scope, byte[] RootKey);

/// <summary>
/// Contents of a .guestkeys file (spec 7.5.1): the scope and the three global keys, no K0 and
/// no Km_local.
/// </summary>
public sealed record GuestKeysFile(string Scope, byte[] ManagerGlobalKey, byte[] SenderKey, byte[] CitizenKey);

/// <summary>
/// The machine readable key transfer formats of spec 7.5. Keys are written as 64 uppercase hex
/// characters and parsed case-insensitively (spec 7.4).
/// </summary>
public static class KeyFiles
{
    public const string EqualKeysExtension = ".equalkeys";

    public const string GuestKeysExtension = ".guestkeys";

    // TODO (spec 7.5): the PDF text renders the object names as "sig - net_equal_keys" and
    // "sig - net_guest_keys"; the spaces are taken to be typesetting artifacts.
    public const string EqualKeysObjectName = "sig-net_equal_keys";

    public const string GuestKeysObjectName = "sig-net_guest_keys";

    private static readonly JsonSerializerOptions writeOptions = new() { WriteIndented = true };

    public static string WriteEqualKeys(EqualKeysFile file)
    {
        ArgumentNullException.ThrowIfNull(file);
        SigNetUri.CheckScope(file.Scope);

        var root = new JsonObject
        {
            [EqualKeysObjectName] = new JsonObject
            {
                ["scope"] = file.Scope,
                ["k0"] = ToHex(file.RootKey, "k0")
            }
        };

        return root.ToJsonString(writeOptions);
    }

    public static EqualKeysFile ReadEqualKeys(string json)
    {
        var body = ReadBody(json, EqualKeysObjectName);

        return new EqualKeysFile(ReadScope(body), ReadKey(body, "k0"));
    }

    public static string WriteGuestKeys(GuestKeysFile file)
    {
        ArgumentNullException.ThrowIfNull(file);
        SigNetUri.CheckScope(file.Scope);

        var root = new JsonObject
        {
            [GuestKeysObjectName] = new JsonObject
            {
                ["scope"] = file.Scope,
                ["km_global"] = ToHex(file.ManagerGlobalKey, "km_global"),
                ["ks"] = ToHex(file.SenderKey, "ks"),
                ["kc"] = ToHex(file.CitizenKey, "kc")
            }
        };

        return root.ToJsonString(writeOptions);
    }

    public static GuestKeysFile ReadGuestKeys(string json)
    {
        var body = ReadBody(json, GuestKeysObjectName);

        return new GuestKeysFile(ReadScope(body), ReadKey(body, "km_global"), ReadKey(body, "ks"), ReadKey(body, "kc"));
    }

    /// <summary>
    /// Load a guest key set as keys for a client. The arrays read from the file are zeroed.
    /// </summary>
    public static SigNetKeys ToKeys(this GuestKeysFile file)
    {
        try
        {
            return SigNetKeys.FromDerivedKeys(file.SenderKey, file.CitizenKey, file.ManagerGlobalKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(file.SenderKey);
            CryptographicOperations.ZeroMemory(file.CitizenKey);
            CryptographicOperations.ZeroMemory(file.ManagerGlobalKey);
        }
    }

    private static JsonObject ReadBody(string json, string objectName)
    {
        ArgumentNullException.ThrowIfNull(json);

        var root = JsonNode.Parse(json) as JsonObject ?? throw new FormatException("Expected a JSON object");
        if (root[objectName] is not JsonObject body)
            throw new FormatException($"Missing \"{objectName}\" object");

        return body;
    }

    private static string ReadScope(JsonObject body)
    {
        string scope = body["scope"]?.GetValue<string>() ?? throw new FormatException("Missing \"scope\"");
        SigNetUri.CheckScope(scope);

        return scope;
    }

    private static byte[] ReadKey(JsonObject body, string name)
    {
        string hex = body[name]?.GetValue<string>() ?? throw new FormatException($"Missing \"{name}\"");
        if (hex.Length != KeyDerivation.KeyLength * 2)
            throw new FormatException($"\"{name}\" must be {KeyDerivation.KeyLength * 2} hex characters");

        // Convert.FromHexString is case-insensitive, as spec 7.4 requires for machine input
        return Convert.FromHexString(hex);
    }

    private static string ToHex(byte[] key, string name)
    {
        if (key == null || key.Length != KeyDerivation.KeyLength)
            throw new ArgumentException($"\"{name}\" must be {KeyDerivation.KeyLength} bytes");

        return Convert.ToHexString(key);
    }
}
