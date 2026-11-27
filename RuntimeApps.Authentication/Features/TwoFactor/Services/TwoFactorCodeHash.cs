using System.Security.Cryptography;
using System.Text;

namespace RuntimeApps.Authentication.Features.TwoFactor.Services;

/// <summary>Computes the value stored in the used-code ledger so raw codes are never persisted.</summary>
public static class TwoFactorCodeHash {
    /// <summary>
    /// SHA-256 (hex) over the user key, method and code. The user key is length-prefixed so different
    /// combinations cannot produce the same input. Pass the already-normalized code.
    /// </summary>
    public static string Compute(string userKey, string method, string code) {
        ArgumentException.ThrowIfNullOrEmpty(userKey);
        ArgumentException.ThrowIfNullOrEmpty(method);
        ArgumentException.ThrowIfNullOrEmpty(code);
        var input = $"{userKey.Length}:{userKey}|{method}|{code}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input)));
    }
}
