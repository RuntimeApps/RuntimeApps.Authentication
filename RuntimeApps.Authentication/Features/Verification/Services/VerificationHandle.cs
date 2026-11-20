using System.Security.Cryptography;
using System.Text;

namespace RuntimeApps.Authentication.Features.Verification.Services {
    /// <summary>Creates opaque public verification handles and their persisted SHA-256 lookup hashes.</summary>
    public static class VerificationHandle {
        public static string Create() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

        public static string ComputeHash(string handle) {
            ArgumentException.ThrowIfNullOrWhiteSpace(handle);
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(handle)));
        }
    }
}
