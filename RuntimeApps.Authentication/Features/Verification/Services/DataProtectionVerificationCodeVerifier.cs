using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using RuntimeApps.Authentication.Features.Verification.Contracts;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Features.Verification.Models;
namespace RuntimeApps.Authentication.Features.Verification.Services {
    /// <summary>
    /// Protects verification codes with ASP.NET Core Data Protection and binds them to
    /// the request, user, purpose, channel, and destination.
    /// </summary>
    public sealed class DataProtectionVerificationCodeVerifier<TKey> : IVerificationCodeVerifier<TKey>
        where TKey : IEquatable<TKey> {
        private readonly IDataProtector _protector;

        public DataProtectionVerificationCodeVerifier(IDataProtectionProvider provider) {
            ArgumentNullException.ThrowIfNull(provider);
            _protector = provider.CreateProtector("RuntimeApps.Authentication.VerificationCode.v1");
        }

        public string CreateVerifier(string code, VerificationRequest<TKey> request) {
            ArgumentException.ThrowIfNullOrEmpty(code);
            ArgumentNullException.ThrowIfNull(request);

            var payload = JsonSerializer.Serialize(new VerificationCodePayload(
                Convert.ToString(request.Id, CultureInfo.InvariantCulture),
                Convert.ToString(request.UserId, CultureInfo.InvariantCulture),
                request.Purpose,
                request.Channel,
                request.CustomPurpose,
                request.CustomChannel,
                request.NormalizedDestination,
                code));

            return _protector.Protect(payload);
        }

        public bool Verify(string code, VerificationRequest<TKey> request) {
            if(string.IsNullOrEmpty(code) || request?.CodeVerifier == null)
                return false;

            try {
                var payload = JsonSerializer.Deserialize<VerificationCodePayload>(
                    _protector.Unprotect(request.CodeVerifier));
                if(payload == null ||
                   payload.RequestId != Convert.ToString(request.Id, CultureInfo.InvariantCulture) ||
                   payload.UserId != Convert.ToString(request.UserId, CultureInfo.InvariantCulture) ||
                   payload.Purpose != request.Purpose ||
                   payload.Channel != request.Channel ||
                   payload.CustomPurpose != request.CustomPurpose ||
                   payload.CustomChannel != request.CustomChannel ||
                   payload.Destination != request.NormalizedDestination)
                    return false;

                var expected = Encoding.UTF8.GetBytes(payload.Code);
                var supplied = Encoding.UTF8.GetBytes(code);
                return expected.Length == supplied.Length &&
                       CryptographicOperations.FixedTimeEquals(expected, supplied);
            } catch(CryptographicException) {
                return false;
            } catch(JsonException) {
                return false;
            }
        }

        private sealed record VerificationCodePayload(
            string RequestId,
            string UserId,
            VerificationPurpose Purpose,
            VerificationChannel Channel,
            string CustomPurpose,
            string CustomChannel,
            string Destination,
            string Code);
    }
}
