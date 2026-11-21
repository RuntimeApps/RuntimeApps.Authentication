using RuntimeApps.Authentication.Features.Verification.Models;
namespace RuntimeApps.Authentication.Features.Verification.Contracts {
    public interface IVerificationCodeVerifier<TKey> where TKey : IEquatable<TKey> {
        string CreateVerifier(string code, VerificationRequest<TKey> request);
        bool Verify(string code, VerificationRequest<TKey> request);
    }
}
