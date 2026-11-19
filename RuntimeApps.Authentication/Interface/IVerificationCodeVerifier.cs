using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Interface {
    public interface IVerificationCodeVerifier<TKey> where TKey : IEquatable<TKey> {
        string CreateVerifier(string code, VerificationRequest<TKey> request);
        bool Verify(string code, VerificationRequest<TKey> request);
    }
}