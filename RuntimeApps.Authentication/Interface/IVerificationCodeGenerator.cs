using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Interface {
    public interface IVerificationCodeGenerator<TUser, TKey> where TKey : IEquatable<TKey> {
        Task<string> GenerateAsync(
            VerificationCodeContext<TUser, TKey> context,
            VerificationOptions options,
            CancellationToken cancellationToken = default);
    }
}