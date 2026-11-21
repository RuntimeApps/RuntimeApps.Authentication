using RuntimeApps.Authentication.Features.Verification.Models;
namespace RuntimeApps.Authentication.Features.Verification.Contracts {
    public interface IVerificationCodeGenerator<TUser, TKey> where TKey : IEquatable<TKey> {
        Task<string> GenerateAsync(
            VerificationCodeContext<TUser, TKey> context,
            VerificationOptions options,
            CancellationToken cancellationToken = default);
    }
}
