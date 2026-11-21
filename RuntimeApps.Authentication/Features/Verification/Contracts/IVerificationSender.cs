using RuntimeApps.Authentication.Features.Verification.Models;
namespace RuntimeApps.Authentication.Features.Verification.Contracts {
    public interface IVerificationSender<TUser, TKey> where TKey : IEquatable<TKey> {
        Task SendAsync(
            VerificationCodeContext<TUser, TKey> context,
            string code,
            DateTimeOffset expiresAt,
            CancellationToken cancellationToken = default);
    }
}
