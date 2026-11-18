using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Interface {
    public interface IVerificationSender<TUser, TKey> where TKey : IEquatable<TKey> {
        Task SendAsync(
            VerificationCodeContext<TUser, TKey> context,
            string code,
            DateTimeOffset expiresAt,
            CancellationToken cancellationToken = default);
    }
}