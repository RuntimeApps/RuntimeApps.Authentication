using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Interface {
    public interface IRegistrationService<TUser, TKey> where TKey : IEquatable<TKey> {
        Task<Result<RegistrationVerificationResponse>> RegisterAsync(
            TUser user, string password, CancellationToken cancellationToken = default);

        Task<Result<TUser, Token>> VerifyAsync(
            string verificationHandle, string code, CancellationToken cancellationToken = default);

        Task<Result<RegistrationVerificationResponse>> ResendAsync(
            string verificationHandle, CancellationToken cancellationToken = default);
    }
}