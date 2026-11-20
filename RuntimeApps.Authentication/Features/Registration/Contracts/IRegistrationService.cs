using RuntimeApps.Authentication.Features.Registration.Models;
using RuntimeApps.Authentication.Shared.Models;
namespace RuntimeApps.Authentication.Features.Registration.Contracts {
    public interface IRegistrationService<TUser, TKey> where TKey : IEquatable<TKey> {
        Task<Result<RegistrationVerificationResponse>> RegisterAsync(
            TUser user, string password, CancellationToken cancellationToken = default);

        Task<Result<TUser, Token>> VerifyAsync(
            string verificationHandle, string code, CancellationToken cancellationToken = default);

        Task<Result<RegistrationVerificationResponse>> ResendAsync(
            string verificationHandle, CancellationToken cancellationToken = default);
    }
}
