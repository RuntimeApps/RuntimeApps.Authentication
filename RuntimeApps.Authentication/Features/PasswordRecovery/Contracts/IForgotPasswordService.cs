using RuntimeApps.Authentication.Features.PasswordRecovery.Models;
using RuntimeApps.Authentication.Shared.Models;
namespace RuntimeApps.Authentication.Features.PasswordRecovery.Contracts {
    public interface IForgotPasswordService<TUser, TKey> where TKey : IEquatable<TKey> {
        Task<ForgotPasswordResponse> RequestAsync(string email, CancellationToken cancellationToken = default);
        Task<Result> ResetAsync(string verificationHandle, string credential, string newPassword, CancellationToken cancellationToken = default);
    }
}
