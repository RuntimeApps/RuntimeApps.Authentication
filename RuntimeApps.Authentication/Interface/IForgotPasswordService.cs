using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Interface {
    public interface IForgotPasswordService<TUser, TKey> where TKey : IEquatable<TKey> {
        Task<ForgotPasswordResponse> RequestAsync(string email, CancellationToken cancellationToken = default);
        Task<Result> ResetAsync(string verificationHandle, string credential, string newPassword, CancellationToken cancellationToken = default);
    }
}