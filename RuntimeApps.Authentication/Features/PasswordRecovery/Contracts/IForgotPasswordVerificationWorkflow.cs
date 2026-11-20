using RuntimeApps.Authentication.Features.Verification.Contracts;
using RuntimeApps.Authentication.Features.Verification.Models;
using RuntimeApps.Authentication.Shared.Models;
namespace RuntimeApps.Authentication.Features.PasswordRecovery.Contracts {
    /// <summary>
    /// Additional verification capability used by password recovery. Kept separate to avoid
    /// expanding the existing public verification interface.
    /// </summary>
    public interface IForgotPasswordVerificationWorkflow<TUser, TKey> : IVerificationWorkflowService<TUser, TKey>
        where TKey : IEquatable<TKey> {
        /// <summary>Validates a recovery credential without consuming the request.</summary>
        Task<Result<TUser>> CheckAsync(string verificationHandle, string credential,
            VerificationPurpose expectedPurpose, VerificationChannel expectedChannel,
            CancellationToken cancellationToken = default);
    }
}
