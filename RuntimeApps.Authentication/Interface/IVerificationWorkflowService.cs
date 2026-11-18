using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Interface {
    public interface IVerificationWorkflowService<TUser, TKey> where TKey : IEquatable<TKey> {
        Task<VerificationOperationResult> StartAsync(
            TUser user,
            VerificationPurpose purpose,
            VerificationChannel channel,
            string destination,
            string customPurpose = null,
            string customChannel = null,
            CancellationToken cancellationToken = default);

        Task<VerificationOperationResult> ResendAsync(
            string verificationHandle,
            VerificationPurpose expectedPurpose,
            VerificationChannel expectedChannel,
            CancellationToken cancellationToken = default);

        Task<Result<TUser>> VerifyAsync(
            string verificationHandle,
            string code,
            VerificationPurpose expectedPurpose,
            VerificationChannel expectedChannel,
            CancellationToken cancellationToken = default);
    }
}