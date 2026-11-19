using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Interface {
    /// <summary>
    /// Persistence contract for verification requests. State-changing methods must be atomic;
    /// implementations must use conditional updates or transactions to prevent replay and races.
    /// </summary>
    public interface IVerificationRequestStore<TKey> where TKey : IEquatable<TKey> {
        Task<bool> TryCreateAsync(
            VerificationRequest<TKey> request,
            DateTimeOffset sendsSince,
            int maximumSendsPerHour,
            CancellationToken cancellationToken = default);

        Task<bool> TrySetInitialVerifierAsync(
            TKey requestId,
            string verifier,
            DateTimeOffset sentAt,
            DateTimeOffset expiresAt,
            CancellationToken cancellationToken = default);

        Task<VerificationRequest<TKey>> FindByHandleHashAsync(
            string handleHash,
            CancellationToken cancellationToken = default);

        Task<bool> TryResendAsync(
            TKey requestId,
            int expectedCodeVersion,
            string newCodeVerifier,
            DateTimeOffset now,
            DateTimeOffset expiresAt,
            TimeSpan resendCooldown,
            DateTimeOffset sendsSince,
            int maximumSendsPerHour,
            CancellationToken cancellationToken = default);

        Task<bool> TryIncrementFailedAttemptsAsync(
            TKey requestId,
            int expectedCodeVersion,
            int maximumFailedAttempts,
            DateTimeOffset now,
            CancellationToken cancellationToken = default);

        Task<bool> TryConsumeAsync(
            TKey requestId,
            int expectedCodeVersion,
            DateTimeOffset now,
            CancellationToken cancellationToken = default);

        Task SupersedePendingAsync(
            TKey userId,
            VerificationPurpose purpose,
            VerificationChannel channel,
            string normalizedDestination,
            CancellationToken cancellationToken = default);
    }
}