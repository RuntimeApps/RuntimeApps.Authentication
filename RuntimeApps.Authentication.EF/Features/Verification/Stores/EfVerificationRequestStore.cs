using System.Data;
using Microsoft.EntityFrameworkCore;
using RuntimeApps.Authentication.Features.Verification.Contracts;
using RuntimeApps.Authentication.Features.Verification.Models;
namespace RuntimeApps.Authentication.EF.Features.Verification.Stores {
    /// <summary>
    /// Relational EF Core implementation. Conditional updates and serializable transactions protect
    /// request state transitions and destination-level send limits against concurrent requests.
    /// Transactions run inside the DbContext execution strategy, so providers configured with
    /// retry-on-failure are supported.
    /// </summary>
    public sealed class EfVerificationRequestStore<TDbContext, TKey>: IVerificationRequestStore<TKey>
        where TDbContext : DbContext
        where TKey : IEquatable<TKey> {
        private readonly TDbContext _dbContext;

        public EfVerificationRequestStore(TDbContext dbContext) {
            _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
            if(_dbContext.Model.FindEntityType(typeof(VerificationRequest<TKey>)) == null ||
               _dbContext.Model.FindEntityType(typeof(VerificationSend)) == null)
                throw new InvalidOperationException(
                    $"The DbContext model does not include the verification entities. " +
                    $"Call modelBuilder.AddVerificationRequestEntity<{typeof(TKey).Name}>() in OnModelCreating.");
        }

        private static void PrepareGeneratedId(VerificationRequest<TKey> request) {
            if(!EqualityComparer<TKey>.Default.Equals(request.Id, default!))
                return;
            object generatedId = typeof(TKey) == typeof(Guid)
                ? Guid.NewGuid()
                : typeof(TKey) == typeof(string) ? Guid.NewGuid().ToString("N") : null;
            if(generatedId != null) {
                request.Id = (TKey)generatedId;
                return;
            }
            var typeCode = Type.GetTypeCode(typeof(TKey));
            if(typeCode is not (TypeCode.Byte or TypeCode.Int16 or TypeCode.Int32 or TypeCode.Int64 or
                TypeCode.SByte or TypeCode.UInt16 or TypeCode.UInt32 or TypeCode.UInt64))
                throw new NotSupportedException(
                    $"Verification request key type '{typeof(TKey).FullName}' requires a non-default Id before persistence.");
        }

        private IQueryable<VerificationRequest<TKey>> Requests => _dbContext.Set<VerificationRequest<TKey>>();
        private IQueryable<VerificationSend> Sends => _dbContext.Set<VerificationSend>();

        private void Detach(object entity) {
            var entry = _dbContext.Entry(entity);
            if(entry.State != EntityState.Detached)
                entry.State = EntityState.Detached;
        }

        private void ResetRequest(VerificationRequest<TKey> request, TKey originalId) {
            Detach(request);
            request.Id = originalId;
        }

        public async Task<bool> TryCreateAsync(
            VerificationRequest<TKey> request,
            DateTimeOffset sendsSince,
            int maximumSendsPerHour,
            CancellationToken cancellationToken = default) {
            EnsureRelational();
            // Generated keys (Guid/string) are assigned once; database-generated integer keys are reset per attempt.
            PrepareGeneratedId(request);
            var originalId = request.Id;

            var strategy = _dbContext.Database.CreateExecutionStrategy();
            return await strategy.ExecuteAsync(async () => {
                ResetRequest(request, originalId);
                VerificationSend send = null;
                var committed = false;
                try {
                    await using var transaction = await _dbContext.Database.BeginTransactionAsync(
                        IsolationLevel.Serializable, cancellationToken);

                    await Sends.Where(item => item.SentAt < sendsSince).ExecuteDeleteAsync(cancellationToken);

                    var sendCount = await Sends.CountAsync(item =>
                        item.NormalizedDestination == request.NormalizedDestination &&
                        item.Purpose == request.Purpose &&
                        item.Channel == request.Channel &&
                        item.CustomPurpose == request.CustomPurpose &&
                        item.CustomChannel == request.CustomChannel &&
                        item.SentAt >= sendsSince, cancellationToken);

                    if(sendCount >= maximumSendsPerHour) {
                        await transaction.RollbackAsync(cancellationToken);
                        return false;
                    }

                    await Requests.Where(item =>
                            object.Equals(item.UserId, request.UserId) &&
                            item.Purpose == request.Purpose &&
                            item.Channel == request.Channel &&
                            item.CustomPurpose == request.CustomPurpose &&
                            item.CustomChannel == request.CustomChannel &&
                            item.NormalizedDestination == request.NormalizedDestination &&
                            item.Status == VerificationRequestStatus.Pending)
                        .ExecuteUpdateAsync(setters => setters.SetProperty(
                            item => item.Status, VerificationRequestStatus.Superseded), cancellationToken);

                    await _dbContext.Set<VerificationRequest<TKey>>().AddAsync(request, cancellationToken);
                    send = new VerificationSend {
                        NormalizedDestination = request.NormalizedDestination,
                        Purpose = request.Purpose,
                        Channel = request.Channel,
                        CustomPurpose = request.CustomPurpose,
                        CustomChannel = request.CustomChannel,
                        SentAt = request.CreatedAt
                    };
                    await _dbContext.Set<VerificationSend>().AddAsync(send, cancellationToken);
                    await _dbContext.SaveChangesAsync(cancellationToken);
                    await transaction.CommitAsync(cancellationToken);
                    committed = true;
                    return true;
                } finally {
                    // Keep the shared scoped context free of rows that were rolled back or failed.
                    if(!committed) {
                        ResetRequest(request, originalId);
                        if(send != null)
                            Detach(send);
                    }
                }
            });
        }

        public async Task<bool> TrySetInitialVerifierAsync(
            TKey requestId,
            string verifier,
            DateTimeOffset sentAt,
            DateTimeOffset expiresAt,
            CancellationToken cancellationToken = default) {
            EnsureRelational();
            var affected = await Requests.Where(item =>
                    item.Id.Equals(requestId) &&
                    item.Status == VerificationRequestStatus.Pending &&
                    item.CodeVersion == 0 &&
                    item.CodeVerifier == string.Empty)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(item => item.CodeVerifier, verifier)
                    .SetProperty(item => item.CodeVersion, 1)
                    .SetProperty(item => item.LastSentAt, sentAt)
                    .SetProperty(item => item.ExpiresAt, expiresAt), cancellationToken);
            return affected == 1;
        }

        public Task<VerificationRequest<TKey>> FindByHandleHashAsync(
            string handleHash,
            CancellationToken cancellationToken = default) =>
            Requests.AsNoTracking().SingleOrDefaultAsync(
                request => request.PublicHandleHash == handleHash, cancellationToken);

        public async Task<bool> TryResendAsync(
            TKey requestId,
            int expectedCodeVersion,
            string newCodeVerifier,
            DateTimeOffset now,
            DateTimeOffset expiresAt,
            TimeSpan resendCooldown,
            DateTimeOffset sendsSince,
            int maximumSendsPerHour,
            CancellationToken cancellationToken = default) {
            EnsureRelational();

            var strategy = _dbContext.Database.CreateExecutionStrategy();
            return await strategy.ExecuteAsync(async () => {
                VerificationSend send = null;
                var committed = false;
                try {
                    await using var transaction = await _dbContext.Database.BeginTransactionAsync(
                        IsolationLevel.Serializable, cancellationToken);

                    // No-tracking read: the row is changed with ExecuteUpdate below, so a tracked copy would go stale.
                    var request = await Requests.AsNoTracking()
                        .SingleOrDefaultAsync(item => item.Id.Equals(requestId), cancellationToken);
                    if(request == null || request.Status != VerificationRequestStatus.Pending ||
                       request.LastSentAt > now - resendCooldown) {
                        await transaction.RollbackAsync(cancellationToken);
                        return false;
                    }

                    await Sends.Where(item => item.SentAt < sendsSince).ExecuteDeleteAsync(cancellationToken);

                    var customPurpose = request.CustomPurpose;
                    var customChannel = request.CustomChannel;
                    var sendCount = await Sends.CountAsync(item =>
                        item.NormalizedDestination == request.NormalizedDestination &&
                        item.Purpose == request.Purpose &&
                        item.Channel == request.Channel &&
                        item.CustomPurpose == customPurpose &&
                        item.CustomChannel == customChannel &&
                        item.SentAt >= sendsSince, cancellationToken);
                    if(sendCount >= maximumSendsPerHour) {
                        await transaction.RollbackAsync(cancellationToken);
                        return false;
                    }

                    var affected = await Requests.Where(item =>
                            item.Id.Equals(requestId) &&
                            item.Status == VerificationRequestStatus.Pending &&
                            item.CodeVersion == expectedCodeVersion &&
                            item.LastSentAt <= now - resendCooldown)
                        .ExecuteUpdateAsync(setters => setters
                            .SetProperty(item => item.CodeVerifier, newCodeVerifier)
                            .SetProperty(item => item.CodeVersion, item => item.CodeVersion + 1)
                            .SetProperty(item => item.SendCount, item => item.SendCount + 1)
                            .SetProperty(item => item.LastSentAt, now)
                            .SetProperty(item => item.ExpiresAt, expiresAt), cancellationToken);

                    if(affected != 1) {
                        await transaction.RollbackAsync(cancellationToken);
                        return false;
                    }

                    send = new VerificationSend {
                        NormalizedDestination = request.NormalizedDestination,
                        Purpose = request.Purpose,
                        Channel = request.Channel,
                        CustomPurpose = customPurpose,
                        CustomChannel = customChannel,
                        SentAt = now
                    };
                    await _dbContext.Set<VerificationSend>().AddAsync(send, cancellationToken);
                    await _dbContext.SaveChangesAsync(cancellationToken);
                    await transaction.CommitAsync(cancellationToken);
                    committed = true;
                    return true;
                } finally {
                    if(!committed && send != null)
                        Detach(send);
                }
            });
        }

        public async Task<bool> TryIncrementFailedAttemptsAsync(
            TKey requestId,
            int expectedCodeVersion,
            int maximumFailedAttempts,
            DateTimeOffset now,
            CancellationToken cancellationToken = default) {
            EnsureRelational();
            var affected = await Requests.Where(item =>
                    item.Id.Equals(requestId) &&
                    item.Status == VerificationRequestStatus.Pending &&
                    item.CodeVersion == expectedCodeVersion &&
                    item.ExpiresAt > now &&
                    item.FailedAttempts < maximumFailedAttempts)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(item => item.FailedAttempts, item => item.FailedAttempts + 1)
                    .SetProperty(item => item.Status,
                        item => item.FailedAttempts + 1 >= maximumFailedAttempts
                            ? VerificationRequestStatus.Locked
                            : VerificationRequestStatus.Pending), cancellationToken);
            return affected == 1;
        }

        public async Task<bool> TryConsumeAsync(
            TKey requestId,
            int expectedCodeVersion,
            DateTimeOffset now,
            CancellationToken cancellationToken = default) {
            EnsureRelational();
            var affected = await Requests.Where(item =>
                    item.Id.Equals(requestId) &&
                    item.Status == VerificationRequestStatus.Pending &&
                    item.CodeVersion == expectedCodeVersion &&
                    item.ExpiresAt > now)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(item => item.Status, VerificationRequestStatus.Completed)
                    .SetProperty(item => item.CompletedAt, now), cancellationToken);
            return affected == 1;
        }

        public async Task SupersedePendingAsync(
            TKey userId,
            VerificationPurpose purpose,
            VerificationChannel channel,
            string normalizedDestination,
            CancellationToken cancellationToken = default) {
            EnsureRelational();
            await Requests.Where(item =>
                    object.Equals(item.UserId, userId) &&
                    item.Purpose == purpose &&
                    item.Channel == channel &&
                    item.NormalizedDestination == normalizedDestination &&
                    item.Status == VerificationRequestStatus.Pending)
                .ExecuteUpdateAsync(setters => setters.SetProperty(
                    item => item.Status, VerificationRequestStatus.Superseded), cancellationToken);
        }

        private void EnsureRelational() {
            if(!_dbContext.Database.IsRelational())
                throw new NotSupportedException("Atomic verification-request operations require a relational EF Core provider.");
        }
    }
}
