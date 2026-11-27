using System.Data;
using Microsoft.EntityFrameworkCore;
using RuntimeApps.Authentication.Features.TwoFactor.Contracts;
using RuntimeApps.Authentication.Features.TwoFactor.Models;

namespace RuntimeApps.Authentication.EF.Features.TwoFactor.Stores;

/// <summary>
/// Relational EF Core implementation. Conditional updates, serializable transactions and a unique index
/// protect attempt limits, single use of a challenge and replay of codes against parallel requests.
/// Transactions run inside the DbContext execution strategy, so retry-on-failure providers are supported.
/// </summary>
public sealed class EfTwoFactorChallengeStore<TDbContext, TKey> : ITwoFactorChallengeStore<TKey>, ITwoFactorCleanupStore<TKey>
    where TDbContext : DbContext
    where TKey : IEquatable<TKey> {
    private readonly TDbContext _dbContext;

    public EfTwoFactorChallengeStore(TDbContext dbContext) {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        if(_dbContext.Model.FindEntityType(typeof(TwoFactorChallenge<TKey>)) == null ||
           _dbContext.Model.FindEntityType(typeof(TwoFactorUsedCode<TKey>)) == null)
            throw new InvalidOperationException(
                "The DbContext model does not include the two-factor entities. " +
                $"Call modelBuilder.AddTwoFactorChallengeEntity<{typeof(TKey).Name}>() in OnModelCreating.");
    }

    private IQueryable<TwoFactorChallenge<TKey>> Challenges => _dbContext.Set<TwoFactorChallenge<TKey>>();
    private IQueryable<TwoFactorUsedCode<TKey>> UsedCodes => _dbContext.Set<TwoFactorUsedCode<TKey>>();

    private static void PrepareGeneratedId(TwoFactorChallenge<TKey> challenge) {
        if(!EqualityComparer<TKey>.Default.Equals(challenge.Id, default!))
            return;
        object generatedId = typeof(TKey) == typeof(Guid)
            ? Guid.NewGuid()
            : typeof(TKey) == typeof(string) ? Guid.NewGuid().ToString("N") : null;
        if(generatedId != null) {
            challenge.Id = (TKey)generatedId;
            return;
        }
        var typeCode = Type.GetTypeCode(typeof(TKey));
        if(typeCode is not (TypeCode.Byte or TypeCode.Int16 or TypeCode.Int32 or TypeCode.Int64 or
            TypeCode.SByte or TypeCode.UInt16 or TypeCode.UInt32 or TypeCode.UInt64))
            throw new NotSupportedException(
                $"Two-factor challenge key type '{typeof(TKey).FullName}' requires a non-default Id before persistence.");
    }

    private void Detach(object entity) {
        var entry = _dbContext.Entry(entity);
        if(entry.State != EntityState.Detached)
            entry.State = EntityState.Detached;
    }

    public async Task CreateAsync(TwoFactorChallenge<TKey> challenge, int maxPendingPerUser, CancellationToken cancellationToken = default) {
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxPendingPerUser, 1);
        EnsureRelational();
        PrepareGeneratedId(challenge);
        var originalId = challenge.Id;

        var strategy = _dbContext.Database.CreateExecutionStrategy();
        await strategy.ExecuteAsync(async () => {
            Detach(challenge);
            challenge.Id = originalId;
            var committed = false;
            try {
                await using var transaction = await _dbContext.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);

                // Keep the newest (max - 1) pending challenges; the new one makes it max.
                var createdAt = challenge.CreatedAt;
                var excessIds = await Challenges.AsNoTracking()
                    .Where(item => object.Equals(item.UserId, challenge.UserId) &&
                                   item.Status == TwoFactorChallengeStatus.Pending &&
                                   item.ExpiresAt > createdAt)
                    .OrderByDescending(item => item.CreatedAt)
                    .ThenByDescending(item => item.Id)
                    .Skip(maxPendingPerUser - 1)
                    .Select(item => item.Id)
                    .ToListAsync(cancellationToken);
                if(excessIds.Count > 0)
                    await Challenges.Where(item => excessIds.Contains(item.Id) && item.Status == TwoFactorChallengeStatus.Pending)
                        .ExecuteUpdateAsync(setters => setters.SetProperty(
                            item => item.Status, TwoFactorChallengeStatus.Superseded), cancellationToken);

                await _dbContext.Set<TwoFactorChallenge<TKey>>().AddAsync(challenge, cancellationToken);
                await _dbContext.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                committed = true;
            } finally {
                // Keep the shared scoped context free of a row that was rolled back or failed.
                if(!committed) {
                    Detach(challenge);
                    challenge.Id = originalId;
                }
            }
        });
    }

    public Task<TwoFactorChallenge<TKey>> FindByHandleHashAsync(string handleHash, CancellationToken cancellationToken = default) =>
        Challenges.AsNoTracking().SingleOrDefaultAsync(item => item.HandleHash == handleHash, cancellationToken);

    public async Task<bool> TryReserveAttemptAsync(TKey challengeId, int maxAttempts, DateTimeOffset now, CancellationToken cancellationToken = default) {
        EnsureRelational();
        var affected = await Challenges.Where(item =>
                item.Id.Equals(challengeId) &&
                item.Status == TwoFactorChallengeStatus.Pending &&
                item.ExpiresAt > now &&
                item.Attempts < maxAttempts)
            .ExecuteUpdateAsync(setters => setters.SetProperty(item => item.Attempts, item => item.Attempts + 1), cancellationToken);
        return affected == 1;
    }

    public async Task<bool> TryConsumeAsync(TKey challengeId, DateTimeOffset now, CancellationToken cancellationToken = default) {
        EnsureRelational();
        var affected = await Challenges.Where(item =>
                item.Id.Equals(challengeId) &&
                item.Status == TwoFactorChallengeStatus.Pending &&
                item.ExpiresAt > now)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(item => item.Status, TwoFactorChallengeStatus.Completed)
                .SetProperty(item => item.CompletedAt, now), cancellationToken);
        return affected == 1;
    }

    public async Task<bool> TryMarkCodeUsedAsync(TKey userId, string method, string codeHash, DateTimeOffset usedAt, DateTimeOffset expiresAt, CancellationToken cancellationToken = default) {
        ArgumentException.ThrowIfNullOrEmpty(method);
        ArgumentException.ThrowIfNullOrEmpty(codeHash);
        EnsureRelational();

        var strategy = _dbContext.Database.CreateExecutionStrategy();
        return await strategy.ExecuteAsync(async () => {
            var entry = new TwoFactorUsedCode<TKey> {
                UserId = userId, Method = method, CodeHash = codeHash, UsedAt = usedAt, ExpiresAt = expiresAt
            };
            var committed = false;
            try {
                await using var transaction = await _dbContext.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);

                // An expired entry for the same code no longer protects anything and would block the unique index.
                await UsedCodes.Where(item =>
                        object.Equals(item.UserId, userId) && item.Method == method &&
                        item.CodeHash == codeHash && item.ExpiresAt <= usedAt)
                    .ExecuteDeleteAsync(cancellationToken);

                try {
                    await _dbContext.Set<TwoFactorUsedCode<TKey>>().AddAsync(entry, cancellationToken);
                    await _dbContext.SaveChangesAsync(cancellationToken);
                } catch(DbUpdateException) {
                    Detach(entry);
                    // Some providers abort the transaction on a constraint violation, so end it before querying.
                    await transaction.RollbackAsync(cancellationToken);
                    var alreadyUsed = await UsedCodes.AsNoTracking().AnyAsync(item =>
                        object.Equals(item.UserId, userId) && item.Method == method &&
                        item.CodeHash == codeHash && item.ExpiresAt > usedAt, cancellationToken);
                    if(alreadyUsed) return false;
                    throw;
                }

                await transaction.CommitAsync(cancellationToken);
                committed = true;
                return true;
            } finally {
                if(!committed) Detach(entry);
            }
        });
    }

    public async Task<int> DeleteExpiredAsync(DateTimeOffset now, TimeSpan retention, int batchSize, CancellationToken cancellationToken = default) {
        EnsureRelational();
        ArgumentOutOfRangeException.ThrowIfLessThan(retention, TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfLessThan(batchSize, 1);

        // Select a bounded set of keys first, then delete by key with the predicate repeated, so a row is only
        // removed if it is still expired when the delete runs. This stays portable (no LIMIT inside DELETE).
        var codeIds = await UsedCodes.AsNoTracking()
            .Where(item => item.ExpiresAt <= now)
            .OrderBy(item => item.Id)
            .Select(item => item.Id)
            .Take(batchSize)
            .ToListAsync(cancellationToken);
        var deleted = codeIds.Count == 0 ? 0 : await UsedCodes
            .Where(item => item.ExpiresAt <= now && codeIds.Contains(item.Id))
            .ExecuteDeleteAsync(cancellationToken);

        var remaining = batchSize - deleted;
        if(remaining <= 0) return deleted;

        // retention >= 0 keeps the cutoff at or before now, so a challenge that can still be answered never matches.
        var cutoff = now - retention;
        var challengeIds = await Challenges.AsNoTracking()
            .Where(item => item.ExpiresAt < cutoff)
            .OrderBy(item => item.Id)
            .Select(item => item.Id)
            .Take(remaining)
            .ToListAsync(cancellationToken);
        if(challengeIds.Count == 0) return deleted;
        return deleted + await Challenges
            .Where(item => item.ExpiresAt < cutoff && challengeIds.Contains(item.Id))
            .ExecuteDeleteAsync(cancellationToken);
    }

    private void EnsureRelational() {
        if(!_dbContext.Database.IsRelational())
            throw new NotSupportedException("Atomic two-factor operations require a relational EF Core provider.");
    }
}
