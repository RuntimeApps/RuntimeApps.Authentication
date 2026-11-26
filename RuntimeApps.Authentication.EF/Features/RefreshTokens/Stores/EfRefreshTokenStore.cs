using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;
using RuntimeApps.Authentication.Features.RefreshTokens.Contracts;
using RuntimeApps.Authentication.Features.RefreshTokens.Models;
namespace RuntimeApps.Authentication.EF.Features.RefreshTokens.Stores {
    /// <summary>
    /// EF Core store. Atomic rotation requires a relational provider with transaction support.
    /// </summary>
    public sealed class EfRefreshTokenStore<TDbContext, TKey>: IRefreshTokenStore<TKey>, IRefreshTokenCleanupStore<TKey>
        where TDbContext : DbContext
        where TKey : IEquatable<TKey> {
        private readonly TDbContext _dbContext;

        public EfRefreshTokenStore(TDbContext dbContext) {
            _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
            if(_dbContext.Model.FindEntityType(typeof(RefreshToken<TKey>)) == null)
                throw new InvalidOperationException(
                    $"The DbContext model does not include {typeof(RefreshToken<TKey>).Name}. " +
                    $"Call modelBuilder.AddRefreshTokenEntity<{typeof(TKey).Name}>() in OnModelCreating.");
        }

        private static void PrepareGeneratedId(RefreshToken<TKey> token) {
            if(!EqualityComparer<TKey>.Default.Equals(token.Id, default!))
                return;

            object generatedId = typeof(TKey) == typeof(Guid)
                ? Guid.NewGuid()
                : typeof(TKey) == typeof(string)
                    ? Guid.NewGuid().ToString("N")
                    : null;

            if(generatedId != null) {
                token.Id = (TKey)generatedId;
                return;
            }

            var keyTypeCode = Type.GetTypeCode(typeof(TKey));
            if(keyTypeCode is not (TypeCode.Byte or TypeCode.Int16 or TypeCode.Int32 or TypeCode.Int64 or
                TypeCode.SByte or TypeCode.UInt16 or TypeCode.UInt32 or TypeCode.UInt64)) {
                throw new NotSupportedException(
                    $"Refresh-token key type '{typeof(TKey).FullName}' requires a non-default Id before persistence. " +
                    "Use Guid, string, or an EF-supported generated integer key type.");
            }
        }

        public async Task CreateAsync(RefreshToken<TKey> token, CancellationToken cancellationToken = default) {
            PrepareGeneratedId(token);
            await _dbContext.Set<RefreshToken<TKey>>().AddAsync(token, cancellationToken);
            await _dbContext.SaveChangesAsync(cancellationToken);
        }

        public Task<RefreshToken<TKey>> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default) =>
            _dbContext.Set<RefreshToken<TKey>>()
                .AsNoTracking()
                .SingleOrDefaultAsync(token => token.TokenHash == tokenHash, cancellationToken);

        public async Task<bool> TryRotateAsync(
            TKey tokenId,
            string expectedTokenHash,
            RefreshToken<TKey> replacement,
            DateTimeOffset now,
            CancellationToken cancellationToken = default) {
            if(!_dbContext.Database.IsRelational())
                throw new NotSupportedException("Atomic refresh-token rotation requires a relational EF Core provider.");

            // Generated keys (Guid/string) are assigned once so every retry attempt reuses the same value.
            // Database-generated integer keys stay at their default and are reset before each attempt.
            PrepareGeneratedId(replacement);
            var originalId = replacement.Id;

            // User-initiated transactions must run inside the execution strategy so providers configured
            // with retry-on-failure (for example EnableRetryOnFailure) retry the whole unit.
            var strategy = _dbContext.Database.CreateExecutionStrategy();
            return await strategy.ExecuteAsync(async () => {
                ResetReplacement(replacement, originalId);
                var committed = false;
                try {
                    await using var transaction = await _dbContext.Database.BeginTransactionAsync(cancellationToken);
                    await _dbContext.Set<RefreshToken<TKey>>().AddAsync(replacement, cancellationToken);
                    await _dbContext.SaveChangesAsync(cancellationToken);

                    var affected = await _dbContext.Set<RefreshToken<TKey>>()
                        .Where(token => token.Id.Equals(tokenId) &&
                                        token.TokenHash == expectedTokenHash &&
                                        token.RevokedAt == null &&
                                        token.ExpiresAt > now)
                        .ExecuteUpdateAsync(setters => setters
                            .SetProperty(token => token.RevokedAt, now)
                            .SetProperty(token => token.ReplacedByTokenId, replacement.Id)
                            .SetProperty(token => token.HasReplacement, true), cancellationToken);

                    if(affected != 1) {
                        await transaction.RollbackAsync(cancellationToken);
                        return false;
                    }

                    await transaction.CommitAsync(cancellationToken);
                    committed = true;
                    return true;
                } finally {
                    // A rolled-back or failed insert must not stay tracked as a persisted row in the
                    // shared scoped context (it is shared with the Identity stores).
                    if(!committed)
                        ResetReplacement(replacement, originalId);
                }
            });
        }

        private void ResetReplacement(RefreshToken<TKey> replacement, TKey originalId) {
            var entry = _dbContext.Entry(replacement);
            if(entry.State != EntityState.Detached)
                entry.State = EntityState.Detached;
            replacement.Id = originalId;
        }

        public async Task RevokeFamilyAsync(Guid familyId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default) {
            await _dbContext.Set<RefreshToken<TKey>>()
                .Where(token => token.FamilyId == familyId && token.RevokedAt == null)
                .ExecuteUpdateAsync(setters => setters.SetProperty(token => token.RevokedAt, revokedAt), cancellationToken);
        }

        public async Task<int> DeleteInactiveAsync(
            DateTimeOffset now,
            TimeSpan retention,
            int batchSize,
            CancellationToken cancellationToken = default) {
            if(!_dbContext.Database.IsRelational())
                throw new NotSupportedException("Refresh-token cleanup requires a relational EF Core provider.");
            ArgumentOutOfRangeException.ThrowIfLessThan(retention, TimeSpan.Zero);
            ArgumentOutOfRangeException.ThrowIfLessThan(batchSize, 1);

            // retention >= 0 keeps the cutoff at or before now, so an unrevoked token that is still valid
            // (ExpiresAt > now) can never match.
            var cutoff = now - retention;
            Expression<Func<RefreshToken<TKey>, bool>> isInactive = token =>
                (token.RevokedAt != null && token.RevokedAt < cutoff) ||
                (token.RevokedAt == null && token.ExpiresAt < cutoff);

            var tokens = _dbContext.Set<RefreshToken<TKey>>();
            // Select a bounded set of keys first, then delete by key. This stays portable across providers
            // (not every provider supports LIMIT inside a DELETE ... WHERE IN subquery) and keeps each
            // statement short. The predicate is applied again to the delete so a row is only removed if it
            // is still inactive when the delete runs.
            var ids = await tokens
                .AsNoTracking()
                .Where(isInactive)
                .OrderBy(token => token.Id)
                .Select(token => token.Id)
                .Take(batchSize)
                .ToListAsync(cancellationToken);
            if(ids.Count == 0)
                return 0;

            return await tokens
                .Where(isInactive)
                .Where(token => ids.Contains(token.Id))
                .ExecuteDeleteAsync(cancellationToken);
        }

        public async Task<int> RevokeAllAsync(TKey userId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default) =>
            await _dbContext.Set<RefreshToken<TKey>>()
                 .Where(token => object.Equals(token.UserId, userId) && token.RevokedAt == null)
                .ExecuteUpdateAsync(setters => setters.SetProperty(token => token.RevokedAt, revokedAt), cancellationToken);
    }
}
