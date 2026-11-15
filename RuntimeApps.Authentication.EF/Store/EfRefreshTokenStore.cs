using Microsoft.EntityFrameworkCore;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.EF.Store {
    /// <summary>
    /// EF Core store. Atomic rotation requires a relational provider with transaction support.
    /// </summary>
    public sealed class EfRefreshTokenStore<TDbContext, TKey> : IRefreshTokenStore<TKey>
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

        public async Task CreateAsync(RefreshToken<TKey> token, CancellationToken cancellationToken = default) {
            await _dbContext.Set<RefreshToken<TKey>>().AddAsync(token, cancellationToken);
            await _dbContext.SaveChangesAsync(cancellationToken);
        }

        public Task<RefreshToken<TKey>> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default) =>
            _dbContext.Set<RefreshToken<TKey>>()
                .AsNoTracking()
                .SingleOrDefaultAsync(token => token.TokenHash == tokenHash, cancellationToken);

        public async Task<bool> TryRotateAsync(
            Guid tokenId,
            string expectedTokenHash,
            RefreshToken<TKey> replacement,
            DateTimeOffset now,
            CancellationToken cancellationToken = default) {
            if(!_dbContext.Database.IsRelational())
                throw new NotSupportedException("Atomic refresh-token rotation requires a relational EF Core provider.");

            await using var transaction = await _dbContext.Database.BeginTransactionAsync(cancellationToken);
            var affected = await _dbContext.Set<RefreshToken<TKey>>()
                .Where(token => token.Id == tokenId &&
                                token.TokenHash == expectedTokenHash &&
                                token.RevokedAt == null &&
                                token.ExpiresAt > now)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(token => token.RevokedAt, now)
                    .SetProperty(token => token.ReplacedByTokenId, replacement.Id), cancellationToken);

            if(affected != 1) {
                await transaction.RollbackAsync(cancellationToken);
                return false;
            }

            await _dbContext.Set<RefreshToken<TKey>>().AddAsync(replacement, cancellationToken);
            await _dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return true;
        }

        public async Task RevokeFamilyAsync(Guid familyId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default) {
            await _dbContext.Set<RefreshToken<TKey>>()
                .Where(token => token.FamilyId == familyId && token.RevokedAt == null)
                .ExecuteUpdateAsync(setters => setters.SetProperty(token => token.RevokedAt, revokedAt), cancellationToken);
        }

        public async Task<int> RevokeAllAsync(TKey userId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default) =>
            await _dbContext.Set<RefreshToken<TKey>>()
                .Where(token => token.UserId.Equals(userId) && token.RevokedAt == null)
                .ExecuteUpdateAsync(setters => setters.SetProperty(token => token.RevokedAt, revokedAt), cancellationToken);
    }
}