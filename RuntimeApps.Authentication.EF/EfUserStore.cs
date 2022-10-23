using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace RuntimeApps.Authentication.EF {
    public class EfUserStore<TUser, TRole, TKey>: UserStoreBase<TUser, TKey, IdentityUserClaim<TKey>, IdentityUserLogin<TKey>, IdentityUserToken<TKey>>
        where TUser : IdentityUser<TKey>
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey> {

        private readonly IdentityDbContext<TUser, TRole, TKey> _dbContext;

        public EfUserStore(IdentityDbContext<TUser, TRole, TKey> dbContext, IdentityErrorDescriber identityErrorDescriber) : base(identityErrorDescriber) {
            _dbContext = dbContext;
        }

        public override IQueryable<TUser> Users => _dbContext.Users;

        public override async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken = default) {
            await _dbContext.Users.AddAsync(user, cancellationToken);
            await _dbContext.SaveChangesAsync(cancellationToken);
            return IdentityResult.Success;
        }

        public override async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken = default) {
            _dbContext.Users.Update(user);
            await _dbContext.SaveChangesAsync(cancellationToken);
            return IdentityResult.Success;
        }

        public override async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken = default) {
            _dbContext.Users.Remove(user);
            await _dbContext.SaveChangesAsync(cancellationToken);
            return IdentityResult.Success;
        }

        protected override Task<TUser> FindUserAsync(TKey userId, CancellationToken cancellationToken) =>
            _dbContext.Users.FirstOrDefaultAsync(u => u.Id.Equals(userId), cancellationToken: cancellationToken);

        public override Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken = default) =>
            _dbContext.Users.FirstOrDefaultAsync(p => p.Id.ToString() == userId, cancellationToken);

        public override Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default) =>
            _dbContext.Users.FirstOrDefaultAsync(u => u.NormalizedEmail == normalizedEmail, cancellationToken: cancellationToken);

        public override Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken = default) =>
            _dbContext.Users.FirstOrDefaultAsync(u => u.NormalizedUserName == normalizedUserName, cancellationToken);

        public override async Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default) {
            await _dbContext.UserClaims.AddRangeAsync(claims.Select(c => new IdentityUserClaim<TKey>() {
                UserId = user.Id,
                ClaimType = c.Type,
                ClaimValue = c.Value,
            }), cancellationToken);
            await _dbContext.SaveChangesAsync(cancellationToken);
        }

        public override async Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default) {
            var userClaims = await _dbContext.UserClaims.Where(c => c.UserId.Equals(user.Id)).ToListAsync(cancellationToken);
            var removedClaims = userClaims.Where(uc => claims.Any(c => c.Type == uc.ClaimType && c.Value == uc.ClaimValue)).ToList();
            _dbContext.UserClaims.RemoveRange(removedClaims);
            await _dbContext.SaveChangesAsync(cancellationToken);
        }

        public override async Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken = default) {
            var result = await _dbContext.UserClaims.Where(c => c.UserId.Equals(user.Id)).ToListAsync(cancellationToken);
            return result.Select(c => new Claim(c.ClaimType, c.ClaimValue)).ToList();
        }

        public override async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default) {
            var userIds = await _dbContext.UserClaims.Where(c => c.ClaimType == claim.Type && c.ClaimValue == claim.Value).Select(c => c.UserId).ToListAsync(cancellationToken);
            return await _dbContext.Users.Where(u => userIds.Contains(u.Id)).ToListAsync(cancellationToken);
        }

        public override async Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = default) {
            var lastClaim = await _dbContext.UserClaims.FirstOrDefaultAsync(c => c.UserId.Equals(user.Id) && c.ClaimType == claim.Type && c.ClaimValue == claim.Value, cancellationToken);
            if(lastClaim != null) {
                lastClaim.ClaimType = newClaim.Type;
                lastClaim.ClaimValue = newClaim.Value;
            }
            await _dbContext.SaveChangesAsync(cancellationToken);
        }

        public override async Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken = default) {
            var data = new IdentityUserLogin<TKey>() {
                LoginProvider = login.LoginProvider,
                ProviderKey = login.ProviderKey,
                ProviderDisplayName = login.ProviderDisplayName,
                UserId = user.Id
            };
            await _dbContext.UserLogins.AddAsync(data, cancellationToken);
            await _dbContext.SaveChangesAsync(cancellationToken);
        }

        public override async Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken = default) {
            var data = await _dbContext.UserLogins
                .FirstOrDefaultAsync(l => l.UserId.Equals(user.Id) &&
                    l.LoginProvider == loginProvider &&
                    l.ProviderKey == providerKey, cancellationToken);
            if(data != null) {
                _dbContext.UserLogins.Remove(data);
                await _dbContext.SaveChangesAsync(cancellationToken);
            }
        }

        public override async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken = default) {
            return await _dbContext.UserLogins
                .Where(l => l.UserId.Equals(user.Id))
                .Select(l => new UserLoginInfo(l.LoginProvider, l.ProviderKey, l.ProviderDisplayName))
                .ToListAsync(cancellationToken: cancellationToken);
        }

        protected override Task<IdentityUserLogin<TKey>> FindUserLoginAsync(TKey userId, string loginProvider, string providerKey, CancellationToken cancellationToken) =>
            _dbContext.UserLogins.FirstOrDefaultAsync(l => l.UserId.Equals(userId) && l.LoginProvider == loginProvider && l.ProviderKey == providerKey, cancellationToken: cancellationToken);

        protected override Task<IdentityUserLogin<TKey>> FindUserLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken) =>
            _dbContext.UserLogins.FirstOrDefaultAsync(l => l.LoginProvider == loginProvider && l.ProviderKey == providerKey, cancellationToken: cancellationToken);

        protected override async Task AddUserTokenAsync(IdentityUserToken<TKey> token) {
            await _dbContext.UserTokens.AddAsync(token);
            await _dbContext.SaveChangesAsync();
        }

        protected override Task<IdentityUserToken<TKey>> FindTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken) =>
            _dbContext.UserTokens.FirstOrDefaultAsync(t => t.UserId.Equals(user.Id) && t.LoginProvider == loginProvider && t.Name == name, cancellationToken);

        protected override Task RemoveUserTokenAsync(IdentityUserToken<TKey> token) {
            _dbContext.UserTokens.Remove(token);
            return _dbContext.SaveChangesAsync();
        }
    }
}
