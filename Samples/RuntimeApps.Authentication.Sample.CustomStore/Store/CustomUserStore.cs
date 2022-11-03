using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Sample.CustomStore.Store {
    public class CustomUserStore: UserStoreBase<IdentityUser, IdentityRole, string, IdentityUserClaim<string>, IdentityUserRole<string>, IdentityUserLogin<string>, IdentityUserToken<string>, IdentityRoleClaim<string>>, IProtectedUserStore<IdentityUser> {
        private readonly IdentityErrorDescriber _describer;
        private readonly IStoreUnitOfWork _unitOfWork;

        public CustomUserStore(IdentityErrorDescriber describer, IStoreUnitOfWork unitOfWork) : base(describer) {
            _describer = describer;
            _unitOfWork = unitOfWork;
        }

        public override IQueryable<IdentityUser> Users => UserData.Values.AsQueryable();
        private Dictionary<string, IdentityUser> UserData { get => _unitOfWork.Users; }
        private Dictionary<string, IdentityRole> RoleData { get => _unitOfWork.Roles; }
        private List<IdentityUserRole<string>> UserRoles { get => _unitOfWork.UserRoles; }
        private List<IdentityUserClaim<string>> UserClaims { get => _unitOfWork.UserClaims; }
        private List<IdentityUserLogin<string>> UserLogins { get => _unitOfWork.UserLogins; }
        private List<IdentityUserToken<string>> UserTokens { get => _unitOfWork.UserTokens; }

        public override Task<IdentityResult> CreateAsync(IdentityUser user, CancellationToken cancellationToken = default) {
            user.Id = user.NormalizedUserName;
            if(UserData.TryAdd(user.Id, user))
                return Task.FromResult(IdentityResult.Success);
            else
                return Task.FromResult(IdentityResult.Failed(_describer.DuplicateUserName(user.UserName)));
        }

        public override Task<IdentityResult> UpdateAsync(IdentityUser user, CancellationToken cancellationToken = default) {
            if(UserData.ContainsKey(user.Id)) {
                UserData[user.Id] = user;
            }
            return Task.FromResult(IdentityResult.Success);
        }

        public override Task<IdentityResult> DeleteAsync(IdentityUser user, CancellationToken cancellationToken = default) {
            UserData.Remove(user.Id);
            return Task.FromResult(IdentityResult.Success);
        }

        public override Task<IdentityUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default) => 
            Task.FromResult(UserData.Values.FirstOrDefault(u => u.NormalizedEmail == normalizedEmail));

        public override Task<IdentityUser> FindByIdAsync(string userId, CancellationToken cancellationToken = default) {
            UserData.TryGetValue(userId, out var user);
            return Task.FromResult(user);
        }

        public override Task<IdentityUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken = default) => 
            FindByIdAsync(normalizedUserName, cancellationToken);

        protected override Task<IdentityUser> FindUserAsync(string userId, CancellationToken cancellationToken) => 
            FindByIdAsync(userId, cancellationToken);

        public override Task AddClaimsAsync(IdentityUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default) {
            UserClaims.AddRange(claims.Select(c => new IdentityUserClaim<string> {
                Id = _unitOfWork.GetUserClaimId(),
                UserId = user.Id,
                ClaimType = c.Type,
                ClaimValue = c.Value
            }));
            return Task.CompletedTask;
        }

        public override Task<IList<Claim>> GetClaimsAsync(IdentityUser user, CancellationToken cancellationToken = default) =>
            Task.FromResult<IList<Claim>>(UserClaims.Where(c => c.UserId == user.Id).Select(c => new Claim(c.ClaimType, c.ClaimValue)).ToList());

        public override Task<IList<IdentityUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default) =>
            Task.FromResult<IList<IdentityUser>>(UserData.Values.Where(u => UserClaims.Any(c => c.UserId == u.Id && c.ClaimType == claim.Type && c.ClaimValue == claim.Value)).ToList());
        public override Task RemoveClaimsAsync(IdentityUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default) {
            var userClaims = UserClaims.Where(uc => uc.UserId == user.Id && claims.Any(c => c.Type == uc.ClaimType && c.Value == uc.ClaimValue));
            foreach(var item in userClaims)
                UserClaims.Remove(item);
            return Task.CompletedTask;
        }

        public override Task ReplaceClaimAsync(IdentityUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = default) {
            var lastClaim = UserClaims.FirstOrDefault(uc=>uc.UserId == user.Id && uc.ClaimType == claim.Type && uc.ClaimValue == claim.Value);
            if(lastClaim != null) {
                lastClaim.ClaimValue = newClaim.Value;
                lastClaim.ClaimType = newClaim.Type;
            }
            return Task.CompletedTask;
        }

        public override Task AddLoginAsync(IdentityUser user, UserLoginInfo login, CancellationToken cancellationToken = default) {
            UserLogins.Add(new IdentityUserLogin<string> {
                UserId = user.Id,
                LoginProvider = login.LoginProvider,
                ProviderDisplayName = login.ProviderDisplayName,
                ProviderKey = login.ProviderKey
            });
            return Task.CompletedTask;
        }

        public override Task<IList<UserLoginInfo>> GetLoginsAsync(IdentityUser user, CancellationToken cancellationToken = default) =>
            Task.FromResult<IList<UserLoginInfo>>(UserLogins.Where(u => u.UserId == user.Id).Select(u => new UserLoginInfo(u.LoginProvider, u.ProviderKey, u.ProviderDisplayName)).ToList());

        public override Task RemoveLoginAsync(IdentityUser user, string loginProvider, string providerKey, CancellationToken cancellationToken = default) {
            var userlogin = UserLogins.FirstOrDefault(u=>u.UserId == user.Id && u.LoginProvider == loginProvider && u.ProviderKey == providerKey);
            if(userlogin != null)
                UserLogins.Remove(userlogin);
            return Task.CompletedTask;
        }

        protected override Task<IdentityUserLogin<string>> FindUserLoginAsync(string userId, string loginProvider, string providerKey, CancellationToken cancellationToken) => 
            Task.FromResult(UserLogins.FirstOrDefault(u => u.UserId == userId && u.LoginProvider == loginProvider && u.ProviderKey == providerKey));

        protected override Task<IdentityUserLogin<string>> FindUserLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken) =>
            Task.FromResult(UserLogins.FirstOrDefault(u => u.LoginProvider == loginProvider && u.ProviderKey == providerKey));

        protected override Task AddUserTokenAsync(IdentityUserToken<string> token) {
            UserTokens.Add(token);
            return Task.FromResult(token);
        }

        protected override Task<IdentityUserToken<string>> FindTokenAsync(IdentityUser user, string loginProvider, string name, CancellationToken cancellationToken) =>
            Task.FromResult(UserTokens.FirstOrDefault(u => u.UserId == user.Id && u.LoginProvider == loginProvider && u.Name == name));

        protected override Task RemoveUserTokenAsync(IdentityUserToken<string> token) {
            UserTokens.Remove(token);
            return Task.CompletedTask;
        }

        public override Task AddToRoleAsync(IdentityUser user, string normalizedRoleName, CancellationToken cancellationToken = default) {
            UserRoles.Add(new IdentityUserRole<string> {
                RoleId = normalizedRoleName,
                UserId = user.Id
            });
            return Task.CompletedTask;
        }

        public override Task<IList<string>> GetRolesAsync(IdentityUser user, CancellationToken cancellationToken = default) => 
            Task.FromResult<IList<string>>(UserRoles.Where(r => r.UserId == user.Id).Select(r => r.RoleId).ToList());

        public override Task<IList<IdentityUser>> GetUsersInRoleAsync(string normalizedRoleName, CancellationToken cancellationToken = default) =>
            Task.FromResult<IList<IdentityUser>>(UserData.Values.Where(u => UserRoles.Any(r => r.RoleId == normalizedRoleName && r.UserId == u.Id)).ToList());
        public override Task<bool> IsInRoleAsync(IdentityUser user, string normalizedRoleName, CancellationToken cancellationToken = default) =>
            Task.FromResult(UserRoles.Any(r => r.UserId == user.Id && r.RoleId == normalizedRoleName));
        public override Task RemoveFromRoleAsync(IdentityUser user, string normalizedRoleName, CancellationToken cancellationToken = default) {
            var userRole = UserRoles.FirstOrDefault(r => r.RoleId == normalizedRoleName && r.UserId == user.Id);
            if (userRole != null)
                UserRoles.Remove(userRole);
            return Task.CompletedTask;
        }

        protected override Task<IdentityRole> FindRoleAsync(string normalizedRoleName, CancellationToken cancellationToken) {
            RoleData.TryGetValue(normalizedRoleName, out var roleData);
            return Task.FromResult(roleData);
        }

        protected override Task<IdentityUserRole<string>> FindUserRoleAsync(string userId, string roleId, CancellationToken cancellationToken) =>
            Task.FromResult(UserRoles.FirstOrDefault(r => r.UserId == userId && r.RoleId == roleId));
    }
}
