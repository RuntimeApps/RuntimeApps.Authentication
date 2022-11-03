using System.Diagnostics.Contracts;
using Microsoft.AspNetCore.Identity;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace RuntimeApps.Authentication.Sample.CustomStore.Store {
    public class StoreUnitOfWork: IStoreUnitOfWork {
        private int UserClaimId = 1;
        private int RoleClaimId = 1;
        
        public Dictionary<string, IdentityUser> Users { get; } = new Dictionary<string, IdentityUser>();
        public Dictionary<string, IdentityRole> Roles { get; } = new Dictionary<string, IdentityRole>();
        public List<IdentityUserRole<string>> UserRoles { get; } = new List<IdentityUserRole<string>>();
        public List<IdentityUserClaim<string>> UserClaims { get; } = new List<IdentityUserClaim<string>>();
        public List<IdentityUserLogin<string>> UserLogins { get; } = new List<IdentityUserLogin<string>>();
        public List<IdentityUserToken<string>> UserTokens { get; } = new List<IdentityUserToken<string>>();
        public List<IdentityRoleClaim<string>> RoleClaims { get; } = new List<IdentityRoleClaim<string>>();

        public int GetUserClaimId() => Interlocked.Increment(ref UserClaimId);
        public int GetRoleClaimId() => Interlocked.Increment(ref RoleClaimId);
    }
}
