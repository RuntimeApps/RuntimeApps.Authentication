using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Sample.CustomStore.Store {
    public interface IStoreUnitOfWork {
        Dictionary<string, IdentityUser> Users { get; }
        Dictionary<string, IdentityRole> Roles { get; }
        List<IdentityUserRole<string>> UserRoles { get; }
        List<IdentityUserClaim<string>> UserClaims { get; }
        List<IdentityUserLogin<string>> UserLogins { get; }
        List<IdentityUserToken<string>> UserTokens { get; }
        List<IdentityRoleClaim<string>> RoleClaims { get; }

        int GetUserClaimId();
        int GetRoleClaimId();
    }
}
