using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace RuntimeApps.Authentication.Sample.CustomClaim {
    public class CustomUserClaimsPrincipalFactory: UserClaimsPrincipalFactory<IdentityUser<int>, IdentityRole<int>> {
        public CustomUserClaimsPrincipalFactory(UserManager<IdentityUser<int>> userManager, RoleManager<IdentityRole<int>> roleManager, IOptions<IdentityOptions> options) : base(userManager, roleManager, options) {
        }

        protected override async Task<ClaimsIdentity> GenerateClaimsAsync(IdentityUser<int> user) {
            var id = await base.GenerateClaimsAsync(user).ConfigureAwait(false);
            if(!string.IsNullOrEmpty(user.PhoneNumber)) {
                id.AddClaim(new Claim(ClaimTypes.MobilePhone, user.PhoneNumber));
            }
            return id;
        }
    }
}
