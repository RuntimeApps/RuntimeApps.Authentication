using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Interface;

namespace RuntimeApps.Authentication.Service {
    internal class RuntimeAppsSignInManager<TUser>: SignInManager<TUser>, ISignInManager<TUser>
        where TUser : class {
        public RuntimeAppsSignInManager(UserManager<TUser> userManager, IHttpContextAccessor contextAccessor, IUserClaimsPrincipalFactory<TUser> claimsFactory, IOptions<IdentityOptions> optionsAccessor, ILogger<SignInManager<TUser>> logger, IAuthenticationSchemeProvider schemes, IUserConfirmation<TUser> confirmation) : base(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation) {
        }

        protected override async Task<SignInResult> SignInOrTwoFactorAsync(TUser user, bool isPersistent, string loginProvider = null, bool bypassTwoFactor = false) {
            if(!bypassTwoFactor && await IsTfaEnabled(user)) {
                return SignInResult.TwoFactorRequired;
            }

            return SignInResult.Success;
        }

        protected virtual async Task<bool> IsTfaEnabled(TUser user)
            => UserManager.SupportsUserTwoFactor &&
            await UserManager.GetTwoFactorEnabledAsync(user) &&
            (await UserManager.GetValidTwoFactorProvidersAsync(user)).Count > 0;
    }
}
