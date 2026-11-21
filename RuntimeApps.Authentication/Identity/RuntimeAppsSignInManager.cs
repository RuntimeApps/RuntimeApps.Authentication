using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Identity.Contracts;
namespace RuntimeApps.Authentication.Identity {
    internal class RuntimeAppsSignInManager<TUser>: SignInManager<TUser>, ISignInManager<TUser>
        where TUser : class {
        public RuntimeAppsSignInManager(UserManager<TUser> userManager, IHttpContextAccessor contextAccessor, IUserClaimsPrincipalFactory<TUser> claimsFactory, IOptions<IdentityOptions> optionsAccessor, ILogger<SignInManager<TUser>> logger, IAuthenticationSchemeProvider schemes, IUserConfirmation<TUser> confirmation) : base(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation) {
        }

        protected override async Task<SignInResult> SignInOrTwoFactorAsync(TUser user, bool isPersistent, string loginProvider = null, bool bypassTwoFactor = false) {
            if(!bypassTwoFactor && await IsTfaEnabled(user)) {
                return await base.SignInOrTwoFactorAsync(user, isPersistent, loginProvider, bypassTwoFactor);
            }

            return SignInResult.Success;
        }

        public Task<SignInResult> CreateTwoFactorChallengeAsync(TUser user) =>
            SignInOrTwoFactorAsync(user, false, "RuntimeApps.External", false);

        protected virtual async Task<bool> IsTfaEnabled(TUser user)
            => UserManager.SupportsUserTwoFactor &&
            await UserManager.GetTwoFactorEnabledAsync(user) &&
            (await UserManager.GetValidTwoFactorProvidersAsync(user)).Count > 0;
    }
}
