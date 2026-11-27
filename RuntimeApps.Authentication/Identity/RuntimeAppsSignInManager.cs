using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RuntimeApps.Authentication.Features.TwoFactor.Services;
using RuntimeApps.Authentication.Identity.Contracts;
namespace RuntimeApps.Authentication.Identity {
    internal class RuntimeAppsSignInManager<TUser>: SignInManager<TUser>, ISignInManager<TUser>
        where TUser : class {
        private readonly TwoFactorFeatureMarker _twoFactorFeature;

        public RuntimeAppsSignInManager(UserManager<TUser> userManager, IHttpContextAccessor contextAccessor, IUserClaimsPrincipalFactory<TUser> claimsFactory, IOptions<IdentityOptions> optionsAccessor, ILogger<SignInManager<TUser>> logger, IAuthenticationSchemeProvider schemes, IUserConfirmation<TUser> confirmation, TwoFactorFeatureMarker twoFactorFeature = null) : base(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation) {
            _twoFactorFeature = twoFactorFeature;
        }

        protected override async Task<SignInResult> SignInOrTwoFactorAsync(TUser user, bool isPersistent, string loginProvider = null, bool bypassTwoFactor = false) {
            if(!bypassTwoFactor && await IsTfaEnabled(user)) {
                return SignInResult.TwoFactorRequired;
            }

            return SignInResult.Success;
        }

        protected virtual async Task<bool> IsTfaEnabled(TUser user) {
            if(!UserManager.SupportsUserTwoFactor || !await UserManager.GetTwoFactorEnabledAsync(user))
                return false;
            // With API two-factor login registered, the flag alone decides. Requiring a valid provider here
            // would let a flagged user sign in with the password alone, so the gate must fail closed.
            if(_twoFactorFeature != null)
                return true;
            return (await UserManager.GetValidTwoFactorProvidersAsync(user)).Count > 0;
        }
    }
}
