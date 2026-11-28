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

        /// <remarks>
        /// Identity decides whether to reset the failed-access count after a correct password with a private check that
        /// only recognizes Identity token providers. A user enrolled in a library method that is not an Identity provider
        /// (for example SMS) would get the count reset at every password step, so wrong second-factor codes would never
        /// reach lockout. When API two-factor login is registered and the second step is required, the count is kept.
        /// </remarks>
        public override async Task<SignInResult> CheckPasswordSignInAsync(TUser user, string password, bool lockoutOnFailure) {
            ArgumentNullException.ThrowIfNull(user);
            if(_twoFactorFeature == null || !await IsTfaEnabled(user))
                return await base.CheckPasswordSignInAsync(user, password, lockoutOnFailure);

            var error = await PreSignInCheck(user);
            if(error != null)
                return error;
            if(await UserManager.CheckPasswordAsync(user, password))
                return SignInResult.Success;

            if(UserManager.SupportsUserLockout && lockoutOnFailure) {
                await UserManager.AccessFailedAsync(user);
                if(await UserManager.IsLockedOutAsync(user))
                    return await LockedOut(user);
            }
            return SignInResult.Failed;
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
