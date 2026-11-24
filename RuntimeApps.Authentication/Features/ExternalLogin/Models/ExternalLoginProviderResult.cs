using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Features.ExternalLogin.Models {
    public sealed class ExternalLoginProviderResult<TUser> where TUser : class {
        public TUser User { get; init; }
        public UserLoginInfo LoginInfo { get; init; }
        public string Email { get; init; }
        public bool EmailVerified { get; init; }
        public string HostedDomain { get; init; }
        /// <summary>How the default trust policy should treat <see cref="Email"/>. Set from the provider's options.</summary>
        public ExternalLoginEmailTrustMode EmailTrustMode { get; init; } = ExternalLoginEmailTrustMode.Verified;
    }
}
