using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Model {
    public sealed class ExternalLoginProviderResult<TUser> where TUser : class {
        public TUser User { get; init; }
        public UserLoginInfo LoginInfo { get; init; }
        public string Email { get; init; }
        public bool EmailVerified { get; init; }
        public string HostedDomain { get; init; }
    }
}