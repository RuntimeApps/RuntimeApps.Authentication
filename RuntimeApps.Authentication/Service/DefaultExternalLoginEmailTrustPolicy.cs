using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Service {
    /// <summary>
    /// Trusts verified Google Gmail/Googlemail addresses and verified Google Workspace addresses
    /// whose email domain matches the token's hosted-domain claim. Other providers require a custom policy.
    /// </summary>
    public sealed class DefaultExternalLoginEmailTrustPolicy<TUser> : IExternalLoginEmailTrustPolicy<TUser>
        where TUser : class {
        public bool IsEmailTrusted(string provider, ExternalLoginProviderResult<TUser> result) {
            if(result == null || !result.EmailVerified || string.IsNullOrWhiteSpace(result.Email) ||
               !string.Equals(provider, "GOOGLE", StringComparison.OrdinalIgnoreCase))
                return false;

            var at = result.Email.LastIndexOf('@');
            if(at <= 0 || at == result.Email.Length - 1)
                return false;

            var emailDomain = result.Email[(at + 1)..];
            if(emailDomain.Equals("gmail.com", StringComparison.OrdinalIgnoreCase) ||
               emailDomain.Equals("googlemail.com", StringComparison.OrdinalIgnoreCase))
                return true;

            return !string.IsNullOrWhiteSpace(result.HostedDomain) &&
                   emailDomain.Equals(result.HostedDomain, StringComparison.OrdinalIgnoreCase);
        }
    }
}