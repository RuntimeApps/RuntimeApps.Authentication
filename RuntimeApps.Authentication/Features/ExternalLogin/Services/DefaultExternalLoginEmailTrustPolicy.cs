using RuntimeApps.Authentication.Features.ExternalLogin.Contracts;
using RuntimeApps.Authentication.Features.ExternalLogin.Models;
namespace RuntimeApps.Authentication.Features.ExternalLogin.Services {
    /// <summary>
    /// Applies the provider's <see cref="ExternalLoginEmailTrustMode"/>, carried on the validated result.
    /// <list type="bullet">
    /// <item><description><see cref="ExternalLoginEmailTrustMode.Never"/>: no email is trusted.</description></item>
    /// <item><description><see cref="ExternalLoginEmailTrustMode.Always"/>: any non-empty email is trusted.</description></item>
    /// <item><description><see cref="ExternalLoginEmailTrustMode.Verified"/>: trusts verified Google Gmail/Googlemail addresses
    /// and verified Google Workspace addresses whose email domain matches the token's hosted-domain claim.
    /// Other providers require a custom policy or a different mode.</description></item>
    /// </list>
    /// </summary>
    public sealed class DefaultExternalLoginEmailTrustPolicy<TUser>: IExternalLoginEmailTrustPolicy<TUser>
        where TUser : class {
        public bool IsEmailTrusted(string provider, ExternalLoginProviderResult<TUser> result) {
            if(result == null || string.IsNullOrWhiteSpace(result.Email))
                return false;

            switch(result.EmailTrustMode) {
                case ExternalLoginEmailTrustMode.Never:
                    return false;
                case ExternalLoginEmailTrustMode.Always:
                    return true;
            }

            if(!result.EmailVerified ||
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
