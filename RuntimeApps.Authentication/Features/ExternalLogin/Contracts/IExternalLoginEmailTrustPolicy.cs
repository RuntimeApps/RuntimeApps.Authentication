using RuntimeApps.Authentication.Features.ExternalLogin.Models;
namespace RuntimeApps.Authentication.Features.ExternalLogin.Contracts {
    public interface IExternalLoginEmailTrustPolicy<TUser> where TUser : class {
        bool IsEmailTrusted(string provider, ExternalLoginProviderResult<TUser> result);
    }
}
