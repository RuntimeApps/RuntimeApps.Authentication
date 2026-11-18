using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Interface {
    public interface IExternalLoginEmailTrustPolicy<TUser> where TUser : class {
        bool IsEmailTrusted(string provider, ExternalLoginProviderResult<TUser> result);
    }
}