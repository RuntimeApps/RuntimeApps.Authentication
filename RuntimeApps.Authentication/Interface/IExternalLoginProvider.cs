using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Interface {
    public interface IExternalLoginProvider<TUser> where TUser : class {
        string Provider { get; }
        Task<ExternalLoginProviderResult<TUser>> ValidateAsync(string token);
    }
}