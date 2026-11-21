using RuntimeApps.Authentication.Features.ExternalLogin.Models;
namespace RuntimeApps.Authentication.Features.ExternalLogin.Contracts {
    public interface IExternalLoginProvider<TUser> where TUser : class {
        string Provider { get; }
        Task<ExternalLoginProviderResult<TUser>> ValidateAsync(string token);
    }
}
