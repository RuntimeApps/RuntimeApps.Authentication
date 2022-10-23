using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Interface {
    public interface IExternalLoginProvider<TUser>
        where TUser : class {
        string Provider { get; }
        Task<(TUser, UserLoginInfo)> ValidateAsync(string token);
    }
}
