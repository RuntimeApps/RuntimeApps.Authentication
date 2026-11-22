using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Identity.Contracts {
    /// <remarks>Identity password operations do not accept cancellation tokens; callers check before writing and finish essential session revocation afterward.</remarks>
    public interface IUserPasswordManager<TUser> where TUser : class {
        Task<bool> CheckPasswordAsync(TUser user, string password);
        Task<IdentityResult> AddPasswordAsync(TUser user, string password);
        Task<IdentityResult> ChangePasswordAsync(TUser user, string currentPassword, string newPassword);
        Task<IdentityResult> RemovePasswordAsync(TUser user);
        Task<string> GeneratePasswordResetTokenAsync(TUser user);
        Task<IdentityResult> ResetPasswordAsync(TUser user, string token, string newPassword);
    }
}
