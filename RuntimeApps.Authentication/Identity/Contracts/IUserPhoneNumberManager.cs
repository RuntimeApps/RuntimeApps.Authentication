using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Identity.Contracts {
    public interface IUserPhoneNumberManager<TUser> where TUser : class {
        Task<IdentityResult> SetPhoneNumberAsync(TUser user, string phoneNumber); 
        Task<IdentityResult> ChangePhoneNumberAsync(TUser user, string phoneNumber, string token); 
        Task<string> GenerateChangePhoneNumberTokenAsync(TUser user, string phoneNumber);
    }
}
