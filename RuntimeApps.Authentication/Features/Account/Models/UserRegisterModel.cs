using Microsoft.AspNetCore.Identity;

namespace RuntimeApps.Authentication.Features.Account.Models {
    public class UserRegisterModel<TUser, TKey>
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey> {
        public TUser UserInfo { get; set; }
        public string Password { get; set; }
    }
}
