using System.ComponentModel.DataAnnotations;

namespace RuntimeApps.Authentication.Features.Registration.Models {
    public class RegisterUserModel<TUser>
        where TUser : class {
        [Required]
        public TUser UserInfo { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
