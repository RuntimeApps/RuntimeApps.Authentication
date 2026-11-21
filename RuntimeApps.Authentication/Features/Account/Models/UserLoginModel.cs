using System.ComponentModel.DataAnnotations;

namespace RuntimeApps.Authentication.Features.Account.Models {
    public class UserLoginModel {
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
