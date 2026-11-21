using System.ComponentModel.DataAnnotations;

namespace RuntimeApps.Authentication.Features.Account.Models {
    public class ChangePasswordModel {
        [Required]
        public string CurrentPassword { get; set; }
        [Required]
        public string NewPassword { get; set; }
    }
}
