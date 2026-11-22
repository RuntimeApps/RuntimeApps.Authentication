using System.ComponentModel.DataAnnotations;

namespace RuntimeApps.Authentication.Features.ExternalLogin.Models {
    public class ExternalAuthModel {
        [Required]
        public string Provider { get; set; }
        [Required]
        public string Token { get; set; }
    }
}
