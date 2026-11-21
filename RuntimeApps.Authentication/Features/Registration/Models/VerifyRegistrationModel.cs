using System.ComponentModel.DataAnnotations;

namespace RuntimeApps.Authentication.Features.Registration.Models {
    public sealed class VerifyRegistrationModel {
        [Required]
        public string VerificationHandle { get; set; }
        [Required]
        public string Code { get; set; }
    }
}
