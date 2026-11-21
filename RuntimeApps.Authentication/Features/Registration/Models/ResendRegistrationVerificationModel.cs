using System.ComponentModel.DataAnnotations;

namespace RuntimeApps.Authentication.Features.Registration.Models {
    public sealed class ResendRegistrationVerificationModel {
        [Required]
        public string VerificationHandle { get; set; }
    }
}
