using System.ComponentModel.DataAnnotations;

namespace RuntimeApps.Authentication.Features.PasswordRecovery.Models {
    /// <summary>Completes password recovery with a verification code or link token.</summary>
    public sealed class ResetPasswordModel {
        [Required]
        [MaxLength(128)]
        public string VerificationHandle { get; set; }

        [Required]
        [MaxLength(4096)]
        public string Credential { get; set; }

        [Required]
        [MaxLength(1024)]
        public string NewPassword { get; set; }
    }
}
