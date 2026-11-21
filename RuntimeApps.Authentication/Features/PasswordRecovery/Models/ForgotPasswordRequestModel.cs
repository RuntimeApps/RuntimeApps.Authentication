using System.ComponentModel.DataAnnotations;

namespace RuntimeApps.Authentication.Features.PasswordRecovery.Models {
    /// <summary>Requests password recovery for an email address.</summary>
    public sealed class ForgotPasswordRequestModel {
        [Required]
        [EmailAddress]
        [MaxLength(256)]
        public string Email { get; set; }
    }
}
