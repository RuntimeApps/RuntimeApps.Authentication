using System.ComponentModel.DataAnnotations;

namespace RuntimeApps.Authentication.Features.ExternalLogin.Models {
    /// <summary>Request to unlink the external identity of a provider from the signed-in account.</summary>
    public class UnlinkExternalLoginModel {
        [Required]
        public string Provider { get; set; }
    }
}
