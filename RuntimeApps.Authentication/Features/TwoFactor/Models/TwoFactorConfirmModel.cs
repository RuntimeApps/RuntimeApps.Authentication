using System.ComponentModel.DataAnnotations;

namespace RuntimeApps.Authentication.Features.TwoFactor.Models;

/// <summary>Request to confirm a started two-factor setup with a code from the new method.</summary>
public class TwoFactorConfirmModel {
    [Required]
    public string Code { get; set; }
}
