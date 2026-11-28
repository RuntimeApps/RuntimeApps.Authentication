using System.ComponentModel.DataAnnotations;

namespace RuntimeApps.Authentication.Features.TwoFactor.Models;

/// <summary>
/// Request to turn two-factor off. Needs re-authentication and a current code, so a stolen session or a
/// leaked password alone cannot remove the second factor.
/// </summary>
public class TwoFactorDisableModel : TwoFactorReauthenticationModel {
    /// <summary>An enrolled method whose current code is given in <see cref="Code"/>.</summary>
    [Required]
    public string Method { get; set; }

    [Required]
    public string Code { get; set; }
}
