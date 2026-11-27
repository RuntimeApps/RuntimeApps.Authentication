using System.ComponentModel.DataAnnotations;

namespace RuntimeApps.Authentication.Features.TwoFactor.Models;

/// <summary>Request to complete a login with a second factor.</summary>
public class TwoFactorLoginModel {
    /// <summary>The challenge handle returned by the login response.</summary>
    [Required]
    public string Challenge { get; set; }

    /// <summary>The method name, for example "authenticator".</summary>
    [Required]
    public string Method { get; set; }

    /// <summary>The code from the authenticator app or delivered to the user.</summary>
    [Required]
    public string Code { get; set; }
}
