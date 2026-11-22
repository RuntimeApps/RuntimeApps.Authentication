using System.ComponentModel.DataAnnotations;

namespace RuntimeApps.Authentication.Features.Account.Models {
    /// <summary>Request body for adding a password to the authenticated account.</summary>
    public sealed record AddPasswordRequest([property: Required] string Password);
}
