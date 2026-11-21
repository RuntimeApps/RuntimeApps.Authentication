using System.ComponentModel.DataAnnotations;

namespace RuntimeApps.Authentication.Features.Account.Models {
    /// <summary>Request body for assigning or removing roles from a user.</summary>
    public sealed record UserRolesRequest([property: Required, MinLength(1)] IReadOnlyCollection<string> Roles);
}
