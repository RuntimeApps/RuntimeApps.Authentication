using System.ComponentModel.DataAnnotations;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Features.Account.Models {
    /// <summary>Request body for applying or removing multiple user claims.</summary>
    public sealed record BulkClaimsRequest([property: Required, MinLength(1)] IReadOnlyCollection<ClaimDto> Claims);
}
