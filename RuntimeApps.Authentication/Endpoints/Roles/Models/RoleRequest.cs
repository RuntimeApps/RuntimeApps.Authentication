using System.ComponentModel.DataAnnotations;

namespace RuntimeApps.Authentication.Endpoints.Roles.Models {
    /// <summary>
    /// Request body for role creation and updates. The generic payload preserves consumer-defined
    /// role fields while keeping the public operation envelope explicit.
    /// </summary>
    public sealed record RoleRequest<TRole>([property: Required] TRole Role) where TRole : class;
}
