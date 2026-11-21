using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Shared.Extensions;
using RuntimeApps.Authentication.Shared.Models;
namespace RuntimeApps.Authentication.Endpoints.Roles {
    public static class RoleClaimApiEndpointRouteBuilderExtensions {
        public static IEndpointRouteBuilder MapRoleClaimGetApi<TRole>(this IEndpointRouteBuilder endpoints)
            where TRole : class {
            var routeGroup = endpoints.MapGroup("");

            routeGroup.MapGet("{roleId}/Claim", async Task<Results<Ok<IEnumerable<ClaimDto>>, ValidationProblem>> ([FromRoute] string roleId, IRoleManager<TRole> roleManager, HttpContext httpContext) => {
                var role = await roleManager.FindByIdAsync(roleId);
                if(role == null)
                    return RoleNotFound();

                var result = await roleManager.GetClaimsAsync(role);
                return TypedResults.Ok<IEnumerable<ClaimDto>>(result.Select(c => new ClaimDto(c)));
            });

            return endpoints;
        }

        public static IEndpointRouteBuilder MapRoleClaimManageApi<TRole>(this IEndpointRouteBuilder endpoints)
            where TRole : class {
            var routeGroup = endpoints.MapGroup("");

            routeGroup.MapPost("{roleId}/Claim", async Task<Results<Ok, ValidationProblem>> ([FromRoute] string roleId, [FromBody] ClaimDto claim, IRoleManager<TRole> roleManager, HttpContext httpContext) => {
                var role = await roleManager.FindByIdAsync(roleId);
                if(role == null)
                    return RoleNotFound();

                var result = await roleManager.AddClaimAsync(role, claim.ToClaim());
                if(!result.Succeeded)
                    return result.CreateValidationProblem();
                return TypedResults.Ok();
            });

            routeGroup.MapDelete("{roleId}/Claim", async Task<Results<Ok, ValidationProblem>> ([FromRoute] string roleId, [FromBody] ClaimDto claim, IRoleManager<TRole> roleManager, HttpContext httpContext) => {
                var role = await roleManager.FindByIdAsync(roleId);
                if(role == null)
                    return RoleNotFound();

                var result = await roleManager.RemoveClaimAsync(role, claim.ToClaim());
                if(!result.Succeeded)
                    return result.CreateValidationProblem();
                return TypedResults.Ok();
            });

            return endpoints;
        }

        private static ValidationProblem RoleNotFound() =>
            ValidationProblemFactory.CreateValidationProblem("NotFound", "Role Not Found");

    }
}
