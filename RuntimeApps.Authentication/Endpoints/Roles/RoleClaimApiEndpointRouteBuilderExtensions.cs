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

            routeGroup.MapGet("{roleId}/Claim", async Task<IResult> ([FromRoute] string roleId, IRoleManager<TRole> roleManager, CancellationToken cancellationToken) => {
                cancellationToken.ThrowIfCancellationRequested();
                var role = await roleManager.FindByIdAsync(roleId);
                if(role == null)
                    return RoleNotFound();

                cancellationToken.ThrowIfCancellationRequested();
                var result = await roleManager.GetClaimsAsync(role);
                cancellationToken.ThrowIfCancellationRequested();
                return TypedResults.Ok<IEnumerable<ClaimDto>>(result.Select(c => new ClaimDto(c)));
            }).Produces<IEnumerable<ClaimDto>>(StatusCodes.Status200OK).Produces(StatusCodes.Status404NotFound);

            return endpoints;
        }

        public static IEndpointRouteBuilder MapRoleClaimManageApi<TRole>(this IEndpointRouteBuilder endpoints)
            where TRole : class {
            var routeGroup = endpoints.MapGroup("");

            routeGroup.MapPost("{roleId}/Claim", async Task<IResult> ([FromRoute] string roleId, [FromBody] ClaimDto claim, IRoleManager<TRole> roleManager, CancellationToken cancellationToken) => {
                if(!IsValidClaim(claim))
                    return ValidationProblemFactory.CreateValidationProblem("InvalidClaim", "Claim type and value are required.");
                cancellationToken.ThrowIfCancellationRequested();
                var role = await roleManager.FindByIdAsync(roleId);
                if(role == null)
                    return RoleNotFound();

                cancellationToken.ThrowIfCancellationRequested();
                var result = await roleManager.AddClaimAsync(role, claim.ToClaim());
                if(!result.Succeeded)
                    return result.CreatePublicError();
                return TypedResults.Ok();
            }).Produces(StatusCodes.Status200OK)
            .ProducesValidationProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status404NotFound);

            routeGroup.MapDelete("{roleId}/Claim", async Task<IResult> ([FromRoute] string roleId, [FromBody] ClaimDto claim, IRoleManager<TRole> roleManager, CancellationToken cancellationToken) => {
                if(!IsValidClaim(claim))
                    return ValidationProblemFactory.CreateValidationProblem("InvalidClaim", "Claim type and value are required.");
                cancellationToken.ThrowIfCancellationRequested();
                var role = await roleManager.FindByIdAsync(roleId);
                if(role == null)
                    return RoleNotFound();

                cancellationToken.ThrowIfCancellationRequested();
                var result = await roleManager.RemoveClaimAsync(role, claim.ToClaim());
                if(!result.Succeeded)
                    return result.CreatePublicError();
                return TypedResults.Ok();
            }).Produces(StatusCodes.Status200OK)
            .ProducesValidationProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status404NotFound);

            return endpoints;
        }

        private static IResult RoleNotFound() => TypedResults.NotFound();

        private static bool IsValidClaim(ClaimDto claim) =>
            claim != null && !string.IsNullOrWhiteSpace(claim.Type) && claim.Value != null;

    }
}
