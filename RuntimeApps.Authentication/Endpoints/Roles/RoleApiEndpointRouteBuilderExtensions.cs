using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Endpoints.Roles.Models;
using RuntimeApps.Authentication.Shared.Extensions;
namespace RuntimeApps.Authentication.Endpoints.Roles {
    public static class RoleApiEndpointRouteBuilderExtensions {
        public static IEndpointRouteBuilder MapRoleGetApi<TRole>(this IEndpointRouteBuilder endpoints)
            where TRole : class {
            var routeGroup = endpoints.MapGroup("");

            routeGroup.MapGet("{roleId}", async Task<IResult> ([FromRoute] string roleId, IRoleManager<TRole> roleManager, CancellationToken cancellationToken) => {
                cancellationToken.ThrowIfCancellationRequested();
                var role = await roleManager.FindByIdAsync(roleId);
                cancellationToken.ThrowIfCancellationRequested();
                return role == null ? TypedResults.NotFound() : TypedResults.Ok(role);
            }).Produces<TRole>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound);

            routeGroup.MapGet("name/{roleName}", async Task<IResult> ([FromRoute] string roleName, IRoleManager<TRole> roleManager, CancellationToken cancellationToken) => {
                cancellationToken.ThrowIfCancellationRequested();
                var role = await roleManager.FindByNameAsync(roleName);
                cancellationToken.ThrowIfCancellationRequested();
                return role == null ? TypedResults.NotFound() : TypedResults.Ok(role);
            }).Produces<TRole>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound);

            routeGroup.MapGet("/", IEnumerable<TRole> (IRoleManager<TRole> roleManager, CancellationToken cancellationToken) => {
                cancellationToken.ThrowIfCancellationRequested();
                return roleManager.Roles.ToList();
            }).Produces<IEnumerable<TRole>>(StatusCodes.Status200OK);

            return endpoints;
        }

        public static IEndpointRouteBuilder MapRoleManageApi<TRole>(this IEndpointRouteBuilder endpoints)
            where TRole : class {
            var routeGroup = endpoints.MapGroup("");

            routeGroup.MapPost("/", async Task<IResult> ([FromBody] RoleRequest<TRole> request, IRoleManager<TRole> roleManager, CancellationToken cancellationToken) => {
                if(request?.Role == null)
                    return ValidationProblemFactory.CreateValidationProblem("InvalidRole", "Role is required.");
                cancellationToken.ThrowIfCancellationRequested();
                var result = await roleManager.CreateAsync(request.Role);
                if(!result.Succeeded)
                    return result.CreatePublicError();

                return TypedResults.Ok();
            }).Produces(StatusCodes.Status200OK)
              .ProducesValidationProblem(StatusCodes.Status400BadRequest);

            routeGroup.MapPut("/", async Task<IResult> ([FromBody] RoleRequest<TRole> request, IRoleManager<TRole> roleManager, CancellationToken cancellationToken) => {
                if(request?.Role == null)
                    return ValidationProblemFactory.CreateValidationProblem("InvalidRole", "Role is required.");
                cancellationToken.ThrowIfCancellationRequested();
                var result = await roleManager.UpdateAsync(request.Role);
                if(!result.Succeeded)
                    return result.CreatePublicError();

                return TypedResults.Ok();
            }).Produces(StatusCodes.Status200OK)
              .ProducesValidationProblem(StatusCodes.Status400BadRequest);

            routeGroup.MapDelete("{roleId}", async Task<IResult> ([FromRoute] string roleId, IRoleManager<TRole> roleManager, CancellationToken cancellationToken) => {
                cancellationToken.ThrowIfCancellationRequested();
                var role = await roleManager.FindByIdAsync(roleId);
                if(role == null)
                    return TypedResults.NotFound();

                cancellationToken.ThrowIfCancellationRequested();
                var result = await roleManager.DeleteAsync(role);
                if(!result.Succeeded)
                    return result.CreatePublicError();

                return TypedResults.Ok();
            }).Produces(StatusCodes.Status200OK)
              .Produces(StatusCodes.Status404NotFound)
              .ProducesValidationProblem(StatusCodes.Status400BadRequest);

            return endpoints;
        }
    }
}
