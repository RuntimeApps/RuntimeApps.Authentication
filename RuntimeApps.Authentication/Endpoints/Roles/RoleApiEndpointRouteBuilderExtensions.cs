using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Shared.Extensions;
namespace RuntimeApps.Authentication.Endpoints.Roles {
    public static class RoleApiEndpointRouteBuilderExtensions {
        public static IEndpointRouteBuilder MapRoleGetApi<TRole>(this IEndpointRouteBuilder endpoints)
            where TRole : class {
            var routeGroup = endpoints.MapGroup("");

            routeGroup.MapGet("{roleId}", async Task<IResult> ([FromRoute] string roleId, IRoleManager<TRole> roleManager) => {
                var role = await roleManager.FindByIdAsync(roleId);
                return role == null ? TypedResults.NotFound() : TypedResults.Ok(role);
            }).Produces<TRole>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound);

            routeGroup.MapGet("name/{roleName}", async Task<IResult> ([FromRoute] string roleName, IRoleManager<TRole> roleManager) => {
                var role = await roleManager.FindByNameAsync(roleName);
                return role == null ? TypedResults.NotFound() : TypedResults.Ok(role);
            }).Produces<TRole>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound);

            routeGroup.MapGet("/", IEnumerable<TRole> (IRoleManager<TRole> roleManager) => {
                return roleManager.Roles.ToList();
            }).Produces<IEnumerable<TRole>>(StatusCodes.Status200OK);

            return endpoints;
        }

        public static IEndpointRouteBuilder MapRoleManageApi<TRole>(this IEndpointRouteBuilder endpoints)
            where TRole : class {
            var routeGroup = endpoints.MapGroup("");

            routeGroup.MapPost("/", async Task<IResult> ([FromBody] TRole role, IRoleManager<TRole> roleManager) => {
                var result = await roleManager.CreateAsync(role);
                if(!result.Succeeded)
                    return result.CreatePublicError();

                return TypedResults.Ok();
            }).Produces(StatusCodes.Status200OK)
              .ProducesValidationProblem(StatusCodes.Status400BadRequest);

            routeGroup.MapPut("/", async Task<IResult> ([FromBody] TRole role, IRoleManager<TRole> roleManager) => {
                var result = await roleManager.UpdateAsync(role);
                if(!result.Succeeded)
                    return result.CreatePublicError();

                return TypedResults.Ok();
            }).Produces(StatusCodes.Status200OK)
              .ProducesValidationProblem(StatusCodes.Status400BadRequest);

            routeGroup.MapDelete("{roleId}", async Task<IResult> ([FromRoute] string roleId, IRoleManager<TRole> roleManager) => {
                var role = await roleManager.FindByIdAsync(roleId);
                if(role == null)
                    return TypedResults.NotFound();

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
