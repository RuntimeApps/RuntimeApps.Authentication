using AutoMapper;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using RuntimeApps.Authentication.Extensions;
using RuntimeApps.Authentication.Interface;

namespace RuntimeApps.Authentication.Controller {
    public static class RoleApiEndpointRouteBuilderExtensions {
        public static IEndpointRouteBuilder MapRoleGetApi<TRole>(this IEndpointRouteBuilder endpoints)
            where TRole : class {
            var routeGroup = endpoints.MapGroup("");

            IMapper mapper = endpoints.ServiceProvider.GetRequiredService<IMapper>();

            routeGroup.MapGet("{roleId}", async Task<TRole> ([FromRoute] string roleId, IRoleManager<TRole> roleManager) => {
                return await roleManager.FindByIdAsync(roleId);
            });

            routeGroup.MapGet("name/{roleName}", async Task<TRole> ([FromRoute] string roleName, IRoleManager<TRole> roleManager) => {
                return await roleManager.FindByNameAsync(roleName);
            });

            routeGroup.MapGet("/", IEnumerable<TRole> (IRoleManager<TRole> roleManager) => {
                return roleManager.Roles.ToList();
            });

            return endpoints;
        }

        public static IEndpointRouteBuilder MapRoleManageApi<TRole>(this IEndpointRouteBuilder endpoints)
            where TRole : class {
            var routeGroup = endpoints.MapGroup("");

            IMapper mapper = endpoints.ServiceProvider.GetRequiredService<IMapper>();

            routeGroup.MapPost("/", async Task<Results<Ok, ValidationProblem>> ([FromBody] TRole role, IRoleManager<TRole> roleManager) => {
                var result = await roleManager.CreateAsync(role);
                if(!result.Succeeded)
                    return result.CreateValidationProblem();

                return TypedResults.Ok();
            });

            routeGroup.MapPut("/", async Task<Results<Ok, ValidationProblem>> ([FromBody] TRole role, IRoleManager<TRole> roleManager) => {
                var result = await roleManager.UpdateAsync(role);
                if(!result.Succeeded)
                    return result.CreateValidationProblem();

                return TypedResults.Ok();
            });

            routeGroup.MapDelete("{roleId}", async Task<Results<Ok, ValidationProblem>> ([FromRoute] string roleId, IRoleManager<TRole> roleManager) => {
                var role = await roleManager.FindByIdAsync(roleId);
                if(role == null)
                    return ValidationProblemFactory.CreateValidationProblem("NotFound", "Role Not Found");

                var result = await roleManager.DeleteAsync(role);
                if(!result.Succeeded)
                    return result.CreateValidationProblem();

                return TypedResults.Ok();
            });

            return endpoints;
        }
    }
}
