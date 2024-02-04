using AutoMapper;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using RuntimeApps.Authentication.Extensions;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Controller
{
    public static class RoleClaimApiEndpointRouteBuilderExtensions {
        public static IEndpointRouteBuilder MapRoleClaimGetApi<TRole>(this IEndpointRouteBuilder endpoints)
            where TRole : class {
            var routeGroup = endpoints.MapGroup("");

            IMapper mapper = endpoints.ServiceProvider.GetRequiredService<IMapper>();

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

            IMapper mapper = endpoints.ServiceProvider.GetRequiredService<IMapper>();

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
