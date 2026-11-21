using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Shared.Extensions;
namespace RuntimeApps.Authentication.Endpoints.Users {
    public static class UserRoleApiEndpointRouteBuilderExtensions {
        public static IEndpointRouteBuilder MapUserRoleGetApi<TUser>(this IEndpointRouteBuilder endpoints)
            where TUser : class {
            var routeGroup = endpoints.MapGroup("");

            routeGroup.MapGet("{userId}/Role", async Task<Results<Ok<IList<string>>, ValidationProblem>> ([FromRoute] string userId, IUserManager<TUser> userManager, IUserRoleManager<TUser> roleManager) => {
                var user = await userManager.FindByIdAsync(userId);
                if(user == null)
                    return UserNotFound();

                var result = await roleManager.GetRolesAsync(user);
                return TypedResults.Ok(result);
            });

            return endpoints;
        }

        public static IEndpointRouteBuilder MapUserRoleManageApi<TUser>(this IEndpointRouteBuilder endpoints)
            where TUser : class {
            var routeGroup = endpoints.MapGroup("");

            routeGroup.MapPost("{userId}/Role", async Task<Results<Ok, ValidationProblem>> ([FromRoute] string userId, [FromBody] IEnumerable<string> roles, IUserManager<TUser> userManager, IUserRoleManager<TUser> roleManager) => {
                var user = await userManager.FindByIdAsync(userId);
                if(user == null)
                    return UserNotFound();

                var result = await roleManager.AddToRolesAsync(user, roles);
                if(!result.Succeeded)
                    return result.CreateValidationProblem();

                return TypedResults.Ok();
            });

            routeGroup.MapDelete("{userId}/Role", async Task<Results<Ok, ValidationProblem>> ([FromRoute] string userId, [FromBody] IEnumerable<string> roles, IUserManager<TUser> userManager, IUserRoleManager<TUser> roleManager) => {
                var user = await userManager.FindByIdAsync(userId);
                if(user == null)
                    return UserNotFound();

                var result = await roleManager.RemoveFromRolesAsync(user, roles);
                if(!result.Succeeded)
                    return result.CreateValidationProblem();

                return TypedResults.Ok();
            });

            routeGroup.MapPost("{userId}/Role/{roleName}", async Task<Results<Ok, ValidationProblem>> ([FromRoute] string userId, [FromRoute] string roleName, IUserManager<TUser> userManager, IUserRoleManager<TUser> roleManager) => {
                var user = await userManager.FindByIdAsync(userId);
                if(user == null)
                    return UserNotFound();

                var result = await roleManager.AddToRoleAsync(user, roleName);
                if(!result.Succeeded)
                    return result.CreateValidationProblem();

                return TypedResults.Ok();
            });

            routeGroup.MapDelete("{userId}/Role/{roleName}", async Task<Results<Ok, ValidationProblem>> ([FromRoute] string userId, [FromRoute] string roleName, IUserManager<TUser> userManager, IUserRoleManager<TUser> roleManager) => {
                var user = await userManager.FindByIdAsync(userId);
                if(user == null)
                    return UserNotFound();

                var result = await roleManager.RemoveFromRoleAsync(user, roleName);
                if(!result.Succeeded)
                    return result.CreateValidationProblem();

                return TypedResults.Ok();
            });

            return endpoints;
        }

        private static ValidationProblem UserNotFound() =>
            ValidationProblemFactory.CreateValidationProblem("NotFound", "User not found");

    }
}
