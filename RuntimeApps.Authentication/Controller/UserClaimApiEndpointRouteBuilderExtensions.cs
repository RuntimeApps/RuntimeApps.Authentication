using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using RuntimeApps.Authentication.Extensions;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Controller {
    public static class UserClaimApiEndpointRouteBuilderExtensions {
        public static IEndpointRouteBuilder MapUserClaimGetApi<TUser>(this IEndpointRouteBuilder endpoints)
            where TUser : class {
            var routeGroup = endpoints.MapGroup("");

            routeGroup.MapGet("{userId}/claim", async Task<Results<Ok<IEnumerable<ClaimDto>>, ValidationProblem>> ([FromRoute] string userId, IUserManager<TUser> userManager) => {
                var user = await userManager.FindByIdAsync(userId);
                if(user == null)
                    return UserNotFound();

                var result = await userManager.GetClaimsAsync(user);
                return TypedResults.Ok(result?.Select(c => new ClaimDto(c)));
            });

            return endpoints;
        }
        public static IEndpointRouteBuilder MapUserClaimManageApi<TUser>(this IEndpointRouteBuilder endpoints)
            where TUser : class {
            var routeGroup = endpoints.MapGroup("");

            routeGroup.MapPost("{userId}/claim", async Task<Results<Ok, ValidationProblem>> ([FromRoute] string userId, [FromBody] ClaimDto claim, IUserManager<TUser> userManager) => {
                var user = await userManager.FindByIdAsync(userId);
                if(user == null)
                    return UserNotFound();

                var result = await userManager.AddClaimAsync(user, claim.ToClaim());
                if(!result.Succeeded)
                    return result.CreateValidationProblem();
                return TypedResults.Ok();
            });

            routeGroup.MapDelete("{userId}/claim", async Task<Results<Ok, ValidationProblem>> ([FromRoute] string userId, [FromBody] ClaimDto claim, IUserManager<TUser> userManager) => {
                var user = await userManager.FindByIdAsync(userId);
                if(user == null)
                    return UserNotFound();

                var result = await userManager.RemoveClaimAsync(user, claim.ToClaim());
                if(!result.Succeeded)
                    return result.CreateValidationProblem();
                return TypedResults.Ok();
            });

            routeGroup.MapPost("{userId}/claim/bulk", async Task<Results<Ok, ValidationProblem>> ([FromRoute] string userId, [FromBody] IEnumerable<ClaimDto> claims, IUserManager<TUser> userManager) => {
                var user = await userManager.FindByIdAsync(userId);
                if(user == null)
                    return UserNotFound();

                var result = await userManager.AddClaimsAsync(user, claims.Select(c => c.ToClaim()));
                if(!result.Succeeded)
                    return result.CreateValidationProblem();
                return TypedResults.Ok();
            });

            routeGroup.MapDelete("{userId}/claim/bulk", async Task<Results<Ok, ValidationProblem>> ([FromRoute] string userId, [FromBody] IEnumerable<ClaimDto> claims, IUserManager<TUser> userManager) => {
                var user = await userManager.FindByIdAsync(userId);
                if(user == null)
                    return UserNotFound();

                var result = await userManager.RemoveClaimsAsync(user, claims.Select(c => c.ToClaim()));
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
