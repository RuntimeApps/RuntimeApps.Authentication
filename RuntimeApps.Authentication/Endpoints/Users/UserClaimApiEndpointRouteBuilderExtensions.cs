using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Features.Account.Models;
using RuntimeApps.Authentication.Shared.Extensions;
using RuntimeApps.Authentication.Shared.Models;
namespace RuntimeApps.Authentication.Endpoints.Users {
    public static class UserClaimApiEndpointRouteBuilderExtensions {
        public static IEndpointRouteBuilder MapUserClaimGetApi<TUser>(this IEndpointRouteBuilder endpoints)
            where TUser : class {
            var routeGroup = endpoints.MapGroup("");

            routeGroup.MapGet("{userId}/claim", async Task<IResult> ([FromRoute] string userId, IUserManager<TUser> userManager, IUserClaimManager<TUser> claimManager, CancellationToken cancellationToken) => {
                cancellationToken.ThrowIfCancellationRequested();
                var user = await userManager.FindByIdAsync(userId);
                if(user == null)
                    return UserNotFound();

                cancellationToken.ThrowIfCancellationRequested();
                var result = await claimManager.GetClaimsAsync(user);
                cancellationToken.ThrowIfCancellationRequested();
                return TypedResults.Ok(result?.Select(c => new ClaimDto(c)));
            }).Produces<IEnumerable<ClaimDto>>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound);

            return endpoints;
        }
        public static IEndpointRouteBuilder MapUserClaimManageApi<TUser>(this IEndpointRouteBuilder endpoints)
            where TUser : class {
            var routeGroup = endpoints.MapGroup("");

            routeGroup.MapPost("{userId}/claim", async Task<IResult> ([FromRoute] string userId, [FromBody] ClaimDto claim, IUserManager<TUser> userManager, IUserClaimManager<TUser> claimManager, CancellationToken cancellationToken) => {
                if(!IsValidClaim(claim))
                    return ValidationProblemFactory.CreateValidationProblem("InvalidClaim", "Claim type and value are required.");
                cancellationToken.ThrowIfCancellationRequested();
                var user = await userManager.FindByIdAsync(userId);
                if(user == null)
                    return UserNotFound();

                cancellationToken.ThrowIfCancellationRequested();
                var result = await claimManager.AddClaimAsync(user, claim.ToClaim());
                if(!result.Succeeded)
                    return result.CreatePublicError();
                return TypedResults.Ok();
            }).Produces(StatusCodes.Status200OK)
            .ProducesValidationProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status404NotFound);

            routeGroup.MapDelete("{userId}/claim", async Task<IResult> ([FromRoute] string userId, [FromBody] ClaimDto claim, IUserManager<TUser> userManager, IUserClaimManager<TUser> claimManager, CancellationToken cancellationToken) => {
                if(!IsValidClaim(claim))
                    return ValidationProblemFactory.CreateValidationProblem("InvalidClaim", "Claim type and value are required.");
                cancellationToken.ThrowIfCancellationRequested();
                var user = await userManager.FindByIdAsync(userId);
                if(user == null)
                    return UserNotFound();

                cancellationToken.ThrowIfCancellationRequested();
                var result = await claimManager.RemoveClaimAsync(user, claim.ToClaim());
                if(!result.Succeeded)
                    return result.CreatePublicError();
                return TypedResults.Ok();
            }).Produces(StatusCodes.Status200OK)
            .ProducesValidationProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status404NotFound);

            routeGroup.MapPost("{userId}/claim/bulk", async Task<IResult> ([FromRoute] string userId, [FromBody] BulkClaimsRequest request, IUserManager<TUser> userManager, IUserClaimManager<TUser> claimManager, CancellationToken cancellationToken) => {
                if(!HasValidClaims(request?.Claims))
                    return ValidationProblemFactory.CreateValidationProblem("InvalidClaims", "Provide at least one claim with a type and value.");
                cancellationToken.ThrowIfCancellationRequested();
                var user = await userManager.FindByIdAsync(userId);
                if(user == null)
                    return UserNotFound();

                cancellationToken.ThrowIfCancellationRequested();
                var result = await claimManager.AddClaimsAsync(user, request.Claims.Select(c => c.ToClaim()));
                if(!result.Succeeded)
                    return result.CreatePublicError();
                return TypedResults.Ok();
            }).Produces(StatusCodes.Status200OK)
            .ProducesValidationProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status404NotFound);

            routeGroup.MapDelete("{userId}/claim/bulk", async Task<IResult> ([FromRoute] string userId, [FromBody] BulkClaimsRequest request, IUserManager<TUser> userManager, IUserClaimManager<TUser> claimManager, CancellationToken cancellationToken) => {
                if(!HasValidClaims(request?.Claims))
                    return ValidationProblemFactory.CreateValidationProblem("InvalidClaims", "Provide at least one claim with a type and value.");
                cancellationToken.ThrowIfCancellationRequested();
                var user = await userManager.FindByIdAsync(userId);
                if(user == null)
                    return UserNotFound();

                cancellationToken.ThrowIfCancellationRequested();
                var result = await claimManager.RemoveClaimsAsync(user, request.Claims.Select(c => c.ToClaim()));
                if(!result.Succeeded)
                    return result.CreatePublicError();
                return TypedResults.Ok();
            }).Produces(StatusCodes.Status200OK)
            .ProducesValidationProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status404NotFound);

            return endpoints;
        }

        private static IResult UserNotFound() => TypedResults.NotFound();

        private static bool IsValidClaim(ClaimDto claim) =>
            claim != null && !string.IsNullOrWhiteSpace(claim.Type) && claim.Value != null;

        private static bool HasValidClaims(IReadOnlyCollection<ClaimDto> claims) =>
            claims is { Count: > 0 } && claims.All(IsValidClaim);

    }
}
