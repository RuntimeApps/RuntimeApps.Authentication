using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using RuntimeApps.Authentication.Identity.Contracts;
namespace RuntimeApps.Authentication.Endpoints.Users {
    public static class UserApiEndpointRouteBuilderExtensions {
        public static IEndpointRouteBuilder MapUserGetApi<TUser, TUserDto>(this IEndpointRouteBuilder endpoints)
            where TUser : class
            where TUserDto : class {
            var routeGroup = endpoints.MapGroup("");

            routeGroup.MapGet("{userId}", async Task<IResult> ([FromRoute] string userId, IUserManager<TUser> userManager, [FromServices] IUserMapper<TUser, TUserDto> mapper) => {
                var user = await userManager.FindByIdAsync(userId);
                return user != default ? TypedResults.Ok(mapper.ToDto(user)) : TypedResults.NotFound();
            }).Produces<TUserDto>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound);

            routeGroup.MapGet("/", async Task<IResult> ([FromQuery] string userName, IUserManager<TUser> userManager, [FromServices] IUserMapper<TUser, TUserDto> mapper) => {
                var user = await userManager.FindByNameAsync(userName);
                return user != default ? TypedResults.Ok(mapper.ToDto(user)) : TypedResults.NotFound();
            }).Produces<TUserDto>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status404NotFound);

            return endpoints;
        }

    }
}
