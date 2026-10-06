using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using RuntimeApps.Authentication.Interface;

namespace RuntimeApps.Authentication.Controller {
    public static class UserApiEndpointRouteBuilderExtensions {
        public static IEndpointRouteBuilder MapUserGetApi<TUser, TUserDto>(this IEndpointRouteBuilder endpoints)
            where TUser : class
            where TUserDto : class {
            var routeGroup = endpoints.MapGroup("");

            routeGroup.MapGet("{userId}", async Task<TUserDto> ([FromRoute] string userId, IUserManager<TUser> userManager, [FromServices] IUserMapper<TUser, TUserDto> mapper) => {
                var user = await userManager.FindByIdAsync(userId);
                return user != default ? mapper.ToDto(user) : default;
            });

            routeGroup.MapGet("/", async Task<TUserDto> ([FromQuery] string userName, IUserManager<TUser> userManager, [FromServices] IUserMapper<TUser, TUserDto> mapper) => {
                var user = await userManager.FindByNameAsync(userName);
                return user != default ? mapper.ToDto(user) : default;
            });

            return endpoints;
        }

    }
}
