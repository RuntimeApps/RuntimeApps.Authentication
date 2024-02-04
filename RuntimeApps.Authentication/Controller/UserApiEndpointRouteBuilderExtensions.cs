using AutoMapper;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using RuntimeApps.Authentication.Interface;

namespace RuntimeApps.Authentication.Controller {
    public static class UserApiEndpointRouteBuilderExtensions {
        public static IEndpointRouteBuilder MapUserGetApi<TUser, TUserDto>(this IEndpointRouteBuilder endpoints)
            where TUser : class
            where TUserDto : class {
            var routeGroup = endpoints.MapGroup("");

            IMapper mapper = endpoints.ServiceProvider.GetRequiredService<IMapper>();

            routeGroup.MapGet("{userId}", async Task<TUserDto> ([FromRoute] string userId, IUserManager<TUser> userManager) => {
                var user = await userManager.FindByIdAsync(userId);
                return user != default ? mapper.Map<TUserDto>(user) : default;
            });

            routeGroup.MapGet("/", async Task<TUserDto> ([FromQuery] string userName, IUserManager<TUser> userManager) => {
                var user = await userManager.FindByNameAsync(userName);
                return user != default ? mapper.Map<TUserDto>(user) : default;
            });

            return endpoints;
        }

    }
}
