using AutoMapper;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using RuntimeApps.Authentication.Extensions;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Controller
{
    public static class AccountApiEndpointRouteBuilderExtensions {
        public static IEndpointRouteBuilder MapLoginApi<TUser, TUserDto, TKey>(this IEndpointRouteBuilder endpoints)
            where TUser : IdentityUser<TKey>
            where TUserDto : class
            where TKey : IEquatable<TKey> {
            var routeGroup = endpoints.MapGroup("");

            IMapper mapper = endpoints.ServiceProvider.GetRequiredService<IMapper>();
            IEnumerable<IExternalLoginProvider<TUser>> externalLoginProviders = endpoints.ServiceProvider.GetServices<IExternalLoginProvider<TUser>>();

            routeGroup.MapPost("login", async Task<Results<Ok<Result<TUserDto, Token>>, ValidationProblem>> ([FromBody] UserLoginModel userLoginModel, IUserAccountService<TUser> userAccountService) => {
                var result = await userAccountService.LoginAsync(userLoginModel.UserName, userLoginModel.Password);
                if(!result.Succeeded)
                    return result.CreateValidationProblem();
                return TypedResults.Ok(MapResult<TUser, TUserDto, TKey>(result, mapper));
            });

            if(externalLoginProviders?.Any() == true) {
                routeGroup.MapPost("login/external", async Task<Results<Ok<Result<TUserDto, Token>>, ValidationProblem>> ([FromBody] ExternalAuthModel request, IUserAccountService<TUser> userAccountService) => {
                    var result = await userAccountService.ExternalLoginAsync(request.Provider, request.Token);
                    if(!result.Succeeded)
                        return result.CreateValidationProblem();
                    return TypedResults.Ok(MapResult<TUser, TUserDto, TKey>(result, mapper));
                });
            }

            return endpoints;
        }

        public static IEndpointRouteBuilder MapRegisterApi<TUser, TUserDto, TKey>(this IEndpointRouteBuilder endpoints)
            where TUser : IdentityUser<TKey>
            where TUserDto : class
            where TKey : IEquatable<TKey> {
            var routeGroup = endpoints.MapGroup("");

            IMapper mapper = endpoints.ServiceProvider.GetRequiredService<IMapper>();

            routeGroup.MapPost("register", async Task<Results<Ok<Result<TUserDto, Token>>, ValidationProblem>> ([FromBody] RegisterUserModel<TUserDto> user, IUserAccountService<TUser> userAccountService) => {
                var result = await userAccountService.RegisterAsync(mapper.Map<TUser>(user.UserInfo), user.Password);
                if(!result.Succeeded)
                    return result.CreateValidationProblem();
                return TypedResults.Ok(MapResult<TUser, TUserDto, TKey>(result, mapper));
            });

            return endpoints;
        }

        public static IEndpointRouteBuilder MapAccountApi<TUser, TUserDto, TKey>(this IEndpointRouteBuilder endpoints)
        where TUser : IdentityUser<TKey>
        where TUserDto : class
        where TKey : IEquatable<TKey> {
            var authorizedRouteGroup = endpoints.MapGroup("").RequireAuthorization();
            IMapper mapper = endpoints.ServiceProvider.GetRequiredService<IMapper>();

            authorizedRouteGroup.MapGet("/", async (IUserManager<TUser> userManager, HttpContext httpContext) => {
                var user = await userManager.GetUserAsync(httpContext.User);
                return user != null ? mapper.Map<TUserDto>(user) : null;
            });

            authorizedRouteGroup.MapPost("password/change", async Task<Results<Ok, ValidationProblem>> ([FromBody] ChangePasswordModel input, IUserManager<TUser> userManager, HttpContext httpContext) => {
                var user = await userManager.GetUserAsync(httpContext.User);
                if(user == null)
                    return ValidationProblemFactory.CreateValidationProblem("NoAccess", "Cannot change password without login");

                var result = await userManager.ChangePasswordAsync(user, input.CurrentPassword, input.NewPassword);
                if(!result.Succeeded)
                    return result.CreateValidationProblem();

                return TypedResults.Ok();
            });

            authorizedRouteGroup.MapPost("password", async Task<Results<Ok, ValidationProblem>> ([FromBody] string password, IUserManager<TUser> userManager, HttpContext httpContext) => {
                var user = await userManager.GetUserAsync(httpContext.User);
                if(user == null)
                    return ValidationProblemFactory.CreateValidationProblem("NoAccess", "Cannot change password without login");

                var result = await userManager.AddPasswordAsync(user, password);
                if(!result.Succeeded)
                    return result.CreateValidationProblem();

                return TypedResults.Ok();
            });

            return endpoints;
        }

        private static Result<TUserDto, Token> MapResult<TUser, TUserDto, TKey>(Result<TUser, Token> result, IMapper mapper)
            where TUser : IdentityUser<TKey>
            where TUserDto : class
            where TKey : IEquatable<TKey> {
            return new Result<TUserDto, Token>(result.Code, result.Errors) {
                Data = result.Data != default ? mapper.Map<TUserDto>(result.Data) : default,
                Meta = result.Meta,
            };
        }
    }
}
