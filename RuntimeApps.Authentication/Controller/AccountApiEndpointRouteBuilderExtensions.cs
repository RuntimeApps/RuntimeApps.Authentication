using AutoMapper;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Controller {
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
                    return CreateValidationProblem(result);
                return TypedResults.Ok(MapResult<TUser, TUserDto, TKey>(result, mapper));
            });

            if(externalLoginProviders?.Any() == true) {
                routeGroup.MapPost("login/external", async Task<Results<Ok<Result<TUserDto, Token>>, ValidationProblem>> ([FromBody] ExternalAuthModel request, IUserAccountService<TUser> userAccountService) => {
                    var result = await userAccountService.ExternalLoginAsync(request.Provider, request.Token);
                    if(!result.Succeeded)
                        return CreateValidationProblem(result);
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
                    return CreateValidationProblem(result);
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
                    return CreateValidationProblem("NoAccess", "Cannot change password without login");

                var result = await userManager.ChangePasswordAsync(user, input.CurrentPassword, input.NewPassword);
                if(!result.Succeeded)
                    return CreateValidationProblem(result);

                return TypedResults.Ok();
            });

            authorizedRouteGroup.MapPost("password", async Task<Results<Ok, ValidationProblem>> ([FromBody] string password, IUserManager<TUser> userManager, HttpContext httpContext) => {
                var user = await userManager.GetUserAsync(httpContext.User);
                if(user == null)
                    return CreateValidationProblem("NoAccess", "Cannot change password without login");

                var result = await userManager.AddPasswordAsync(user, password);
                if(!result.Succeeded)
                    return CreateValidationProblem(result);

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

        private static ValidationProblem CreateValidationProblem(string errorCode, string errorDescription) =>
        TypedResults.ValidationProblem(new Dictionary<string, string[]> {
            { errorCode, new string[] { errorDescription } }
        });

        private static ValidationProblem CreateValidationProblem(IdentityResult result) {
            var errorDictionary = new Dictionary<string, string[]>(1);

            foreach(var error in result.Errors) {
                string[] newDescriptions;

                if(errorDictionary.TryGetValue(error.Code, out var descriptions)) {
                    newDescriptions = new string[descriptions.Length + 1];
                    Array.Copy(descriptions, newDescriptions, descriptions.Length);
                    newDescriptions[descriptions.Length] = error.Description;
                }
                else {
                    newDescriptions = new string[] { error.Description };
                }

                errorDictionary[error.Code] = newDescriptions;
            }

            return TypedResults.ValidationProblem(errorDictionary);
        }

        private static ValidationProblem CreateValidationProblem(Result result) {
            var errorDictionary = new Dictionary<string, string[]>(1);

            foreach(var error in result.Errors) {
                string[] newDescriptions;

                if(errorDictionary.TryGetValue(error.Code, out var descriptions)) {
                    newDescriptions = new string[descriptions.Length + 1];
                    Array.Copy(descriptions, newDescriptions, descriptions.Length);
                    newDescriptions[descriptions.Length] = error.Description;
                }
                else {
                    newDescriptions = new string[] { error.Description };
                }

                errorDictionary[error.Code] = newDescriptions;
            }

            return TypedResults.ValidationProblem(errorDictionary);
        }

    }
}
