using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using RuntimeApps.Authentication.Endpoints.RefreshTokens;
using RuntimeApps.Authentication.Features.Account.Contracts;
using RuntimeApps.Authentication.Features.Account.Models;
using RuntimeApps.Authentication.Features.ExternalLogin.Contracts;
using RuntimeApps.Authentication.Features.ExternalLogin.Models;
using RuntimeApps.Authentication.Features.RefreshTokens.Contracts;
using RuntimeApps.Authentication.Features.Registration.Contracts;
using RuntimeApps.Authentication.Features.Registration.Models;
using RuntimeApps.Authentication.Features.Verification.Contracts;
using RuntimeApps.Authentication.Identity.Contracts;
using RuntimeApps.Authentication.Shared.Extensions;
using RuntimeApps.Authentication.Shared.Models;
namespace RuntimeApps.Authentication.Endpoints.Account {
    public static class AccountApiEndpointRouteBuilderExtensions {
        /// <summary>Maps login and configured external-login endpoints only.</summary>
        public static IEndpointRouteBuilder MapAuthenticationApi<TUser, TUserDto, TKey>(this IEndpointRouteBuilder endpoints)
            where TUser : IdentityUser<TKey>
            where TUserDto : class
            where TKey : IEquatable<TKey> {
            RequireServices(endpoints, "Authentication", typeof(IUserAccountService<TUser>), typeof(IUserMapper<TUser, TUserDto>));
            var routeGroup = endpoints.MapGroup("").AllowAnonymous();

            routeGroup.MapPost("login", async Task<Results<Ok<Result<TUserDto, Token>>, ValidationProblem>> ([FromBody] UserLoginModel userLoginModel, IUserAccountService<TUser> userAccountService, [FromServices] IUserMapper<TUser, TUserDto> mapper, HttpContext context) => {
                var result = await userAccountService.LoginAsync(userLoginModel.UserName, userLoginModel.Password, context.RequestAborted);
                if(!result.Succeeded)
                    return result.CreateValidationProblem();
                return TypedResults.Ok(MapResult<TUser, TUserDto, TKey>(result, mapper));
            }).WithName("Authentication_Login").WithTags("Authentication").WithSummary("Log in");

            if(endpoints.ServiceProvider.GetService<IServiceProviderIsService>()
                ?.IsService(typeof(IExternalLoginProvider<TUser>)) == true) {
                routeGroup.MapPost("login/external", async Task<Results<Ok<Result<TUserDto, Token>>, ValidationProblem>> ([FromBody] ExternalAuthModel request, IUserAccountService<TUser> userAccountService, [FromServices] IUserMapper<TUser, TUserDto> mapper, HttpContext context) => {
                    var result = await userAccountService.ExternalLoginAsync(request.Provider, request.Token, context.RequestAborted);
                    if(!result.Succeeded)
                        return result.CreateValidationProblem();
                    return TypedResults.Ok(MapResult<TUser, TUserDto, TKey>(result, mapper));
                }).WithName("Authentication_ExternalLogin").WithTags("Authentication").WithSummary("Log in with an external provider");
            }

            return endpoints;
        }

        /// <summary>Maps the user-registration endpoint.</summary>
        public static IEndpointRouteBuilder MapRegistrationApi<TUser, TUserDto, TKey>(this IEndpointRouteBuilder endpoints)
            where TUser : IdentityUser<TKey>, new()
            where TUserDto : class
            where TKey : IEquatable<TKey> {
            RequireServices(endpoints, "Registration",
                typeof(IRegistrationService<TUser, TKey>),
                typeof(IUserAccountService<TUser>),
                typeof(IUserMapper<TUser, TUserDto>),
                typeof(IVerificationWorkflowService<TUser, TKey>),
                typeof(IVerificationRequestStore<TKey>),
                typeof(IVerificationSender<TUser, TKey>));

            var routeGroup = endpoints.MapGroup("").AllowAnonymous();

            routeGroup.MapPost("register", async Task<Results<Accepted<Result<RegistrationVerificationResponse>>, ValidationProblem>> (
                [FromBody] RegisterUserModel<TUserDto> user,
                IRegistrationService<TUser, TKey> registrationService,
                [FromServices] IUserMapper<TUser, TUserDto> mapper,
                HttpContext httpContext) => {
                    if(user?.UserInfo == null)
                        return ValidationProblemFactory.CreateValidationProblem("InvalidRegistration", "User information is required.");

                    var result = await registrationService.RegisterAsync(
                        mapper.ToUser(user.UserInfo), user.Password, httpContext.RequestAborted);
                    if(!result.Succeeded)
                        return result.CreateValidationProblem();
                    return TypedResults.Accepted((string)null, result);
                }).WithName("Registration_Register").WithTags("Registration").WithSummary("Register a user");

            return endpoints;
        }

        /// <summary>Maps registration verification and resend endpoints.</summary>
        public static IEndpointRouteBuilder MapVerificationApi<TUser, TUserDto, TKey>(this IEndpointRouteBuilder endpoints)
            where TUser : IdentityUser<TKey>, new()
            where TUserDto : class
            where TKey : IEquatable<TKey> {
            RequireServices(endpoints, "Verification", typeof(IRegistrationService<TUser, TKey>), typeof(IUserMapper<TUser, TUserDto>), typeof(IVerificationWorkflowService<TUser, TKey>), typeof(IVerificationRequestStore<TKey>), typeof(IVerificationSender<TUser, TKey>));
            var routeGroup = endpoints.MapGroup("").AllowAnonymous();
            routeGroup.MapPost("register/verify", async Task<Results<Ok<Result<TUserDto, Token>>, ValidationProblem>> (
                [FromBody] VerifyRegistrationModel request,
                IRegistrationService<TUser, TKey> registrationService,
                [FromServices] IUserMapper<TUser, TUserDto> mapper,
                HttpContext httpContext) => {
                    if(request == null)
                        return ValidationProblemFactory.CreateValidationProblem("InvalidVerification", "Verification handle and code are required.");

                    var result = await registrationService.VerifyAsync(
                        request.VerificationHandle, request.Code, httpContext.RequestAborted);
                    if(!result.Succeeded)
                        return result.CreateValidationProblem();
                    return TypedResults.Ok(MapResult<TUser, TUserDto, TKey>(result, mapper));
                }).WithName("Verification_VerifyRegistration").WithTags("Verification").WithSummary("Verify a registration");

            routeGroup.MapPost("register/resend", async Task<Results<Accepted<Result<RegistrationVerificationResponse>>, ValidationProblem>> (
                [FromBody] ResendRegistrationVerificationModel request,
                IRegistrationService<TUser, TKey> registrationService,
                HttpContext httpContext) => {
                    if(request == null)
                        return ValidationProblemFactory.CreateValidationProblem("InvalidVerification", "Verification handle is required.");

                    var result = await registrationService.ResendAsync(
                        request.VerificationHandle, httpContext.RequestAborted);
                    if(!result.Succeeded)
                        return result.CreateValidationProblem();
                    return TypedResults.Accepted((string)null, result);
                }).WithName("Verification_ResendRegistration").WithTags("Verification").WithSummary("Resend registration verification");

            return endpoints;
        }

        /// <summary>
        /// Maps an administrator-only endpoint for creating users that are already email-confirmed.
        /// No authentication token is issued by this endpoint.
        /// </summary>
        public static IEndpointRouteBuilder MapAdminUserApi<TUser, TUserDto, TKey>(
            this IEndpointRouteBuilder endpoints,
            string authorizationPolicy = null)
            where TUser : IdentityUser<TKey>
            where TUserDto : class
            where TKey : IEquatable<TKey> {
            var serviceAvailability = endpoints.ServiceProvider.GetRequiredService<IServiceProviderIsService>();
            if(!serviceAvailability.IsService(typeof(IUserManager<TUser>)) ||
               !serviceAvailability.IsService(typeof(IUserMapper<TUser, TUserDto>)))
                throw new InvalidOperationException("Admin user endpoints require IUserManager and the configured user mapper.");

            var routeGroup = endpoints.MapGroup("admin/users");
            if(string.IsNullOrWhiteSpace(authorizationPolicy))
                routeGroup.RequireAuthorization(new AuthorizeAttribute { Roles = "Administrator" });
            else
                routeGroup.RequireAuthorization(authorizationPolicy);

            routeGroup.MapPost("", async Task<Results<Ok<TUserDto>, ValidationProblem>> (
                [FromBody] RegisterUserModel<TUserDto> request,
                IUserManager<TUser> userManager,
                [FromServices] IUserMapper<TUser, TUserDto> mapper) => {
                    if(request?.UserInfo == null || string.IsNullOrEmpty(request.Password))
                        return ValidationProblemFactory.CreateValidationProblem(
                            "InvalidUser", "User information and password are required.");

                    var user = mapper.ToUser(request.UserInfo);
                    if(string.IsNullOrWhiteSpace(user.UserName))
                        user.UserName = user.Email;
                    user.EmailConfirmed = true;

                    var result = await userManager.CreateAsync(user, request.Password);
                    if(!result.Succeeded)
                        return result.CreateValidationProblem();

                    return TypedResults.Ok(mapper.ToDto(user));
                });

            return endpoints;
        }

        /// <summary>Maps authenticated current-account and password-management endpoints.</summary>
        public static IEndpointRouteBuilder MapAccountManagementApi<TUser, TUserDto, TKey>(this IEndpointRouteBuilder endpoints)
        where TUser : IdentityUser<TKey>
        where TUserDto : class
        where TKey : IEquatable<TKey> {
            RequireServices(endpoints, "Account management", typeof(IUserManager<TUser>), typeof(IUserMapper<TUser, TUserDto>), typeof(IUserPasswordManager<TUser>));
            var authorizedRouteGroup = endpoints.MapGroup("").RequireAuthorization();

            authorizedRouteGroup.MapGet("/", async (IUserManager<TUser> userManager, HttpContext httpContext, IUserMapper<TUser, TUserDto> mapper) => {
                var user = await userManager.GetUserAsync(httpContext.User);
                return user != null ? mapper.ToDto(user) : null;
            }).WithName("AccountManagement_Get").WithTags("Account management").WithSummary("Get the current account");

            authorizedRouteGroup.MapPost("password/change", async Task<Results<Ok, ValidationProblem>> ([FromBody] ChangePasswordModel input, IUserManager<TUser> userManager, IUserPasswordManager<TUser> passwordManager, HttpContext httpContext, IServiceProvider services) => {
                var user = await userManager.GetUserAsync(httpContext.User);
                if(user == null)
                    return ValidationProblemFactory.CreateValidationProblem("NoAccess", "Cannot change password without login");

                var result = await passwordManager.ChangePasswordAsync(user, input.CurrentPassword, input.NewPassword);
                if(!result.Succeeded)
                    return result.CreateValidationProblem();

                var refreshTokenService = services.GetService<IRefreshTokenService<TKey>>();
                if(refreshTokenService != null)
                    await refreshTokenService.RevokeAllAsync(user.Id, httpContext.RequestAborted);

                return TypedResults.Ok();
            }).WithName("AccountManagement_ChangePassword").WithTags("Account management").WithSummary("Change the current password");

            authorizedRouteGroup.MapPost("password", async Task<Results<Ok, ValidationProblem>> ([FromBody] string password, IUserManager<TUser> userManager, IUserPasswordManager<TUser> passwordManager, HttpContext httpContext, IServiceProvider services) => {
                var user = await userManager.GetUserAsync(httpContext.User);
                if(user == null)
                    return ValidationProblemFactory.CreateValidationProblem("NoAccess", "Cannot change password without login");

                var result = await passwordManager.AddPasswordAsync(user, password);
                if(!result.Succeeded)
                    return result.CreateValidationProblem();

                var refreshTokenService = services.GetService<IRefreshTokenService<TKey>>();
                if(refreshTokenService != null)
                    await refreshTokenService.RevokeAllAsync(user.Id, httpContext.RequestAborted);

                return TypedResults.Ok();
            }).WithName("AccountManagement_AddPassword").WithTags("Account management").WithSummary("Add a password to the current account");

            return endpoints;
        }

        private static void RequireServices(IEndpointRouteBuilder endpoints, string feature, params Type[] services) {
            var availability = endpoints.ServiceProvider.GetService<IServiceProviderIsService>();
            var missing = availability == null ? services : services.Where(service => !availability.IsService(service)).ToArray();
            if(missing.Length > 0)
                throw new InvalidOperationException($"{feature} endpoints require these registered services: {string.Join(", ", missing.Select(service => service.Name))}.");
        }

        private static Result<TUserDto, Token> MapResult<TUser, TUserDto, TKey>(Result<TUser, Token> result, IUserMapper<TUser, TUserDto> mapper)
            where TUser : IdentityUser<TKey>
            where TUserDto : class
            where TKey : IEquatable<TKey> {
            return new Result<TUserDto, Token>(result.Code, result.Errors) {
                Data = result.Data != default ? mapper.ToDto(result.Data) : default,
                Meta = result.Meta,
            };
        }
    }
}
