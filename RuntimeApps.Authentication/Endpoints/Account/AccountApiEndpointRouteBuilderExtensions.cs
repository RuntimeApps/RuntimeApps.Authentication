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

            routeGroup.MapPost("login", async Task<IResult> ([FromBody] UserLoginModel userLoginModel, IUserAccountService<TUser> userAccountService, [FromServices] IUserMapper<TUser, TUserDto> mapper, HttpContext context) => {
                if(string.IsNullOrWhiteSpace(userLoginModel?.UserName) || string.IsNullOrEmpty(userLoginModel.Password))
                    return ValidationProblemFactory.CreateValidationProblem("InvalidLogin", "User name and password are required.");
                var result = await userAccountService.LoginAsync(userLoginModel.UserName, userLoginModel.Password, context.RequestAborted);
                if(!result.Succeeded) {
                    // Keep the existing two-factor continuation response separate from credential failures.
                    if(result.Code == ResultCode.Accepted)
                        return TypedResults.Accepted((string)null, new AuthenticationContinuationResponse());
                    // Keep unknown, unconfirmed, locked, and incorrect-password failures indistinguishable.
                    return TypedResults.Problem(statusCode: StatusCodes.Status401Unauthorized,
                        title: "Authentication failed", detail: "The username or password is incorrect.",
                        extensions: new Dictionary<string, object> { ["code"] = "authentication_failed" });
                }
                return TypedResults.Ok(MapResult<TUser, TUserDto, TKey>(result, mapper));
            }).WithName("Authentication_Login").WithTags("Authentication").WithSummary("Log in")
              .Produces<Result<TUserDto, Token>>(StatusCodes.Status200OK)
              .Produces<AuthenticationContinuationResponse>(StatusCodes.Status202Accepted)
              .ProducesValidationProblem(StatusCodes.Status400BadRequest)
              .ProducesProblem(StatusCodes.Status401Unauthorized);

            if(endpoints.ServiceProvider.GetService<IServiceProviderIsService>()
                ?.IsService(typeof(IExternalLoginProvider<TUser>)) == true) {
                routeGroup.MapPost("login/external", async Task<IResult> ([FromBody] ExternalAuthModel request, IUserAccountService<TUser> userAccountService, [FromServices] IUserMapper<TUser, TUserDto> mapper, HttpContext context) => {
                    if(string.IsNullOrWhiteSpace(request?.Provider) || string.IsNullOrWhiteSpace(request.Token))
                        return ValidationProblemFactory.CreateValidationProblem("InvalidExternalLogin", "Provider and token are required.");
                    var result = await userAccountService.ExternalLoginAsync(request.Provider, request.Token, context.RequestAborted);
                    if(!result.Succeeded)
                        return PublicErrorFactory.CreateExternalAuthenticationFailure();
                    return TypedResults.Ok(MapResult<TUser, TUserDto, TKey>(result, mapper));
                }).WithName("Authentication_ExternalLogin").WithTags("Authentication").WithSummary("Log in with an external provider")
                  .Produces<Result<TUserDto, Token>>(StatusCodes.Status200OK)
                  .ProducesValidationProblem(StatusCodes.Status400BadRequest)
                  .ProducesProblem(StatusCodes.Status401Unauthorized);
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

            routeGroup.MapPost("register", async Task<IResult> (
                [FromBody] RegisterUserModel<TUserDto> user,
                IRegistrationService<TUser, TKey> registrationService,
                [FromServices] IUserMapper<TUser, TUserDto> mapper,
                HttpContext httpContext) => {
                    if(user?.UserInfo == null)
                        return ValidationProblemFactory.CreateValidationProblem("InvalidRegistration", "User information is required.");

                    var result = await registrationService.RegisterAsync(
                        mapper.ToUser(user.UserInfo), user.Password, httpContext.RequestAborted);
                    if(!result.Succeeded)
                        return result.CreatePublicError();
                    return TypedResults.Accepted((string)null, result);
                }).WithName("Registration_Register").WithTags("Registration").WithSummary("Register a user")
                  .Produces<Result<RegistrationVerificationResponse>>(StatusCodes.Status202Accepted)
                  .ProducesValidationProblem(StatusCodes.Status400BadRequest);

            return endpoints;
        }

        /// <summary>Maps registration verification and resend endpoints.</summary>
        public static IEndpointRouteBuilder MapVerificationApi<TUser, TUserDto, TKey>(this IEndpointRouteBuilder endpoints)
            where TUser : IdentityUser<TKey>, new()
            where TUserDto : class
            where TKey : IEquatable<TKey> {
            RequireServices(endpoints, "Verification", typeof(IRegistrationService<TUser, TKey>), typeof(IUserMapper<TUser, TUserDto>), typeof(IVerificationWorkflowService<TUser, TKey>), typeof(IVerificationRequestStore<TKey>), typeof(IVerificationSender<TUser, TKey>));
            var routeGroup = endpoints.MapGroup("").AllowAnonymous();
            routeGroup.MapPost("register/verify", async Task<IResult> (
                [FromBody] VerifyRegistrationModel request,
                IRegistrationService<TUser, TKey> registrationService,
                [FromServices] IUserMapper<TUser, TUserDto> mapper,
                HttpContext httpContext) => {
                    if(request == null)
                        return ValidationProblemFactory.CreateValidationProblem("InvalidVerification", "Verification handle and code are required.");

                    var result = await registrationService.VerifyAsync(
                        request.VerificationHandle, request.Code, httpContext.RequestAborted);
                    if(!result.Succeeded)
                        return result.CreatePublicError();
                    return TypedResults.Ok(MapResult<TUser, TUserDto, TKey>(result, mapper));
                }).WithName("Verification_VerifyRegistration").WithTags("Verification").WithSummary("Verify a registration")
                  .Produces<Result<TUserDto, Token>>(StatusCodes.Status200OK)
                  .ProducesProblem(StatusCodes.Status403Forbidden)
                  .ProducesValidationProblem(StatusCodes.Status400BadRequest);

            routeGroup.MapPost("register/resend", async Task<IResult> (
                [FromBody] ResendRegistrationVerificationModel request,
                IRegistrationService<TUser, TKey> registrationService,
                HttpContext httpContext) => {
                    if(request == null)
                        return ValidationProblemFactory.CreateValidationProblem("InvalidVerification", "Verification handle is required.");

                    var result = await registrationService.ResendAsync(
                        request.VerificationHandle, httpContext.RequestAborted);
                    if(!result.Succeeded)
                        return result.CreatePublicError();
                    return TypedResults.Accepted((string)null, result);
                }).WithName("Verification_ResendRegistration").WithTags("Verification").WithSummary("Resend registration verification")
                  .Produces<Result<RegistrationVerificationResponse>>(StatusCodes.Status202Accepted)
                  .ProducesValidationProblem(StatusCodes.Status400BadRequest);

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

            routeGroup.MapPost("", async Task<IResult> (
                [FromBody] RegisterUserModel<TUserDto> request,
                IUserManager<TUser> userManager,
                [FromServices] IUserMapper<TUser, TUserDto> mapper,
                CancellationToken cancellationToken) => {
                    if(request?.UserInfo == null || string.IsNullOrEmpty(request.Password))
                        return ValidationProblemFactory.CreateValidationProblem(
                            "InvalidUser", "User information and password are required.");

                    cancellationToken.ThrowIfCancellationRequested();
                    var user = mapper.ToUser(request.UserInfo);
                    if(string.IsNullOrWhiteSpace(user.UserName))
                        user.UserName = user.Email;
                    user.EmailConfirmed = true;

                    var result = await userManager.CreateAsync(user, request.Password);
                    if(!result.Succeeded)
                        return result.CreatePublicError();

                    return TypedResults.Ok(mapper.ToDto(user));
                }).Produces<TUserDto>(StatusCodes.Status200OK)
                  .ProducesValidationProblem(StatusCodes.Status400BadRequest)
                  .Produces(StatusCodes.Status401Unauthorized)
                  .Produces(StatusCodes.Status403Forbidden);

            return endpoints;
        }

        /// <summary>Maps authenticated current-account and password-management endpoints.</summary>
        public static IEndpointRouteBuilder MapAccountManagementApi<TUser, TUserDto, TKey>(this IEndpointRouteBuilder endpoints)
        where TUser : IdentityUser<TKey>
        where TUserDto : class
        where TKey : IEquatable<TKey> {
            RequireServices(endpoints, "Account management", typeof(IUserManager<TUser>), typeof(IUserMapper<TUser, TUserDto>), typeof(IUserPasswordManager<TUser>));
            var authorizedRouteGroup = endpoints.MapGroup("").RequireAuthorization();

            authorizedRouteGroup.MapGet("/", async Task<IResult> (IUserManager<TUser> userManager, HttpContext httpContext, IUserMapper<TUser, TUserDto> mapper, CancellationToken cancellationToken) => {
                cancellationToken.ThrowIfCancellationRequested();
                var user = await userManager.GetUserAsync(httpContext.User);
                cancellationToken.ThrowIfCancellationRequested();
                return user != null ? TypedResults.Ok(mapper.ToDto(user)) : TypedResults.Unauthorized();
            }).WithName("AccountManagement_Get").WithTags("Account management").WithSummary("Get the current account")
              .Produces<TUserDto>(StatusCodes.Status200OK)
              .Produces(StatusCodes.Status401Unauthorized)
              .Produces(StatusCodes.Status403Forbidden);

            authorizedRouteGroup.MapPost("password/change", async Task<IResult> ([FromBody] ChangePasswordModel input, IUserManager<TUser> userManager, IUserPasswordManager<TUser> passwordManager, HttpContext httpContext, IServiceProvider services, CancellationToken cancellationToken) => {
                if(string.IsNullOrEmpty(input?.CurrentPassword) || string.IsNullOrEmpty(input.NewPassword))
                    return ValidationProblemFactory.CreateValidationProblem("InvalidPassword", "Current and new passwords are required.");
                cancellationToken.ThrowIfCancellationRequested();
                var user = await userManager.GetUserAsync(httpContext.User);
                if(user == null)
                    return TypedResults.Unauthorized();

                cancellationToken.ThrowIfCancellationRequested();
                var result = await passwordManager.ChangePasswordAsync(user, input.CurrentPassword, input.NewPassword);
                if(!result.Succeeded)
                    return result.CreatePublicError();

                var refreshTokenService = services.GetService<IRefreshTokenService<TKey>>();
                if(refreshTokenService != null)
                    await refreshTokenService.RevokeAllAsync(user.Id, CancellationToken.None);

                return TypedResults.Ok();
            }).WithName("AccountManagement_ChangePassword").WithTags("Account management").WithSummary("Change the current password")
              .Produces(StatusCodes.Status200OK)
              .ProducesValidationProblem(StatusCodes.Status400BadRequest)
              .Produces(StatusCodes.Status401Unauthorized)
              .Produces(StatusCodes.Status403Forbidden);

            authorizedRouteGroup.MapPost("password", async Task<IResult> ([FromBody] AddPasswordRequest request, IUserManager<TUser> userManager, IUserPasswordManager<TUser> passwordManager, HttpContext httpContext, IServiceProvider services, CancellationToken cancellationToken) => {
                cancellationToken.ThrowIfCancellationRequested();
                var user = await userManager.GetUserAsync(httpContext.User);
                if(user == null)
                    return TypedResults.Unauthorized();
                if(string.IsNullOrEmpty(request?.Password))
                    return ValidationProblemFactory.CreateValidationProblem("InvalidPassword", "Password is required.");

                cancellationToken.ThrowIfCancellationRequested();
                var result = await passwordManager.AddPasswordAsync(user, request?.Password);
                if(!result.Succeeded)
                    return result.CreatePublicError();

                var refreshTokenService = services.GetService<IRefreshTokenService<TKey>>();
                if(refreshTokenService != null)
                    await refreshTokenService.RevokeAllAsync(user.Id, CancellationToken.None);

                return TypedResults.Ok();
            }).WithName("AccountManagement_AddPassword").WithTags("Account management").WithSummary("Add a password to the current account")
              .Produces(StatusCodes.Status200OK)
              .ProducesValidationProblem(StatusCodes.Status400BadRequest)
              .Produces(StatusCodes.Status401Unauthorized)
              .Produces(StatusCodes.Status403Forbidden);

            // Linking is only offered when at least one external login provider is registered.
            if(endpoints.ServiceProvider.GetService<IServiceProviderIsService>()
                ?.IsService(typeof(IExternalLoginService<TUser>)) == true) {
                authorizedRouteGroup.MapGet("logins", async Task<IResult> (IUserManager<TUser> userManager, IExternalLoginService<TUser> externalLoginService, HttpContext httpContext, CancellationToken cancellationToken) => {
                    cancellationToken.ThrowIfCancellationRequested();
                    var user = await userManager.GetUserAsync(httpContext.User);
                    if(user == null)
                        return TypedResults.Unauthorized();

                    cancellationToken.ThrowIfCancellationRequested();
                    return TypedResults.Ok(await externalLoginService.ListLoginsAsync(user, cancellationToken));
                }).WithName("AccountManagement_ListExternalLogins").WithTags("Account management").WithSummary("List the external logins linked to the current account")
                  .Produces<IReadOnlyList<ExternalLoginSummary>>(StatusCodes.Status200OK)
                  .Produces(StatusCodes.Status401Unauthorized)
                  .Produces(StatusCodes.Status403Forbidden);

                authorizedRouteGroup.MapPost("logins/link", async Task<IResult> ([FromBody] LinkExternalLoginModel request, IUserManager<TUser> userManager, IExternalLoginService<TUser> externalLoginService, HttpContext httpContext, CancellationToken cancellationToken) => {
                    if(string.IsNullOrWhiteSpace(request?.Provider) || string.IsNullOrWhiteSpace(request.Token))
                        return ValidationProblemFactory.CreateValidationProblem("InvalidExternalLogin", "Provider and token are required.");
                    cancellationToken.ThrowIfCancellationRequested();
                    var user = await userManager.GetUserAsync(httpContext.User);
                    if(user == null)
                        return TypedResults.Unauthorized();

                    cancellationToken.ThrowIfCancellationRequested();
                    var result = await externalLoginService.LinkAsync(user, request, cancellationToken);
                    return result.Succeeded ? TypedResults.Ok() : result.CreatePublicError();
                }).WithName("AccountManagement_LinkExternalLogin").WithTags("Account management").WithSummary("Link an external login to the current account after re-authentication")
                  .Produces(StatusCodes.Status200OK)
                  .ProducesValidationProblem(StatusCodes.Status400BadRequest)
                  .Produces(StatusCodes.Status401Unauthorized)
                  .Produces(StatusCodes.Status403Forbidden)
                  .Produces(StatusCodes.Status409Conflict);

                authorizedRouteGroup.MapPost("logins/unlink", async Task<IResult> ([FromBody] UnlinkExternalLoginModel request, IUserManager<TUser> userManager, IExternalLoginService<TUser> externalLoginService, HttpContext httpContext, CancellationToken cancellationToken) => {
                    if(string.IsNullOrWhiteSpace(request?.Provider))
                        return ValidationProblemFactory.CreateValidationProblem("InvalidExternalLogin", "Provider is required.");
                    cancellationToken.ThrowIfCancellationRequested();
                    var user = await userManager.GetUserAsync(httpContext.User);
                    if(user == null)
                        return TypedResults.Unauthorized();

                    cancellationToken.ThrowIfCancellationRequested();
                    var result = await externalLoginService.UnlinkAsync(user, request.Provider, cancellationToken);
                    return result.Succeeded ? TypedResults.Ok() : result.CreatePublicError();
                }).WithName("AccountManagement_UnlinkExternalLogin").WithTags("Account management").WithSummary("Unlink an external login unless it is the last authentication method")
                  .Produces(StatusCodes.Status200OK)
                  .ProducesValidationProblem(StatusCodes.Status400BadRequest)
                  .Produces(StatusCodes.Status401Unauthorized)
                  .Produces(StatusCodes.Status403Forbidden)
                  .Produces(StatusCodes.Status409Conflict);
            }

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
