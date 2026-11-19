using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using RuntimeApps.Authentication.Extensions;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Controller {
    public static class ForgotPasswordApiEndpointRouteBuilderExtensions {
        /// <summary>
        /// Maps the optional password-recovery endpoints. Call this explicitly to expose them.
        /// </summary>
        public static IEndpointRouteBuilder MapForgotPasswordApi<TUser, TKey>(
            this IEndpointRouteBuilder endpoints)
            where TUser : Microsoft.AspNetCore.Identity.IdentityUser<TKey>
            where TKey : IEquatable<TKey> {
            ArgumentNullException.ThrowIfNull(endpoints);

            var availability = endpoints.ServiceProvider.GetRequiredService<IServiceProviderIsService>();
            var requiredServices = new[] {
                typeof(IForgotPasswordService<TUser, TKey>),
                typeof(IForgotPasswordVerificationWorkflow<TUser, TKey>),
                typeof(IVerificationRequestStore<TKey>),
                typeof(IVerificationSender<TUser, TKey>),
                typeof(IUserManager<TUser>),
                typeof(Microsoft.AspNetCore.Identity.UserManager<TUser>)
            };
            var missing = requiredServices.Where(type => !availability.IsService(type)).ToArray();
            if(missing.Length > 0)
                throw new InvalidOperationException(
                    "Forgot-password endpoints require AddVerificationServices(), AddForgotPassword(), " +
                    "a persistent verification request store, and a verification sender. Missing: " +
                    string.Join(", ", missing.Select(type => type.Name)));

            var group = endpoints.MapGroup("");
            group.MapPost("forgot-password", async Task<Ok<ForgotPasswordResponse>> (
                [FromBody] ForgotPasswordRequestModel request,
                IForgotPasswordService<TUser, TKey> service,
                HttpContext httpContext) => {
                var result = await service.RequestAsync(request?.Email, httpContext.RequestAborted);
                return TypedResults.Ok(result);
            }).WithName("ForgotPassword");

            group.MapPost("reset-password", async Task<Results<Ok, ValidationProblem>> (
                [FromBody] ResetPasswordModel request,
                IForgotPasswordService<TUser, TKey> service,
                HttpContext httpContext) => {
                if(request == null)
                    return ValidationProblemFactory.CreateValidationProblem(
                        "InvalidPasswordReset", "The password reset request is invalid.");

                var result = await service.ResetAsync(
                    request.VerificationHandle, request.Credential, request.NewPassword,
                    httpContext.RequestAborted);
                if(!result.Succeeded)
                    return result.CreateValidationProblem();
                return TypedResults.Ok();
            }).WithName("ResetPassword");

            return endpoints;
        }
    }
}