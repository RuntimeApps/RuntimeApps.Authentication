using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Shared.Extensions {
    /// <summary>Maps internal results to safe, stable HTTP error contracts.</summary>
    public static class PublicErrorFactory {
        public static IResult CreateExternalAuthenticationFailure() =>
            TypedResults.Problem(statusCode: StatusCodes.Status401Unauthorized,
                title: "Authentication failed", detail: "External authentication could not be completed.",
                extensions: new Dictionary<string, object> { ["code"] = "external_authentication_failed" });

        /// <summary>One response for every failed second-factor attempt, so the reason is never revealed.</summary>
        public static IResult CreateTwoFactorLoginFailure() =>
            TypedResults.Problem(statusCode: StatusCodes.Status401Unauthorized,
                title: "Authentication failed", detail: "The code is incorrect or the sign-in attempt has expired.",
                extensions: new Dictionary<string, object> { ["code"] = "authentication_failed" });

        public static IResult CreatePublicError(this IdentityResult result) =>
            new Result(ResultCode.BadRequest, result?.Errors ?? Enumerable.Empty<IdentityError>()).CreatePublicError();

        public static IResult CreatePublicError(this Result result) {
            var status = result.Code switch {
                ResultCode.BadRequest => StatusCodes.Status400BadRequest,
                ResultCode.Forbidden => StatusCodes.Status403Forbidden,
                ResultCode.Conflict => StatusCodes.Status409Conflict,
                ResultCode.Locked => StatusCodes.Status423Locked,
                _ => StatusCodes.Status400BadRequest
            };

            if(status == StatusCodes.Status400BadRequest) {
                var errors = new Dictionary<string, string[]>();
                foreach(var error in result.Errors ?? Enumerable.Empty<IdentityError>()) {
                    var key = SafeCode(error.Code);
                    var message = SafeIdentityMessage(error.Code);
                    if(!errors.TryGetValue(key, out var messages)) messages = Array.Empty<string>();
                    errors[key] = messages.Append(message).Distinct().ToArray();
                }
                if(errors.Count == 0) errors["request"] = new[] { "The request is invalid." };
                return TypedResults.ValidationProblem(errors);
            }

            var (title, code, detail) = status switch {
                StatusCodes.Status403Forbidden => ("Forbidden", "forbidden", "You are not allowed to perform this operation."),
                StatusCodes.Status409Conflict => ("Conflict", "conflict", "The operation conflicts with the current resource state."),
                StatusCodes.Status423Locked => ("Locked", "locked", "The resource is temporarily unavailable."),
                _ => ("Bad Request", "bad_request", "The request could not be completed.")
            };
            return TypedResults.Problem(statusCode: status, title: title, detail: detail, extensions: new Dictionary<string, object> { ["code"] = code });
        }

        private static string SafeCode(string code) => code switch {
            "PasswordTooShort" or "PasswordRequiresNonAlphanumeric" or "PasswordRequiresDigit" or "PasswordRequiresLower" or "PasswordRequiresUpper" or "PasswordRequiresUniqueChars" => "password",
            "InvalidEmail" => "email",
            "DuplicateEmail" or "DuplicateUserName" => "account",
            "InvalidUserName" => "userName",
            _ => "request"
        };

        private static string SafeIdentityMessage(string code) => code switch {
            "PasswordTooShort" => "The password does not meet the minimum length requirement.",
            "PasswordRequiresNonAlphanumeric" or "PasswordRequiresDigit" or "PasswordRequiresLower" or "PasswordRequiresUpper" or "PasswordRequiresUniqueChars" => "The password does not meet the configured password policy.",
            "InvalidEmail" => "Enter a valid email address.",
            "InvalidUserName" => "The user name is invalid.",
            "DuplicateEmail" or "DuplicateUserName" => "The account could not be created.",
            _ => "The request could not be completed."
        };
    }
}
