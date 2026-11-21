using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using RuntimeApps.Authentication.Shared.Models;
namespace RuntimeApps.Authentication.Shared.Extensions {
    public static class ResultExtensions {
        public static ValidationProblem CreateValidationProblem(this Result result) {
            var errorDictionary = new Dictionary<string, string[]>(1);

            foreach(var error in result.Errors ?? Enumerable.Empty<Microsoft.AspNetCore.Identity.IdentityError>()) {
                var key = error.Code switch {
                    "PasswordTooShort" or "PasswordRequiresNonAlphanumeric" or "PasswordRequiresDigit" or "PasswordRequiresLower" or "PasswordRequiresUpper" or "PasswordRequiresUniqueChars" => "password",
                    "InvalidEmail" => "email",
                    "InvalidUserName" => "userName",
                    _ => "request"
                };
                var message = error.Code switch {
                    "PasswordTooShort" => "The password does not meet the minimum length requirement.",
                    "PasswordRequiresNonAlphanumeric" or "PasswordRequiresDigit" or "PasswordRequiresLower" or "PasswordRequiresUpper" or "PasswordRequiresUniqueChars" => "The password does not meet the configured password policy.",
                    "InvalidEmail" => "Enter a valid email address.",
                    "InvalidUserName" => "The user name is invalid.",
                    _ => "The request could not be completed."
                };
                if(!errorDictionary.TryGetValue(key, out var descriptions)) descriptions = Array.Empty<string>();
                errorDictionary[key] = descriptions.Append(message).Distinct().ToArray();
            }

            if(errorDictionary.Count == 0) errorDictionary["request"] = new[] { "The request is invalid." };

            return TypedResults.ValidationProblem(errorDictionary);
        }
    }
}
