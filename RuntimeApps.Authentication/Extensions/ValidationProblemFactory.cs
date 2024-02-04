using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;

namespace RuntimeApps.Authentication.Extensions {
    public static class ValidationProblemFactory {

        internal static ValidationProblem CreateValidationProblem(string errorCode, string errorDescription) =>
        TypedResults.ValidationProblem(new Dictionary<string, string[]> {
            { errorCode, new string[] { errorDescription } }
        });

    }
}
