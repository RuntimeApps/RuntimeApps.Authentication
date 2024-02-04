using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Extensions {
    public static class ResultExtensions {
        public static ValidationProblem CreateValidationProblem(this Result result) {
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
