using System.Text;
using System.Text.Json.Nodes;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using RuntimeApps.Authentication.Shared.Extensions;
using RuntimeApps.Authentication.Shared.Models;

namespace RuntimeApps.Authentication.Test;

public class PublicErrorFactoryTest {
    [Fact]
    public async Task Identity_errors_are_sanitized_as_validation_problems() {
        var result = new Result(ResultCode.BadRequest,
            Result.CreateErrors("PasswordTooShort", "Secret policy detail"));
        var context = new DefaultHttpContext();
        context.RequestServices = new ServiceCollection().AddLogging().AddProblemDetails().BuildServiceProvider();
        await using var body = new MemoryStream();
        context.Response.Body = body;

        await result.CreatePublicError().ExecuteAsync(context);

        context.Response.StatusCode.Should().Be(StatusCodes.Status400BadRequest);
        body.Position = 0;
        var response = await new StreamReader(body, Encoding.UTF8).ReadToEndAsync();
        response.Should().Contain("password").And.Contain("minimum length");
        response.Should().NotContain("Secret policy detail");
    }

    [Fact]
    public async Task Forbidden_results_use_problem_details_and_403() {
        var result = new Result(ResultCode.Forbidden,
            Result.CreateErrors("Internal", "Sensitive internal detail"));
        var context = new DefaultHttpContext();
        context.RequestServices = new ServiceCollection().AddLogging().AddProblemDetails().BuildServiceProvider();
        await using var body = new MemoryStream();
        context.Response.Body = body;

        await result.CreatePublicError().ExecuteAsync(context);

        context.Response.StatusCode.Should().Be(StatusCodes.Status403Forbidden);
        body.Position = 0;
        var response = await new StreamReader(body, Encoding.UTF8).ReadToEndAsync();
        response.Should().Contain("forbidden");
        response.Should().NotContain("Sensitive internal detail");
    }

    [Fact]
    public async Task External_authentication_failures_are_generic_401_problem_details() {
        static async Task<(int Status, string Body)> Execute() {
            var context = new DefaultHttpContext();
            context.RequestServices = new ServiceCollection().AddLogging().AddProblemDetails().BuildServiceProvider();
            await using var body = new MemoryStream();
            context.Response.Body = body;
            await PublicErrorFactory.CreateExternalAuthenticationFailure().ExecuteAsync(context);
            body.Position = 0;
            return (context.Response.StatusCode, await new StreamReader(body).ReadToEndAsync());
        }

        var (status, body) = await Execute();
        status.Should().Be(StatusCodes.Status401Unauthorized);
        var problem = JsonNode.Parse(body)!.AsObject();
        problem["title"]!.GetValue<string>().Should().Be("Authentication failed");
        problem["detail"]!.GetValue<string>().Should().Be("External authentication could not be completed.");
        problem["status"]!.GetValue<int>().Should().Be(StatusCodes.Status401Unauthorized);
        problem["code"]!.GetValue<string>().Should().Be("external_authentication_failed");
        body.Should().NotContain("Identity").And.NotContain("provider-specific").And.NotContain("account exists");
    }
}
