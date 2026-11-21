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
    public async Task EquivalentExternalAuthenticationFailures_HaveIdenticalPublicResponses() {
        static Result Failure() => new(ResultCode.BadRequest,
            Result.CreateErrors("ExternalAuthenticationFailed", "External authentication could not be completed."));
        static async Task<(int Status, string Body)> Execute(Result result) {
            var context = new DefaultHttpContext();
            context.RequestServices = new ServiceCollection().AddLogging().AddProblemDetails().BuildServiceProvider();
            await using var body = new MemoryStream();
            context.Response.Body = body;
            await result.CreatePublicError().ExecuteAsync(context);
            body.Position = 0;
            return (context.Response.StatusCode, await new StreamReader(body).ReadToEndAsync());
        }

        var untrustedExistingAccount = await Execute(Failure());
        var untrustedNewEmail = await Execute(Failure());

        Assert.Equal(untrustedExistingAccount.Status, untrustedNewEmail.Status);
        static string WithoutTraceId(string body) {
            var problem = JsonNode.Parse(body)!.AsObject();
            problem.Remove("traceId");
            return problem.ToJsonString();
        }
        Assert.Equal(WithoutTraceId(untrustedExistingAccount.Body), WithoutTraceId(untrustedNewEmail.Body));
    }
}
