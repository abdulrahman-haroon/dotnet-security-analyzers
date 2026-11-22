using System.Threading.Tasks;
using Xunit;
using VerifyCS = DotnetSecurityAnalyzers.Tests.Verify<DotnetSecurityAnalyzers.MissingAuthorizationAnalyzer>;

namespace DotnetSecurityAnalyzers.Tests;

public class MissingAuthorizationMinimalApiTests
{
    private static string InApp(string body, string extra = "") => """
        using Microsoft.AspNetCore.Authorization;
        using Microsoft.AspNetCore.Builder;
        using Microsoft.AspNetCore.Http;
        using Microsoft.AspNetCore.Routing;
        using Microsoft.Extensions.DependencyInjection;

        public static class Endpoints
        {
            public static void Configure(WebApplication app)
            {
        """ + body + """

            }

            [AllowAnonymous]
            public static string Public() => "ok";
        """ + extra + """

        }
        """;

    [Fact]
    public Task Flags_endpoint_mapped_on_the_app() => VerifyCS.AnalyzerAsync(InApp("""
                app.{|DSA001:MapGet|}("/balance", () => 100);
                app.{|DSA001:MapPost|}("/transfer", (int amount) => amount).WithName("Transfer");
        """));

    [Fact]
    public Task RequireAuthorization_or_AllowAnonymous_in_the_chain_is_enough() => VerifyCS.AnalyzerAsync(InApp("""
                app.MapGet("/balance", () => 100).RequireAuthorization();
                app.MapGet("/admin", () => 1).WithName("Admin").RequireAuthorization("AdminPolicy");
                app.MapGet("/health", () => "ok").AllowAnonymous();
        """));

    [Fact]
    public Task Attributes_on_the_handler_are_enough() => VerifyCS.AnalyzerAsync(InApp("""
                app.MapGet("/balance", [Authorize] () => 100);
                app.MapGet("/public", Public);
        """));

    [Fact]
    public Task Protected_group_is_enough() => VerifyCS.AnalyzerAsync(InApp("""
                var api = app.MapGroup("/api").RequireAuthorization();
                api.MapGet("/orders", () => 1);

                var users = api.MapGroup("/users");
                users.MapDelete("/{id}", (int id) => id);

                var admin = app.MapGroup("/admin");
                admin.RequireAuthorization("Admin");
                admin.MapPost("/reset", () => 1);

                app.MapGroup("/v2").RequireAuthorization().MapGet("/orders", () => 1);
        """));

    [Fact]
    public Task Flags_endpoints_on_an_unprotected_group() => VerifyCS.AnalyzerAsync(InApp("""
                var api = app.MapGroup("/api").WithTags("Orders");
                api.{|DSA001:MapGet|}("/orders", () => 1);

                app.MapGroup("/v2").{|DSA001:MapPut|}("/orders", () => 1);
        """));

    [Fact]
    public Task Does_not_guess_when_the_builder_comes_from_elsewhere() => VerifyCS.AnalyzerAsync(InApp(
        """
                var endpoint = app.MapGet("/stored", () => 1);
                endpoint.RequireAuthorization();
        """,
        """

            // The caller may pass an already-protected group.
            public static void MapOrders(this IEndpointRouteBuilder routes) => routes.MapGet("/orders", () => 1);
        """));

    [Fact]
    public Task Fallback_policy_silences_minimal_api_warnings() => VerifyCS.AnalyzerAsync(InApp(
        """
                app.MapGet("/balance", () => 100);
        """,
        """

            public static void Services(IServiceCollection services) =>
                services.AddAuthorization(o => o.FallbackPolicy = o.DefaultPolicy);
        """));

    [Fact]
    public Task Mvc_only_protection_does_not_cover_minimal_apis() => VerifyCS.AnalyzerAsync(InApp(
        """
                app.MapControllers().RequireAuthorization();
                app.{|DSA001:MapGet|}("/balance", () => 100);
        """));
}
