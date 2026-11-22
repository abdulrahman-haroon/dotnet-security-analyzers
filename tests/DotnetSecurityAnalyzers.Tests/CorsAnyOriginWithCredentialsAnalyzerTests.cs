using System.Threading.Tasks;
using Xunit;
using VerifyCS = DotnetSecurityAnalyzers.Tests.Verify<DotnetSecurityAnalyzers.CorsAnyOriginWithCredentialsAnalyzer>;

namespace DotnetSecurityAnalyzers.Tests;

public class CorsAnyOriginWithCredentialsAnalyzerTests
{
    private static string InStartup(string body) => """
        using Microsoft.AspNetCore.Cors.Infrastructure;
        using Microsoft.Extensions.DependencyInjection;

        public static class Startup
        {
            public static void Configure(IServiceCollection services)
            {
        """ + body + """

            }
        }
        """;

    [Fact]
    public Task Flags_fluent_any_origin_with_credentials() => VerifyCS.AnalyzerAsync(InStartup("""
                services.AddCors(o => o.AddPolicy("spa", p => {|DSA002:p.SetIsOriginAllowed(_ => true)|}.AllowCredentials()));
        """));

    [Fact]
    public Task Flags_block_lambda_and_separate_statements() => VerifyCS.AnalyzerAsync(InStartup("""
                services.AddCors(o => o.AddPolicy("spa", p =>
                {
                    p.AllowCredentials();
                    {|DSA002:p.SetIsOriginAllowed(origin => { return true; })|};
                }));
        """));

    [Fact]
    public Task Any_origin_without_credentials_is_fine() => VerifyCS.AnalyzerAsync(InStartup("""
                services.AddCors(o => o.AddPolicy("public", p => p.SetIsOriginAllowed(_ => true).AllowAnyHeader()));
        """));

    [Fact]
    public Task Real_origin_check_with_credentials_is_fine() => VerifyCS.AnalyzerAsync(InStartup("""
                services.AddCors(o => o.AddPolicy("spa", p => p
                    .SetIsOriginAllowed(origin => origin == "https://app.example.com")
                    .AllowCredentials()));
        """));

    [Fact]
    public Task Explicit_origins_with_credentials_are_fine() => VerifyCS.AnalyzerAsync(InStartup("""
                services.AddCors(o => o.AddPolicy("spa", p => p.WithOrigins("https://app.example.com").AllowCredentials()));
        """));

    [Fact]
    public Task Credentials_in_a_different_policy_are_not_mixed_up() => VerifyCS.AnalyzerAsync(InStartup("""
                services.AddCors(o =>
                {
                    o.AddPolicy("public", p => p.SetIsOriginAllowed(_ => true));
                    o.AddPolicy("spa", p => p.WithOrigins("https://app.example.com").AllowCredentials());
                });
        """));
}
