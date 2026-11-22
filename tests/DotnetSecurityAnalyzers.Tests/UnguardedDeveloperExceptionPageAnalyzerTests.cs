using System.Threading.Tasks;
using Xunit;
using VerifyCS = DotnetSecurityAnalyzers.Tests.Verify<DotnetSecurityAnalyzers.UnguardedDeveloperExceptionPageAnalyzer>;

namespace DotnetSecurityAnalyzers.Tests;

public class UnguardedDeveloperExceptionPageAnalyzerTests
{
    private static string InApp(string body) => """
        using Microsoft.AspNetCore.Builder;
        using Microsoft.AspNetCore.Hosting;
        using Microsoft.Extensions.Hosting;

        public static class Pipeline
        {
            public static void Configure(WebApplication app, IWebHostEnvironment env)
            {
        """ + body + """

            }
        }
        """;

    [Fact]
    public Task Flags_unguarded_call() => VerifyCS.AnalyzerAsync(InApp("""
                {|DSA004:app.UseDeveloperExceptionPage()|};
        """));

    [Fact]
    public Task Flags_call_on_the_wrong_side_of_the_check() => VerifyCS.AnalyzerAsync(InApp("""
                if (app.Environment.IsDevelopment())
                    app.UseHsts();
                else
                    {|DSA004:app.UseDeveloperExceptionPage()|};

                if (!env.IsDevelopment())
                    {|DSA004:app.UseDeveloperExceptionPage()|};
        """));

    [Fact]
    public Task Development_checks_are_recognised() => VerifyCS.AnalyzerAsync(InApp("""
                if (app.Environment.IsDevelopment())
                {
                    app.UseDeveloperExceptionPage();
                }

                if (env.IsEnvironment("Development") && args())
                    app.UseDeveloperExceptionPage();

                if (!env.IsDevelopment())
                    app.UseExceptionHandler("/error");
                else
                    app.UseDeveloperExceptionPage();

                _ = env.IsDevelopment() ? app.UseDeveloperExceptionPage() : app.UseExceptionHandler("/error");

                static bool args() => true;
        """));

    [Fact]
    public Task Startup_ConfigureDevelopment_only_runs_in_development() => VerifyCS.AnalyzerAsync("""
        using Microsoft.AspNetCore.Builder;

        public class Startup
        {
            public void ConfigureDevelopment(IApplicationBuilder app) => app.UseDeveloperExceptionPage();
        }
        """);
}
