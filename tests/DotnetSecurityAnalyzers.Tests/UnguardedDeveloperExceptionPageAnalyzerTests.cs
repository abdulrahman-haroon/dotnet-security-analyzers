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

    // ---------- Other development-only diagnostics ----------

    private static string InBuilder(string body) => """
        using Microsoft.AspNetCore.Builder;
        using Microsoft.EntityFrameworkCore;
        using Microsoft.Extensions.DependencyInjection;
        using Microsoft.Extensions.Hosting;
        using Microsoft.IdentityModel.Logging;

        public class Db(DbContextOptions<Db> options) : DbContext(options);

        public static class Setup
        {
            public static void Configure(WebApplicationBuilder builder, WebApplication app, bool isDev)
            {
        #pragma warning disable CS0618 // UseDatabaseErrorPage is obsolete, but still used in older apps

        """ + body + """

            }
        }
        """;

    [Fact]
    public Task Flags_every_development_only_feature() => VerifyCS.AnalyzerAsync(InBuilder("""
                builder.Services.AddDbContext<Db>(o => {|DSA004:o.EnableSensitiveDataLogging()|});
                builder.Services.AddSignalR(o => {|DSA004:o.EnableDetailedErrors = true|});
                builder.Services.AddGrpc(o => {|DSA004:o.EnableDetailedErrors = true|});
                builder.Services.AddServerSideBlazor(o => {|DSA004:o.DetailedErrors = true|});
                {|DSA004:IdentityModelEventSource.ShowPII = true|};
                {|DSA004:IdentityModelEventSource.LogCompleteSecurityArtifact = true|};
                {|DSA004:app.UseMigrationsEndPoint()|};
                {|DSA004:app.UseDatabaseErrorPage()|};
        """));

    [Fact]
    public Task Switched_off_or_already_gated_values_are_fine() => VerifyCS.AnalyzerAsync(InBuilder("""
                builder.Services.AddDbContext<Db>(o => o.EnableSensitiveDataLogging(false));
                builder.Services.AddDbContext<Db>(o => o.EnableSensitiveDataLogging(isDev));
                builder.Services.AddSignalR(o => o.EnableDetailedErrors = isDev);
                builder.Services.AddServerSideBlazor(o => o.DetailedErrors = false);
                IdentityModelEventSource.ShowPII = builder.Environment.IsDevelopment();
        """));

    [Fact]
    public Task Development_checks_cover_the_new_features_too() => VerifyCS.AnalyzerAsync(InBuilder("""
                if (builder.Environment.IsDevelopment())
                {
                    builder.Services.AddDbContext<Db>(o => o.EnableSensitiveDataLogging());
                    builder.Services.AddSignalR(o => o.EnableDetailedErrors = true);
                    IdentityModelEventSource.ShowPII = true;
                    app.UseMigrationsEndPoint();
                }
        """));

    [Fact]
    public Task Startup_ConfigureDevelopmentServices_only_runs_in_development() => VerifyCS.AnalyzerAsync("""
        using Microsoft.Extensions.DependencyInjection;

        public class Startup
        {
            public void ConfigureDevelopmentServices(IServiceCollection services) =>
                services.AddSignalR(o => o.EnableDetailedErrors = true);
        }
        """);
}
