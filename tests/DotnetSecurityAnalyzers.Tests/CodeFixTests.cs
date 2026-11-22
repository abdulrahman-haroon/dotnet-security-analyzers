using System.Threading.Tasks;
using DotnetSecurityAnalyzers.CodeFixes;
using Xunit;

namespace DotnetSecurityAnalyzers.Tests;

public class MissingAuthorizationCodeFixTests
{
    private static Task Fix(string source, string fixedSource, string key) =>
        VerifyFix<MissingAuthorizationAnalyzer, MissingAuthorizationCodeFix>.FixAsync(source, fixedSource, key);

    private const string Controller = """
        using Microsoft.AspNetCore.Mvc;

        public class OrdersController : ControllerBase
        {
            // Lists orders.
            public IActionResult {|DSA001:List|}() => Ok();
        }
        """;

    [Fact]
    public Task Adds_Authorize_to_the_action_and_the_using() => Fix(Controller, """
        using Microsoft.AspNetCore.Authorization;
        using Microsoft.AspNetCore.Mvc;

        public class OrdersController : ControllerBase
        {
            // Lists orders.
            [Authorize]
            public IActionResult List() => Ok();
        }
        """, "DSA001.AuthorizeAction");

    [Fact]
    public Task Adds_Authorize_to_the_controller() => Fix(Controller, """
        using Microsoft.AspNetCore.Authorization;
        using Microsoft.AspNetCore.Mvc;

        [Authorize]
        public class OrdersController : ControllerBase
        {
            // Lists orders.
            public IActionResult List() => Ok();
        }
        """, "DSA001.AuthorizeController");

    [Fact]
    public Task Adds_AllowAnonymous_without_duplicating_an_existing_using() => Fix("""
        using Microsoft.AspNetCore.Authorization;
        using Microsoft.AspNetCore.Mvc;

        public class HealthController : ControllerBase
        {
            [HttpGet]
            public IActionResult {|DSA001:Ping|}() => Ok();
        }
        """, """
        using Microsoft.AspNetCore.Authorization;
        using Microsoft.AspNetCore.Mvc;

        public class HealthController : ControllerBase
        {
            [AllowAnonymous]
            [HttpGet]
            public IActionResult Ping() => Ok();
        }
        """, "DSA001.AllowAnonymousAction");

    private const string Endpoint = """
        using Microsoft.AspNetCore.Builder;

        public static class Endpoints
        {
            public static void Map(WebApplication app)
            {
                app.{|DSA001:MapGet|}("/balance", () => 100);
            }
        }
        """;

    [Fact]
    public Task Appends_RequireAuthorization_to_a_minimal_api_endpoint() => Fix(Endpoint, """
        using Microsoft.AspNetCore.Builder;

        public static class Endpoints
        {
            public static void Map(WebApplication app)
            {
                app.MapGet("/balance", () => 100).RequireAuthorization();
            }
        }
        """, "DSA001.RequireAuthorization");

    [Fact]
    public Task Appends_AllowAnonymous_to_a_minimal_api_endpoint() => Fix(Endpoint, """
        using Microsoft.AspNetCore.Builder;

        public static class Endpoints
        {
            public static void Map(WebApplication app)
            {
                app.MapGet("/balance", () => 100).AllowAnonymous();
            }
        }
        """, "DSA001.AllowAnonymousEndpoint");
}

public class CorsAnyOriginWithCredentialsCodeFixTests
{
    [Fact]
    public Task Replaces_any_origin_with_an_explicit_list() =>
        VerifyFix<CorsAnyOriginWithCredentialsAnalyzer, CorsAnyOriginWithCredentialsCodeFix>.FixAsync("""
        using Microsoft.Extensions.DependencyInjection;

        public static class Setup
        {
            public static void Configure(IServiceCollection services) =>
                services.AddCors(o => o.AddPolicy("spa", p => {|DSA002:p.SetIsOriginAllowed(_ => true)|}.AllowCredentials()));
        }
        """, """
        using Microsoft.Extensions.DependencyInjection;

        public static class Setup
        {
            public static void Configure(IServiceCollection services) =>
                services.AddCors(o => o.AddPolicy("spa", p => p.WithOrigins("https://example.com").AllowCredentials()));
        }
        """, "DSA002.WithOrigins");
}

public class UnguardedDeveloperExceptionPageCodeFixTests
{
    private static Task Fix(string source, string fixedSource, string key) =>
        VerifyFix<UnguardedDeveloperExceptionPageAnalyzer, UnguardedDeveloperExceptionPageCodeFix>.FixAsync(source, fixedSource, key);

    private const string App = """
        using Microsoft.AspNetCore.Builder;

        public static class Pipeline
        {
            public static void Configure(WebApplication app)
            {
                {|DSA004:app.UseDeveloperExceptionPage()|};
                app.UseRouting();
            }
        }
        """;

    [Fact]
    public Task Wraps_the_call_in_an_IsDevelopment_check_and_adds_the_using() => Fix(App, """
        using Microsoft.AspNetCore.Builder;
        using Microsoft.Extensions.Hosting;

        public static class Pipeline
        {
            public static void Configure(WebApplication app)
            {
                if (app.Environment.IsDevelopment())
                {
                    app.UseDeveloperExceptionPage();
                }
                app.UseRouting();
            }
        }
        """, "DSA004.Wrap");

    [Fact]
    public Task Keeps_Windows_line_endings_in_CRLF_files() => Fix(App.Replace("\n", "\r\n"), """
        using Microsoft.AspNetCore.Builder;
        using Microsoft.Extensions.Hosting;

        public static class Pipeline
        {
            public static void Configure(WebApplication app)
            {
                if (app.Environment.IsDevelopment())
                {
                    app.UseDeveloperExceptionPage();
                }
                app.UseRouting();
            }
        }
        """.Replace("\n", "\r\n"), "DSA004.Wrap");

    [Fact]
    public Task Removes_the_call_on_WebApplication() => Fix(App, """
        using Microsoft.AspNetCore.Builder;

        public static class Pipeline
        {
            public static void Configure(WebApplication app)
            {
                app.UseRouting();
            }
        }
        """, "DSA004.Remove");

    [Fact]
    public Task Wraps_an_assignment_using_builder_Environment() => Fix("""
        using Microsoft.AspNetCore.Builder;
        using Microsoft.IdentityModel.Logging;

        public static class Setup
        {
            public static void Configure(WebApplicationBuilder builder)
            {
                {|DSA004:IdentityModelEventSource.ShowPII = true|};
            }
        }
        """, """
        using Microsoft.AspNetCore.Builder;
        using Microsoft.Extensions.Hosting;
        using Microsoft.IdentityModel.Logging;

        public static class Setup
        {
            public static void Configure(WebApplicationBuilder builder)
            {
                if (builder.Environment.IsDevelopment())
                {
                    IdentityModelEventSource.ShowPII = true;
                }
            }
        }
        """, "DSA004.Wrap");

    [Fact]
    public Task Remove_is_only_offered_for_the_exception_page() => Fix("""
        using Microsoft.AspNetCore.Builder;

        public static class Pipeline
        {
            public static void Configure(WebApplication app)
            {
                {|DSA004:app.UseMigrationsEndPoint()|};
            }
        }
        """, """
        using Microsoft.AspNetCore.Builder;

        public static class Pipeline
        {
            public static void Configure(WebApplication app)
            {
                {|DSA004:app.UseMigrationsEndPoint()|};
            }
        }
        """, "DSA004.Remove");

    [Fact]
    public Task Uses_the_environment_parameter_in_Startup_style_code() => Fix("""
        using Microsoft.AspNetCore.Builder;
        using Microsoft.AspNetCore.Hosting;
        using Microsoft.Extensions.Hosting;

        public class Startup
        {
            public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
            {
                {|DSA004:app.UseDeveloperExceptionPage()|};
            }
        }
        """, """
        using Microsoft.AspNetCore.Builder;
        using Microsoft.AspNetCore.Hosting;
        using Microsoft.Extensions.Hosting;

        public class Startup
        {
            public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
            {
                if (env.IsDevelopment())
                {
                    app.UseDeveloperExceptionPage();
                }
            }
        }
        """, "DSA004.Wrap");
}

public class InsecureCookieBuilderCodeFixTests
{
    private static Task Fix(string source, string fixedSource, string key) =>
        VerifyFix<InsecureCookieBuilderAnalyzer, InsecureCookieBuilderCodeFix>.FixAsync(source, fixedSource, key);

    [Fact]
    public Task Sets_HttpOnly_true() => Fix("""
        using Microsoft.Extensions.DependencyInjection;

        public static class Setup
        {
            public static void Configure(IServiceCollection services) =>
                services.AddSession(o => {|DSA005:o.Cookie.HttpOnly = false|});
        }
        """, """
        using Microsoft.Extensions.DependencyInjection;

        public static class Setup
        {
            public static void Configure(IServiceCollection services) =>
                services.AddSession(o => o.Cookie.HttpOnly = true);
        }
        """, "DSA005.HttpOnly");

    [Fact]
    public Task Sets_SecurePolicy_Always() => Fix("""
        using Microsoft.AspNetCore.Http;
        using Microsoft.Extensions.DependencyInjection;

        public static class Setup
        {
            public static void Configure(IServiceCollection services) =>
                services.AddAntiforgery(o => {|DSA005:o.Cookie.SecurePolicy = CookieSecurePolicy.None|});
        }
        """, """
        using Microsoft.AspNetCore.Http;
        using Microsoft.Extensions.DependencyInjection;

        public static class Setup
        {
            public static void Configure(IServiceCollection services) =>
                services.AddAntiforgery(o => o.Cookie.SecurePolicy = CookieSecurePolicy.Always);
        }
        """, "DSA005.SecurePolicy");
}
