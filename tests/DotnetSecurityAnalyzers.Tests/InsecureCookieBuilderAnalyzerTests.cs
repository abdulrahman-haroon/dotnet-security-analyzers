using System.Threading.Tasks;
using Xunit;
using VerifyCS = DotnetSecurityAnalyzers.Tests.Verify<DotnetSecurityAnalyzers.InsecureCookieBuilderAnalyzer>;

namespace DotnetSecurityAnalyzers.Tests;

public class InsecureCookieBuilderAnalyzerTests
{
    private static string InServices(string body) => """
        using Microsoft.AspNetCore.Builder;
        using Microsoft.AspNetCore.Http;
        using Microsoft.Extensions.DependencyInjection;

        public static class Setup
        {
            public static void Configure(IServiceCollection services)
            {
        """ + body + """

            }
        }
        """;

    [Fact]
    public Task Flags_session_and_antiforgery_cookies() => VerifyCS.AnalyzerAsync(InServices("""
                services.AddSession(o => {|DSA005:o.Cookie.HttpOnly = false|});
                services.AddAntiforgery(o => {|DSA005:o.Cookie.SecurePolicy = CookieSecurePolicy.None|});
        """));

    [Fact]
    public Task Flags_object_initializer() => VerifyCS.AnalyzerAsync(InServices("""
                var cookie = new CookieBuilder { Name = "auth", {|DSA005:HttpOnly = false|}, {|DSA005:SecurePolicy = CookieSecurePolicy.None|} };
        """));

    [Fact]
    public Task Safe_settings_are_fine() => VerifyCS.AnalyzerAsync(InServices("""
                services.AddSession(o =>
                {
                    o.Cookie.HttpOnly = true;
                    o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                    o.Cookie.SameSite = SameSiteMode.Strict;
                });
        """));

    [Fact]
    public Task Plain_response_cookies_are_left_to_CA5382() => VerifyCS.AnalyzerAsync("""
        using Microsoft.AspNetCore.Http;

        public static class Prefs
        {
            // A theme cookie that JavaScript reads on purpose is not a session cookie.
            public static void Set(HttpResponse response) =>
                response.Cookies.Append("theme", "dark", new CookieOptions { HttpOnly = false });
        }
        """);
}
