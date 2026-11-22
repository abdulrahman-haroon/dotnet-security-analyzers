using System.Threading.Tasks;
using Xunit;
using VerifyCS = DotnetSecurityAnalyzers.Tests.Verify<DotnetSecurityAnalyzers.MissingAuthorizationAnalyzer>;

namespace DotnetSecurityAnalyzers.Tests;

public class MissingAuthorizationAnalyzerTests
{
    private const string Usings = """
        using System;
        using Microsoft.AspNetCore.Authorization;
        using Microsoft.AspNetCore.Mvc;
        """;

    [Fact]
    public Task Flags_every_action_on_an_unprotected_controller() => VerifyCS.AnalyzerAsync(Usings + """

        [ApiController]
        public class OrdersController : ControllerBase
        {
            [HttpGet]
            public IActionResult {|DSA001:List|}() => Ok();

            [HttpDelete("{id}")]
            public IActionResult {|DSA001:Delete|}(int id) => NoContent();
        }
        """);

    [Fact]
    public Task Flags_plain_class_named_Controller() => VerifyCS.AnalyzerAsync(Usings + """

        public class ReportsController
        {
            public string {|DSA001:Export|}() => "csv";
        }
        """);

    [Fact]
    public Task Flags_only_the_action_without_attribute() => VerifyCS.AnalyzerAsync(Usings + """

        public class AccountController : Controller
        {
            [Authorize]
            public IActionResult Profile() => View();

            public IActionResult {|DSA001:Settings|}() => View();
        }
        """);

    [Fact]
    public Task Authorize_on_controller_is_enough() => VerifyCS.AnalyzerAsync(Usings + """

        [Authorize(Policy = "Admin")]
        public class AdminController : ControllerBase
        {
            public IActionResult Index() => Ok();
        }
        """);

    [Fact]
    public Task AllowAnonymous_marks_endpoint_as_intentionally_public() => VerifyCS.AnalyzerAsync(Usings + """

        public class HealthController : ControllerBase
        {
            [AllowAnonymous]
            public IActionResult Ping() => Ok();
        }
        """);

    [Fact]
    public Task Authorize_inherited_from_base_controller_is_enough() => VerifyCS.AnalyzerAsync(Usings + """

        [Authorize]
        public abstract class SecureControllerBase : ControllerBase { }

        public class InvoicesController : SecureControllerBase
        {
            public IActionResult Get() => Ok();
        }
        """);

    [Fact]
    public Task Custom_attribute_deriving_from_Authorize_is_enough() => VerifyCS.AnalyzerAsync(Usings + """

        public sealed class AdminOnlyAttribute : AuthorizeAttribute
        {
            public AdminOnlyAttribute() => Roles = "Admin";
        }

        [AdminOnly]
        public class UsersController : ControllerBase
        {
            public IActionResult Get() => Ok();
        }
        """);

    [Fact]
    public Task Ignores_methods_that_are_not_actions() => VerifyCS.AnalyzerAsync(Usings + """

        public class PaymentsController : ControllerBase, IDisposable
        {
            [NonAction]
            public void Helper() { }

            public static void StaticHelper() { }

            private void PrivateHelper() { }

            public override string ToString() => "x";

            public void Dispose() { }
        }
        """);

    // ---------- Global protection (controllers) ----------

    private const string OpenController = """

        public class OrdersController : ControllerBase
        {
            public IActionResult List() => Ok();
        }
        """;

    [Theory]
    [InlineData("services.AddAuthorization(o => o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());")]
    [InlineData("services.AddAuthorizationBuilder().SetFallbackPolicy(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());")]
    [InlineData("services.AddControllers(o => o.Filters.Add(new AuthorizeFilter()));")]
    public Task Global_protection_silences_controller_warnings(string setup) => VerifyCS.AnalyzerAsync(Usings + $$"""

        using Microsoft.AspNetCore.Mvc.Authorization;
        using Microsoft.Extensions.DependencyInjection;

        public static class Startup
        {
            public static void Configure(IServiceCollection services) { {{setup}} }
        }
        """ + OpenController);

    [Fact]
    public Task MapControllers_RequireAuthorization_silences_controller_warnings() => VerifyCS.AnalyzerAsync(Usings + """

        using Microsoft.AspNetCore.Builder;

        public static class Startup
        {
            public static void Configure(WebApplication app) => app.MapControllers().RequireAuthorization();
        }
        """ + OpenController);

    [Fact]
    public Task Null_fallback_policy_does_not_count() => VerifyCS.AnalyzerAsync(Usings + """

        using Microsoft.Extensions.DependencyInjection;

        public static class Startup
        {
            public static void Configure(IServiceCollection services) => services.AddAuthorization(o => o.FallbackPolicy = null);
        }

        public class OrdersController : ControllerBase
        {
            public IActionResult {|DSA001:List|}() => Ok();
        }
        """);

    [Fact]
    public Task Ignores_classes_that_are_not_controllers() => VerifyCS.AnalyzerAsync(Usings + """

        public class OrderService
        {
            public void Save() { }
        }

        [NonController]
        public class LegacyController
        {
            public void Run() { }
        }

        internal class InternalController : ControllerBase
        {
            public IActionResult Get() => Ok();
        }
        """);
}
