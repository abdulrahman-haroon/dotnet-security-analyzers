using System.Threading.Tasks;
using Microsoft.CodeAnalysis.CSharp.Testing;
using Microsoft.CodeAnalysis.Testing;
using Xunit;
using Credential = DotnetSecurityAnalyzers.Tests.Verify<DotnetSecurityAnalyzers.HardcodedCredentialAnalyzer>;
using Logged = DotnetSecurityAnalyzers.Tests.Verify<DotnetSecurityAnalyzers.SensitiveDataLoggedAnalyzer>;

namespace DotnetSecurityAnalyzers.Tests;

// All secret values below are obviously fake test strings.
public class SecretAnalyzerTests
{
    private static Task SettingsAsync(string fileName, string json)
    {
        var test = new CSharpAnalyzerTest<AppSettingsSecretAnalyzer, DefaultVerifier>
        {
            TestCode = "class C { }",
            ReferenceAssemblies = Credential.References,
        };
        test.TestState.AdditionalFiles.Add((fileName, json));
        return test.RunAsync();
    }

    [Fact]
    public Task Settings_flags_secrets() => SettingsAsync("appsettings.json", """
        {
          // comments and trailing commas are allowed
          "ConnectionStrings": { "Db": {|DSA006:"Server=x;User Id=a;Password=FAKE-pass"|}, },
          /* block comment */
          "Jwt": { "Key": {|DSA006:"FAKE-KEY-000000"|} },
          "Auth": { "ClientSecret": {|DSA006:"FAKE-\"quoted\""|} },
          "Stripe_Api_Key": {|DSA006:"FAKE-000000"|},
          "Smtp": [ { "Password": {|DSA006:"FAKE-000000"|} } ]
        }
        """);

    [Fact]
    public Task Settings_ignores_placeholders_and_non_secrets() => SettingsAsync("appsettings.Production.json", """
        {
          "ConnectionStrings": { "A": "Server=x;Password=<password>", "B": "Server=x;Integrated Security=true", "C": "Server=x;Pwd=${DB_PWD}" },
          "Jwt": { "Key": "", "Issuer": "https://example.test" },
          "Auth": { "ClientSecret": "CHANGE_ME", "ApiKey": "your-api-key" },
          "Cache": { "Key": "orders-by-id" },
          "Pages": { "ResetPassword": "/account/reset", "ForgotPassword": "Forgot it? Reset here" },
          "Identity": { "RequireSecret": "true", "SecretName": "db-login", "Secret": null }
        }
        """);

    [Theory]
    [InlineData("appsettings.Development.json")]
    [InlineData("other.json")]
    public Task Settings_skips_other_files(string name) => SettingsAsync(name, """{ "Password": "FAKE-000000" }""");

    [Theory]
    [InlineData("{ \"Password\": \"")]
    [InlineData("]]} / /* \"")]
    public Task Settings_survives_broken_json(string json) => SettingsAsync("appsettings.json", json);

    private static string CredentialCode(string body) => """
        using System.Net;
        using System.Threading.Tasks;
        using Microsoft.AspNetCore.Identity;
        using Microsoft.Extensions.Hosting;

        public class C
        {
            static void Open(string connectionString) { }
            static void Name(string password) { }

            public async Task M(UserManager<IdentityUser> users, IdentityUser user, string input, IHostEnvironment env)
            {
                await Task.Yield();
        """ + body + """

            }
        }
        """;

    [Fact]
    public Task Flags_hardcoded_credentials() => Credential.AnalyzerAsync(CredentialCode("""
                Open({|DSA007:"Server=x;Password=FAKE-pass"|});
                var cs = "Server=x;Pwd=FAKE-pass";
                Open({|DSA007:cs|});
                _ = new NetworkCredential("a", {|DSA007:"FAKE-pass"|});
                await users.CreateAsync(user, {|DSA007:"FAKE-pass"|});
                await users.AddPasswordAsync(user, {|DSA007:"FAKE-pass"|});
        """));

    [Fact]
    public Task Credentials_from_elsewhere_are_fine() => Credential.AnalyzerAsync(CredentialCode("""
                Open("Server=x;Integrated Security=true");
                Open("Server=x;Password={0}");
                Open(input);
                Name("FAKE-not-a-known-api");
                _ = new NetworkCredential("a", input);
                _ = new NetworkCredential("a", "");
                await users.CreateAsync(user, input);
                if (env.IsDevelopment())
                    await users.CreateAsync(user, "FAKE-pass");
        """));

    [Fact]
    public Task Development_flag_passed_as_bool_counts_as_a_guard() => Logged.AnalyzerAsync(LogCode("""
                var isDevelopment = userName == "dev";
                if (isDevelopment)
                    log.LogDebug("{P}", password);
                if (!isDevelopment)
                    log.LogDebug("{P}", {|DSA008:password|});
        """));

    private static string LogCode(string body) => """
        using Microsoft.Extensions.Logging;

        public class C
        {
            public string ClientSecret { get; set; } = "";

            static string Mask(string value) => "***";

            public void M(ILogger log, string password, string accessToken, string passwordHash, bool hasPassword, string userName)
            {
        """ + body + """

            }
        }
        """;

    [Fact]
    public Task Flags_logged_secrets() => Logged.AnalyzerAsync(LogCode("""
                log.LogInformation("{P}", {|DSA008:password|});
                log.LogError($"token {{|DSA008:accessToken|}}");
                log.LogWarning("secret " + {|DSA008:ClientSecret|});
                log.Log(LogLevel.Debug, "{U} {P}", userName, {|DSA008:password|} ?? "");
        """));

    [Fact]
    public Task Harmless_logging_is_fine() => Logged.AnalyzerAsync(LogCode("""
                log.LogInformation("{H} {B} {U}", passwordHash, hasPassword, userName);
                log.LogInformation("{M} {L}", Mask(password), password.Length);
                log.LogInformation("password reset requested");
        """));
}
