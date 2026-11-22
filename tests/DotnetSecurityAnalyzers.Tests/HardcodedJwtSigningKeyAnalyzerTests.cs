using System.Threading.Tasks;
using Xunit;
using VerifyCS = DotnetSecurityAnalyzers.Tests.Verify<DotnetSecurityAnalyzers.HardcodedJwtSigningKeyAnalyzer>;

namespace DotnetSecurityAnalyzers.Tests;

// All key values below are obviously fake test strings.
public class HardcodedJwtSigningKeyAnalyzerTests
{
    private static string InClass(string members) => """
        using System;
        using System.Text;
        using Microsoft.IdentityModel.Tokens;

        public class Keys
        {
            private const string FakeKey = "FAKE-TEST-KEY-not-a-real-secret-000000000000";

        """ + members + """

        }
        """;

    [Fact]
    public Task Flags_string_literal() => VerifyCS.AnalyzerAsync(InClass("""
            public SecurityKey A() => {|DSA003:new SymmetricSecurityKey(Encoding.UTF8.GetBytes("FAKE-TEST-KEY-not-a-real-secret-111111111111"))|};
        """));

    [Fact]
    public Task Flags_constant() => VerifyCS.AnalyzerAsync(InClass("""
            public SecurityKey A() => {|DSA003:new SymmetricSecurityKey(Encoding.ASCII.GetBytes(FakeKey))|};
        """));

    [Fact]
    public Task Flags_base64_literal() => VerifyCS.AnalyzerAsync(InClass("""
            public SecurityKey A() => {|DSA003:new SymmetricSecurityKey(Convert.FromBase64String("RkFLRS1URVNULUtFWQ=="))|};
        """));

    [Fact]
    public Task Flags_byte_array_and_utf8_literals() => VerifyCS.AnalyzerAsync(InClass("""
            public SecurityKey A() => {|DSA003:new SymmetricSecurityKey(new byte[] { 1, 2, 3, 4 })|};
            public SecurityKey B() => {|DSA003:new SymmetricSecurityKey("FAKE-TEST-KEY"u8.ToArray())|};
        """));

    [Fact]
    public Task Flags_values_passed_through_variables_and_readonly_fields() => VerifyCS.AnalyzerAsync(InClass("""
            private static readonly string ReadonlyKey = "FAKE-TEST-KEY-not-a-real-secret-222222222222";

            public SecurityKey A()
            {
                var secret = "FAKE-TEST-KEY-not-a-real-secret-333333333333";
                var bytes = Encoding.UTF8.GetBytes(secret);
                return {|DSA003:new SymmetricSecurityKey(bytes)|};
            }

            public SecurityKey B() => {|DSA003:new SymmetricSecurityKey(Encoding.UTF8.GetBytes(ReadonlyKey))|};
        """));

    [Fact]
    public Task Variables_that_get_reassigned_are_not_followed() => VerifyCS.AnalyzerAsync(InClass("""
            private static string mutableKey = "FAKE-TEST-KEY-default";

            public SecurityKey A(string fromConfig, bool production)
            {
                var secret = "FAKE-TEST-KEY-dev-only";
                if (production)
                    secret = fromConfig;
                return new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            }

            public SecurityKey B() => new SymmetricSecurityKey(Encoding.UTF8.GetBytes(mutableKey));
        """));

    [Fact]
    public Task Key_from_configuration_is_fine() => VerifyCS.AnalyzerAsync(InClass("""
            public SecurityKey A(string keyFromSecretStore) => new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyFromSecretStore));
            public SecurityKey B(byte[] keyBytes) => new SymmetricSecurityKey(keyBytes);
        """));
}
