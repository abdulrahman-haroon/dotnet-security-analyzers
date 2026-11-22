using System.Collections.Immutable;
using System.IO;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis.CSharp.Testing;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Testing;

namespace DotnetSecurityAnalyzers.Tests;

/// <summary>
/// Compiles a test snippet against real .NET 8 + ASP.NET Core 8 reference assemblies and checks
/// that the analyzer reports exactly the diagnostics marked in the snippet as {|DSA00x:code|}.
/// </summary>
internal static class Verify<TAnalyzer>
    where TAnalyzer : DiagnosticAnalyzer, new()
{
    private static readonly ReferenceAssemblies Net8WithAspNetCore =
        new ReferenceAssemblies(
                "net8.0",
                new PackageIdentity("Microsoft.NETCore.App.Ref", "8.0.20"),
                Path.Combine("ref", "net8.0"))
            .AddPackages(ImmutableArray.Create(
                new PackageIdentity("Microsoft.AspNetCore.App.Ref", "8.0.20"),
                new PackageIdentity("Microsoft.IdentityModel.Tokens", "8.14.0")));

    public static Task AnalyzerAsync(string source) =>
        new CSharpAnalyzerTest<TAnalyzer, DefaultVerifier>
        {
            TestCode = source,
            ReferenceAssemblies = Net8WithAspNetCore,
        }.RunAsync();
}
