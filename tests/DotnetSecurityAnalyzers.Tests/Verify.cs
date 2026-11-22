using System.Collections.Immutable;
using System.IO;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
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
    public static ReferenceAssemblies References => Net8WithAspNetCore;

    private static readonly ReferenceAssemblies Net8WithAspNetCore =
        new ReferenceAssemblies(
                "net8.0",
                new PackageIdentity("Microsoft.NETCore.App.Ref", "8.0.20"),
                Path.Combine("ref", "net8.0"))
            .AddPackages(ImmutableArray.Create(
                new PackageIdentity("Microsoft.AspNetCore.App.Ref", "8.0.20"),
                new PackageIdentity("Microsoft.IdentityModel.Tokens", "8.14.0"),
                new PackageIdentity("Microsoft.EntityFrameworkCore", "8.0.8"),
                new PackageIdentity("Microsoft.AspNetCore.Diagnostics.EntityFrameworkCore", "8.0.8"),
                new PackageIdentity("Grpc.AspNetCore.Server", "2.67.0")));

    public static Task AnalyzerAsync(string source, params MetadataReference[] extraReferences)
    {
        var test = new CSharpAnalyzerTest<TAnalyzer, DefaultVerifier>
        {
            TestCode = source,
            ReferenceAssemblies = Net8WithAspNetCore,
        };
        test.TestState.AdditionalReferences.AddRange(extraReferences);
        return test.RunAsync();
    }
}
