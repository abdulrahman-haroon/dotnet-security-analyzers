using System.Threading.Tasks;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.CSharp.Testing;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Testing;

namespace DotnetSecurityAnalyzers.Tests;

/// <summary>
/// Applies the code fix chosen by <c>equivalenceKey</c> to <c>source</c> and checks the result equals <c>fixedSource</c>
/// exactly (it must also compile, and the warning must be gone).
/// </summary>
internal static class VerifyFix<TAnalyzer, TCodeFix>
    where TAnalyzer : DiagnosticAnalyzer, new()
    where TCodeFix : CodeFixProvider, new()
{
    public static Task FixAsync(string source, string fixedSource, string equivalenceKey) =>
        new CSharpCodeFixTest<TAnalyzer, TCodeFix, DefaultVerifier>
        {
            TestCode = source,
            FixedCode = fixedSource,
            CodeActionEquivalenceKey = equivalenceKey,
            ReferenceAssemblies = Verify<TAnalyzer>.References,
        }.RunAsync();
}
