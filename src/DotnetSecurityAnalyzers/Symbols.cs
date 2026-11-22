using System;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;

namespace DotnetSecurityAnalyzers;

/// <summary>Small helpers shared by the analyzers.</summary>
internal static class Symbols
{
    public static string HelpLink(string ruleId) =>
        $"https://github.com/abdulrahman-haroon/dotnet-security-analyzers/blob/main/docs/rules/{ruleId}.md";

    /// <summary>True if <paramref name="type"/> is <paramref name="target"/>, derives from it, or implements it.</summary>
    public static bool IsOrInherits(ITypeSymbol? type, INamedTypeSymbol target)
    {
        for (var t = type; t is not null; t = t.BaseType)
        {
            if (SymbolEqualityComparer.Default.Equals(t, target))
                return true;
        }

        return type is not null && type.AllInterfaces.Any(i => SymbolEqualityComparer.Default.Equals(i, target));
    }

    private static readonly ImmutableHashSet<string> TestFrameworkAssemblies = ImmutableHashSet.Create(
        StringComparer.OrdinalIgnoreCase,
        "xunit.core", "xunit.v3.core", "nunit.framework", "Microsoft.VisualStudio.TestPlatform.TestFramework",
        "TUnit.Core", "Microsoft.AspNetCore.Mvc.Testing");

    /// <summary>
    /// Test projects use fake keys and throwaway endpoints on purpose; warning there is noise.
    /// </summary>
    public static bool IsTestProject(Compilation compilation) =>
        compilation.ReferencedAssemblyNames.Any(a => TestFrameworkAssemblies.Contains(a.Name));
}
