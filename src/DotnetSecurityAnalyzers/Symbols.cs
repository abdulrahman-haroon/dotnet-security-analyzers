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

    /// <summary>True if the symbol has an attribute whose class is, derives from, or implements <paramref name="target"/>.</summary>
    public static bool HasAttribute(ISymbol symbol, INamedTypeSymbol target) =>
        symbol.GetAttributes().Any(a => IsOrInherits(a.AttributeClass, target));
}
