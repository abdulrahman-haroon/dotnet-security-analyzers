using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace DotnetSecurityAnalyzers.CodeFixes;

/// <summary>Helpers so fixes keep the file's own line endings and indentation (never mix CRLF into an LF file).</summary>
internal static class Usings
{
    /// <summary>Adds `using <paramref name="ns"/>;` in alphabetical position, unless it is already there.</summary>
    public static CompilationUnitSyntax Add(CompilationUnitSyntax root, string ns)
    {
        if (root.Usings.Any(u => u.Name?.ToString() == ns))
            return root;

        var directive = SyntaxFactory.UsingDirective(SyntaxFactory.ParseName(ns))
            .WithTrailingTrivia(EndOfLine(root));

        var index = root.Usings.TakeWhile(u => string.CompareOrdinal(u.Name?.ToString(), ns) < 0).Count();
        return root.WithUsings(root.Usings.Insert(index, directive));
    }

    /// <summary>The line ending the file already uses (LF or CRLF).</summary>
    public static SyntaxTrivia EndOfLine(SyntaxNode root) =>
        root.DescendantTrivia().FirstOrDefault(t => t.IsKind(SyntaxKind.EndOfLineTrivia)) is { RawKind: not 0 } eol
            ? eol
            : SyntaxFactory.CarriageReturnLineFeed;

    /// <summary>The whitespace at the start of the line a node starts on.</summary>
    public static string Indentation(SyntaxNode node) =>
        node.GetLeadingTrivia().LastOrDefault(t => t.IsKind(SyntaxKind.WhitespaceTrivia)).ToString();
}
