using System.Collections.Immutable;
using System.Composition;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace DotnetSecurityAnalyzers.CodeFixes;

/// <summary>DSA005 fix: HttpOnly = true, or SecurePolicy = CookieSecurePolicy.Always.</summary>
[ExportCodeFixProvider(LanguageNames.CSharp, Name = nameof(InsecureCookieBuilderCodeFix)), Shared]
public sealed class InsecureCookieBuilderCodeFix : CodeFixProvider
{
    public override ImmutableArray<string> FixableDiagnosticIds => ImmutableArray.Create(InsecureCookieBuilderAnalyzer.DiagnosticId);

    public override FixAllProvider GetFixAllProvider() => WellKnownFixAllProviders.BatchFixer;

    public override async Task RegisterCodeFixesAsync(CodeFixContext context)
    {
        var root = await context.Document.GetSyntaxRootAsync(context.CancellationToken).ConfigureAwait(false);
        if (root?.FindNode(context.Diagnostics[0].Location.SourceSpan, getInnermostNodeForTie: true)
                .FirstAncestorOrSelf<AssignmentExpressionSyntax>() is not { } assignment)
            return;

        var property = assignment.Left switch
        {
            MemberAccessExpressionSyntax m => m.Name.Identifier.ValueText,
            IdentifierNameSyntax i => i.Identifier.ValueText,
            _ => null,
        };

        ExpressionSyntax? safeValue = property switch
        {
            "HttpOnly" => SyntaxFactory.LiteralExpression(SyntaxKind.TrueLiteralExpression),
            // Keep however the enum was written (CookieSecurePolicy.None / Http.CookieSecurePolicy.None), swap the member.
            "SecurePolicy" when assignment.Right is MemberAccessExpressionSyntax value => value.WithName(SyntaxFactory.IdentifierName("Always")),
            _ => null,
        };
        if (safeValue is null)
            return;

        var title = property == "HttpOnly" ? "Set HttpOnly = true" : "Set SecurePolicy = CookieSecurePolicy.Always";
        context.RegisterCodeFix(
            CodeAction.Create(
                title,
                _ => Task.FromResult(context.Document.WithSyntaxRoot(
                    root.ReplaceNode(assignment.Right, safeValue.WithTriviaFrom(assignment.Right)))),
                equivalenceKey: "DSA005." + property),
            context.Diagnostics[0]);
    }
}
