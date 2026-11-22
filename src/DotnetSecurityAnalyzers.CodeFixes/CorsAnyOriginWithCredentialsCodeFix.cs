using System.Collections.Immutable;
using System.Composition;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace DotnetSecurityAnalyzers.CodeFixes;

/// <summary>DSA002 fix: replace SetIsOriginAllowed(_ => true) with WithOrigins("https://example.com") for the user to edit.</summary>
[ExportCodeFixProvider(LanguageNames.CSharp, Name = nameof(CorsAnyOriginWithCredentialsCodeFix)), Shared]
public sealed class CorsAnyOriginWithCredentialsCodeFix : CodeFixProvider
{
    public override ImmutableArray<string> FixableDiagnosticIds => ImmutableArray.Create(CorsAnyOriginWithCredentialsAnalyzer.DiagnosticId);

    public override FixAllProvider GetFixAllProvider() => WellKnownFixAllProviders.BatchFixer;

    public override async Task RegisterCodeFixesAsync(CodeFixContext context)
    {
        var root = await context.Document.GetSyntaxRootAsync(context.CancellationToken).ConfigureAwait(false);
        if (root?.FindNode(context.Diagnostics[0].Location.SourceSpan, getInnermostNodeForTie: true)
                .FirstAncestorOrSelf<InvocationExpressionSyntax>() is not { Expression: MemberAccessExpressionSyntax member } invocation)
            return;

        context.RegisterCodeFix(
            CodeAction.Create(
                "Allow only listed origins: WithOrigins(\"https://example.com\")",
                _ =>
                {
                    var fixedCall = invocation
                        .WithExpression(member.WithName(SyntaxFactory.IdentifierName("WithOrigins")))
                        .WithArgumentList(SyntaxFactory.ArgumentList(SyntaxFactory.SingletonSeparatedList(
                            SyntaxFactory.Argument(SyntaxFactory.LiteralExpression(
                                SyntaxKind.StringLiteralExpression, SyntaxFactory.Literal("https://example.com"))))));
                    return Task.FromResult(context.Document.WithSyntaxRoot(root.ReplaceNode(invocation, fixedCall)));
                },
                equivalenceKey: "DSA002.WithOrigins"),
            context.Diagnostics[0]);
    }
}
