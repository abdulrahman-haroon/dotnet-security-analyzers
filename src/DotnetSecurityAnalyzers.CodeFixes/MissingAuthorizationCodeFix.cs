using System.Collections.Immutable;
using System.Composition;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace DotnetSecurityAnalyzers.CodeFixes;

/// <summary>
/// DSA001 fixes. Controllers: add [Authorize] to the action or the controller, or [AllowAnonymous].
/// Minimal APIs: append .RequireAuthorization() or .AllowAnonymous().
/// </summary>
[ExportCodeFixProvider(LanguageNames.CSharp, Name = nameof(MissingAuthorizationCodeFix)), Shared]
public sealed class MissingAuthorizationCodeFix : CodeFixProvider
{
    private const string AuthorizationNamespace = "Microsoft.AspNetCore.Authorization";

    public override ImmutableArray<string> FixableDiagnosticIds => ImmutableArray.Create(MissingAuthorizationAnalyzer.DiagnosticId);

    public override FixAllProvider GetFixAllProvider() => WellKnownFixAllProviders.BatchFixer;

    public override async Task RegisterCodeFixesAsync(CodeFixContext context)
    {
        var root = await context.Document.GetSyntaxRootAsync(context.CancellationToken).ConfigureAwait(false);
        if (root is null)
            return;

        var diagnostic = context.Diagnostics[0];
        var node = root.FindNode(diagnostic.Location.SourceSpan);

        if (node is MethodDeclarationSyntax method)
        {
            Register(context, diagnostic, "Add [Authorize] to this action", "DSA001.AuthorizeAction",
                ct => AddAttributeAsync(context.Document, method, "Authorize", ct));
            if (method.Parent is ClassDeclarationSyntax controller)
            {
                Register(context, diagnostic, "Add [Authorize] to the controller", "DSA001.AuthorizeController",
                    ct => AddAttributeAsync(context.Document, controller, "Authorize", ct));
            }
            Register(context, diagnostic, "Add [AllowAnonymous] (it is meant to be public)", "DSA001.AllowAnonymousAction",
                ct => AddAttributeAsync(context.Document, method, "AllowAnonymous", ct));
            return;
        }

        // Minimal API: the diagnostic sits on the method name of app.MapGet(...).
        if (node.FirstAncestorOrSelf<InvocationExpressionSyntax>() is { Expression: MemberAccessExpressionSyntax } invocation)
        {
            Register(context, diagnostic, "Add .RequireAuthorization()", "DSA001.RequireAuthorization",
                ct => AppendCallAsync(context.Document, invocation, "RequireAuthorization", ct));
            Register(context, diagnostic, "Add .AllowAnonymous() (it is meant to be public)", "DSA001.AllowAnonymousEndpoint",
                ct => AppendCallAsync(context.Document, invocation, "AllowAnonymous", ct));
        }
    }

    private static void Register(CodeFixContext context, Diagnostic diagnostic, string title, string key,
        System.Func<CancellationToken, Task<Document>> fix) =>
        context.RegisterCodeFix(CodeAction.Create(title, fix, equivalenceKey: key), diagnostic);

    private static async Task<Document> AddAttributeAsync(Document document, MemberDeclarationSyntax target, string name, CancellationToken cancellationToken)
    {
        var root = (CompilationUnitSyntax)(await document.GetSyntaxRootAsync(cancellationToken).ConfigureAwait(false))!;
        var model = await document.GetSemanticModelAsync(cancellationToken).ConfigureAwait(false);

        // The member's comments and indentation move in front of the new attribute; the member keeps the same indentation.
        var attribute = SyntaxFactory.AttributeList(SyntaxFactory.SingletonSeparatedList(SyntaxFactory.Attribute(SyntaxFactory.IdentifierName(name))))
            .WithLeadingTrivia(target.GetLeadingTrivia())
            .WithTrailingTrivia(Usings.EndOfLine(root), SyntaxFactory.Whitespace(Usings.Indentation(target)));
        var stripped = target.WithoutLeadingTrivia();
        var updated = stripped.WithAttributeLists(stripped.AttributeLists.Insert(0, attribute));

        var newRoot = root.ReplaceNode(target, updated);

        var inScope = model is not null &&
                      !model.LookupNamespacesAndTypes(target.SpanStart, name: name + "Attribute").IsEmpty;
        if (!inScope)
            newRoot = Usings.Add(newRoot, AuthorizationNamespace);

        return document.WithSyntaxRoot(newRoot);
    }

    private static async Task<Document> AppendCallAsync(Document document, InvocationExpressionSyntax invocation, string method, CancellationToken cancellationToken)
    {
        var root = await document.GetSyntaxRootAsync(cancellationToken).ConfigureAwait(false);

        // RequireAuthorization / AllowAnonymous live in Microsoft.AspNetCore.Builder, like MapGet, so no using is needed.
        var call = SyntaxFactory.InvocationExpression(
                SyntaxFactory.MemberAccessExpression(
                    SyntaxKind.SimpleMemberAccessExpression,
                    invocation.WithoutTrailingTrivia(),
                    SyntaxFactory.IdentifierName(method)))
            .WithTrailingTrivia(invocation.GetTrailingTrivia());

        return document.WithSyntaxRoot(root!.ReplaceNode(invocation, call));
    }
}
