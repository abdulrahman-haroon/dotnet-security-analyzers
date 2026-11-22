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
/// DSA004 fixes: wrap the call in if (env.IsDevelopment()) { ... }, or, on a WebApplication, delete it
/// (WebApplication already shows the developer exception page in Development).
/// </summary>
[ExportCodeFixProvider(LanguageNames.CSharp, Name = nameof(UnguardedDeveloperExceptionPageCodeFix)), Shared]
public sealed class UnguardedDeveloperExceptionPageCodeFix : CodeFixProvider
{
    private const string HostingNamespace = "Microsoft.Extensions.Hosting";

    public override ImmutableArray<string> FixableDiagnosticIds => ImmutableArray.Create(UnguardedDeveloperExceptionPageAnalyzer.DiagnosticId);

    public override FixAllProvider GetFixAllProvider() => WellKnownFixAllProviders.BatchFixer;

    public override async Task RegisterCodeFixesAsync(CodeFixContext context)
    {
        var document = context.Document;
        var root = await document.GetSyntaxRootAsync(context.CancellationToken).ConfigureAwait(false);
        var model = await document.GetSemanticModelAsync(context.CancellationToken).ConfigureAwait(false);
        if (root is null || model is null)
            return;

        // Only a stand-alone statement `x.UseDeveloperExceptionPage();` can be wrapped or removed safely.
        if (root.FindNode(context.Diagnostics[0].Location.SourceSpan, getInnermostNodeForTie: true)
                .FirstAncestorOrSelf<InvocationExpressionSyntax>() is not { Expression: MemberAccessExpressionSyntax member, Parent: ExpressionStatementSyntax statement })
            return;

        var receiverType = model.GetTypeInfo(member.Expression, context.CancellationToken).Type;
        var isWebApplication = receiverType?.ToDisplayString() == "Microsoft.AspNetCore.Builder.WebApplication";

        var environment = isWebApplication
            ? SyntaxFactory.MemberAccessExpression(SyntaxKind.SimpleMemberAccessExpression, member.Expression.WithoutTrivia(), SyntaxFactory.IdentifierName("Environment"))
            : FindEnvironmentInScope(model, statement, context.CancellationToken);

        if (environment is not null)
        {
            context.RegisterCodeFix(
                CodeAction.Create(
                    "Only use it in Development: wrap in if (IsDevelopment())",
                    ct => WrapAsync(document, root, model, statement, environment, ct),
                    equivalenceKey: "DSA004.Wrap"),
                context.Diagnostics[0]);
        }

        if (isWebApplication)
        {
            context.RegisterCodeFix(
                CodeAction.Create(
                    "Remove it (WebApplication already shows this page in Development)",
                    _ => Task.FromResult(document.WithSyntaxRoot(root.RemoveNode(statement, SyntaxRemoveOptions.KeepNoTrivia)!)),
                    equivalenceKey: "DSA004.Remove"),
                context.Diagnostics[0]);
        }
    }

    // A parameter or local of type IHostEnvironment (IWebHostEnvironment derives from it), e.g. Startup.Configure(app, env).
    private static ExpressionSyntax? FindEnvironmentInScope(SemanticModel model, SyntaxNode position, CancellationToken cancellationToken)
    {
        var hostEnvironment = model.Compilation.GetTypeByMetadataName("Microsoft.Extensions.Hosting.IHostEnvironment");
        if (hostEnvironment is null)
            return null;

        var symbol = model.LookupSymbols(position.SpanStart).FirstOrDefault(s =>
            (s is IParameterSymbol p && Symbols.IsOrInherits(p.Type, hostEnvironment)) ||
            (s is ILocalSymbol l && Symbols.IsOrInherits(l.Type, hostEnvironment)));

        return symbol is null ? null : SyntaxFactory.IdentifierName(symbol.Name);
    }

    private static Task<Document> WrapAsync(Document document, SyntaxNode root, SemanticModel model, ExpressionStatementSyntax statement,
        ExpressionSyntax environment, CancellationToken cancellationToken)
    {
        // Written out with the file's own line ending and indentation, so the result never depends on IDE settings.
        var eol = Usings.EndOfLine(root).ToString();
        var indent = Usings.Indentation(statement);
        var step = IndentUnit(statement, indent);
        var text =
            $"if ({environment.ToFullString()}.IsDevelopment()){eol}" +
            $"{indent}{{{eol}" +
            $"{indent}{step}{statement.WithoutTrivia().ToFullString()}{eol}" +
            $"{indent}}}";

        var guarded = SyntaxFactory.ParseStatement(text)
            .WithLeadingTrivia(statement.GetLeadingTrivia())
            .WithTrailingTrivia(statement.GetTrailingTrivia());

        var newRoot = root.ReplaceNode(statement, guarded);

        // IsDevelopment() is an extension method in Microsoft.Extensions.Hosting; import it if it isn't in scope.
        var inScope = !model.LookupSymbols(statement.SpanStart, name: "HostEnvironmentEnvExtensions").IsEmpty ||
                      !model.LookupNamespacesAndTypes(statement.SpanStart, name: "HostEnvironmentEnvExtensions").IsEmpty;
        if (!inScope && newRoot is CompilationUnitSyntax unit)
            newRoot = Usings.Add(unit, HostingNamespace);

        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(document.WithSyntaxRoot(newRoot));
    }

    // One indentation step, worked out from how far this statement is indented past its block's `{`.
    private static string IndentUnit(StatementSyntax statement, string indent)
    {
        if (statement.Parent is BlockSyntax block)
        {
            var braceIndent = block.OpenBraceToken.LeadingTrivia.LastOrDefault(t => t.IsKind(SyntaxKind.WhitespaceTrivia)).ToString();
            if (indent.Length > braceIndent.Length && indent.StartsWith(braceIndent, System.StringComparison.Ordinal))
                return indent.Substring(braceIndent.Length);
        }

        return "    ";
    }
}
