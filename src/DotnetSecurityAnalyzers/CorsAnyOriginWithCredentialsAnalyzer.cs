using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace DotnetSecurityAnalyzers;

/// <summary>
/// DSA002: a CORS policy that accepts every origin (SetIsOriginAllowed(_ => true)) and also allows credentials.
/// ASP.NET Core refuses AllowAnyOrigin() + AllowCredentials() at runtime, and this is the usual workaround,
/// which lets any website make logged-in requests to the API.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class CorsAnyOriginWithCredentialsAnalyzer : DiagnosticAnalyzer
{
    public const string DiagnosticId = "DSA002";

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId,
        title: "CORS policy allows any origin with credentials",
        messageFormat: "This CORS policy accepts every origin and also allows credentials, so any website can make authenticated requests",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "SetIsOriginAllowed(_ => true) combined with AllowCredentials() reflects any Origin back with Access-Control-Allow-Credentials: true. List the trusted origins with WithOrigins(...) instead.",
        helpLinkUri: Symbols.HelpLink(DiagnosticId));

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();

        context.RegisterCompilationStartAction(start =>
        {
            var builder = start.Compilation.GetTypeByMetadataName("Microsoft.AspNetCore.Cors.Infrastructure.CorsPolicyBuilder");
            if (builder is null)
                return;

            start.RegisterOperationAction(ctx => AnalyzeInvocation(ctx, builder), OperationKind.Invocation);
        });
    }

    private static void AnalyzeInvocation(OperationAnalysisContext context, INamedTypeSymbol builder)
    {
        var invocation = (IInvocationOperation)context.Operation;
        if (!IsBuilderMethod(invocation.TargetMethod, builder, "SetIsOriginAllowed") ||
            invocation.Arguments.Length != 1 || !IsAlwaysTrueLambda(invocation.Arguments[0].Value))
            return;

        // Look for AllowCredentials() in the same policy lambda / method that configures this builder.
        // shortcut: same-scope check, not data flow; a policy built across two methods is missed.
        var scope = invocation.Syntax.Ancestors().FirstOrDefault(n =>
            n is AnonymousFunctionExpressionSyntax or BaseMethodDeclarationSyntax or LocalFunctionStatementSyntax
              or AccessorDeclarationSyntax or CompilationUnitSyntax);
        var model = invocation.SemanticModel;
        if (scope is null || model is null)
            return;

        var allowsCredentials = scope.DescendantNodes().OfType<InvocationExpressionSyntax>().Any(call =>
            model.GetSymbolInfo(call, context.CancellationToken).Symbol is IMethodSymbol m &&
            IsBuilderMethod(m, builder, "AllowCredentials"));

        if (allowsCredentials)
            context.ReportDiagnostic(Diagnostic.Create(Rule, invocation.Syntax.GetLocation()));
    }

    private static bool IsBuilderMethod(IMethodSymbol method, INamedTypeSymbol builder, string name) =>
        method.Name == name && SymbolEqualityComparer.Default.Equals(method.ContainingType, builder);

    // Matches `_ => true` and `_ => { return true; }`.
    private static bool IsAlwaysTrueLambda(IOperation value)
    {
        if (value is IDelegateCreationOperation delegateCreation)
            value = delegateCreation.Target;

        return value is IAnonymousFunctionOperation { Body.Operations: { Length: 1 } operations } &&
               operations[0] is IReturnOperation { ReturnedValue.ConstantValue: { HasValue: true, Value: true } };
    }
}
