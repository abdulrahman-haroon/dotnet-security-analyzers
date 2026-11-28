using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace DotnetSecurityAnalyzers;

/// <summary>
/// DSA003: a SymmetricSecurityKey (used to sign / validate JWTs) built from a value written in the source code.
/// Anyone who can read the code or the compiled DLL can then forge valid tokens.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class HardcodedJwtSigningKeyAnalyzer : DiagnosticAnalyzer
{
    public const string DiagnosticId = "DSA003";

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId,
        title: "JWT signing key is hardcoded",
        messageFormat: "This signing key is written in the source code; anyone with the code or the DLL can forge tokens. Load it from configuration or a secret store.",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "A SymmetricSecurityKey built from a string literal, constant, or byte-array literal ends up in source control and in the compiled assembly. Read the key from a secret store (Azure Key Vault, AWS Secrets Manager, user-secrets in development).",
        helpLinkUri: Symbols.HelpLink(DiagnosticId));

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();

        context.RegisterCompilationStartAction(start =>
        {
            if (Symbols.IsTestProject(start.Compilation))
                return;

            var compilation = start.Compilation;
            var keyType = compilation.GetTypeByMetadataName("Microsoft.IdentityModel.Tokens.SymmetricSecurityKey");
            var encoding = compilation.GetTypeByMetadataName("System.Text.Encoding");
            var convert = compilation.GetTypeByMetadataName("System.Convert");
            if (keyType is null || encoding is null || convert is null)
                return;

            start.RegisterOperationAction(ctx =>
            {
                var creation = (IObjectCreationOperation)ctx.Operation;
                if (SymbolEqualityComparer.Default.Equals(creation.Type, keyType) &&
                    creation.Arguments.Length > 0 &&
                    IsHardcodedBytes(creation.Arguments[0].Value, encoding, convert, ctx.CancellationToken))
                {
                    ctx.ReportDiagnostic(Diagnostic.Create(Rule, creation.Syntax.GetLocation()));
                }
            }, OperationKind.ObjectCreation);
        });
    }

    private static bool IsHardcodedBytes(IOperation value, INamedTypeSymbol encoding, INamedTypeSymbol convert, CancellationToken cancellationToken)
    {
        value = Resolve(value, cancellationToken);

        switch (value)
        {
            // new byte[] { 1, 2, 3 }
            case IArrayCreationOperation { Initializer: { ElementValues.Length: > 0 } initializer }:
                return initializer.ElementValues.All(e => e.ConstantValue.HasValue);

            // "secret"u8.ToArray()
            case IInvocationOperation { TargetMethod.Name: "ToArray", Instance: IUtf8StringOperation }:
                return true;

            // Encoding.UTF8.GetBytes("secret") or Convert.FromBase64String("c2VjcmV0")
            case IInvocationOperation invocation:
                var method = invocation.TargetMethod;
                var isDecoder =
                    (method.Name == "GetBytes" && Symbols.IsOrInherits(method.ContainingType, encoding)) ||
                    (method.Name == "FromBase64String" && SymbolEqualityComparer.Default.Equals(method.ContainingType, convert));
                return isDecoder && invocation.Arguments.Length > 0 &&
                       Resolve(invocation.Arguments[0].Value, cancellationToken).ConstantValue is { HasValue: true, Value: string };

            default:
                return false;
        }
    }

    /// <summary>
    /// Follows a local variable or readonly field back to the value it was initialised with, as long as
    /// it is never assigned again. Stops at anything else (parameters, method calls, configuration).
    /// </summary>
    internal static IOperation Resolve(IOperation value, CancellationToken cancellationToken)
    {
        for (var hops = 0; hops < 5; hops++)
        {
            while (value is IConversionOperation conversion)
                value = conversion.Operand;

            var (symbol, declaration) = value switch
            {
                ILocalReferenceOperation local => ((ISymbol)local.Local, local.Local.DeclaringSyntaxReferences.FirstOrDefault()),
                IFieldReferenceOperation { Field: { IsReadOnly: true } field } => (field, field.DeclaringSyntaxReferences.FirstOrDefault()),
                _ => (null, null),
            };

            var model = value.SemanticModel;
            var initializer = (declaration?.GetSyntax(cancellationToken) as VariableDeclaratorSyntax)?.Initializer?.Value;

            // Only follow declarations in the same file: other files would need a second semantic model.
            if (symbol is null || model is null || initializer is null || initializer.SyntaxTree != model.SyntaxTree ||
                IsAssignedAfterDeclaration(symbol, initializer, model, cancellationToken))
                return value;

            var next = model.GetOperation(initializer, cancellationToken);
            if (next is null)
                return value;

            value = next;
        }

        return value;
    }

    private static bool IsAssignedAfterDeclaration(ISymbol symbol, SyntaxNode initializer, SemanticModel model, CancellationToken cancellationToken)
    {
        // A readonly field can only be reassigned in a constructor of its own type; a local only in its own method.
        var scope = symbol is ILocalSymbol
            ? initializer.Ancestors().FirstOrDefault(n => n is BlockSyntax or CompilationUnitSyntax)
            : initializer.Ancestors().OfType<TypeDeclarationSyntax>().FirstOrDefault();
        if (scope is null)
            return true;

        foreach (var node in scope.DescendantNodes())
        {
            var target = node switch
            {
                AssignmentExpressionSyntax assignment => assignment.Left,
                ArgumentSyntax { RefKindKeyword.RawKind: not 0 } argument => argument.Expression,
                _ => null,
            };

            if (target is not null &&
                SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(target, cancellationToken).Symbol, symbol))
                return true;
        }

        return false;
    }
}
