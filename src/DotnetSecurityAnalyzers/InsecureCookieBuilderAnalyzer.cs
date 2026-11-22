using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace DotnetSecurityAnalyzers;

/// <summary>
/// DSA005: an authentication, session or antiforgery cookie (configured through CookieBuilder)
/// set to never be Secure, or to be readable by JavaScript.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class InsecureCookieBuilderAnalyzer : DiagnosticAnalyzer
{
    public const string DiagnosticId = "DSA005";

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId,
        title: "Security cookie is weakened",
        messageFormat: "{0}",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "CookieBuilder configures the authentication, session and antiforgery cookies. They must be HttpOnly and must not be sent over plain HTTP.",
        helpLinkUri: Symbols.HelpLink(DiagnosticId));

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();

        context.RegisterCompilationStartAction(start =>
        {
            var cookieBuilder = start.Compilation.GetTypeByMetadataName("Microsoft.AspNetCore.Http.CookieBuilder");
            var securePolicy = start.Compilation.GetTypeByMetadataName("Microsoft.AspNetCore.Http.CookieSecurePolicy");
            if (cookieBuilder is null || securePolicy is null)
                return;

            start.RegisterOperationAction(ctx =>
            {
                var assignment = (ISimpleAssignmentOperation)ctx.Operation;
                if (assignment.Target is not IPropertyReferenceOperation { Property: var property } ||
                    !Symbols.IsOrInherits(property.ContainingType, cookieBuilder))
                    return;

                var value = assignment.Value;
                while (value is IConversionOperation conversion)
                    value = conversion.Operand;

                var message = property.Name switch
                {
                    "SecurePolicy" when value is IFieldReferenceOperation { Field.Name: "None" } field &&
                                        SymbolEqualityComparer.Default.Equals(field.Field.ContainingType, securePolicy)
                        => "SecurePolicy = CookieSecurePolicy.None lets this cookie travel over plain HTTP, where it can be stolen. Use CookieSecurePolicy.Always.",
                    "HttpOnly" when value.ConstantValue is { HasValue: true, Value: false }
                        => "HttpOnly = false lets JavaScript read this cookie, so any XSS bug can steal the session. Leave HttpOnly = true.",
                    _ => null,
                };

                if (message is not null)
                    ctx.ReportDiagnostic(Diagnostic.Create(Rule, assignment.Syntax.GetLocation(), message));
            }, OperationKind.SimpleAssignment);
        });
    }
}
