using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace DotnetSecurityAnalyzers;

/// <summary>DSA008: a string whose name says it is a password, token or card number, passed to ILogger.</summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class SensitiveDataLoggedAnalyzer : DiagnosticAnalyzer
{
    public const string DiagnosticId = "DSA008";

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId,
        title: "Sensitive data written to the log",
        messageFormat: "'{0}' looks like a secret and is written to the log, where more people and systems can read it. Remove it or mask it.",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "Logs are copied, shipped and kept far longer than the data they describe. Never log passwords, tokens, keys or card numbers.",
        helpLinkUri: Symbols.HelpLink(DiagnosticId));

    // Matched against the END of the name, so passwordHash, tokenExpiry and passwordPolicy stay quiet.
    private static readonly string[] SensitiveSuffixes =
    {
        "password", "passwd", "clientsecret", "secretkey", "apikey", "privatekey",
        "accesstoken", "refreshtoken", "idtoken", "cardnumber", "cvv",
    };

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();

        context.RegisterCompilationStartAction(start =>
        {
            if (Symbols.IsTestProject(start.Compilation))
                return;

            var extensions = start.Compilation.GetTypeByMetadataName("Microsoft.Extensions.Logging.LoggerExtensions");
            if (extensions is null)
                return;

            start.RegisterOperationAction(ctx =>
            {
                var invocation = (IInvocationOperation)ctx.Operation;
                if (!SymbolEqualityComparer.Default.Equals(invocation.TargetMethod.ContainingType, extensions) ||
                    UnguardedDeveloperExceptionPageAnalyzer.IsGuarded(invocation.Syntax))
                    return;

                // The first argument is the logger itself.
                foreach (var value in invocation.Arguments.Skip(1).SelectMany(a => LoggedValues(a.Value)))
                {
                    var name = value switch
                    {
                        ILocalReferenceOperation { Local.IsConst: false } local => local.Local.Name,
                        IParameterReferenceOperation parameter => parameter.Parameter.Name,
                        IPropertyReferenceOperation property => property.Property.Name,
                        IFieldReferenceOperation { Field.IsConst: false } field => field.Field.Name,
                        _ => null,
                    };

                    if (name is not null && value.Type?.SpecialType == SpecialType.System_String &&
                        SensitiveSuffixes.Any(s => name.EndsWith(s, StringComparison.OrdinalIgnoreCase)))
                        ctx.ReportDiagnostic(Diagnostic.Create(Rule, value.Syntax.GetLocation(), name));
                }
            }, OperationKind.Invocation);
        });
    }

    // The values that end up in the log text as they are. Method calls (Mask(password)) are not entered.
    private static IEnumerable<IOperation> LoggedValues(IOperation operation) => operation switch
    {
        IConversionOperation conversion => LoggedValues(conversion.Operand),
        IArrayCreationOperation { Initializer: { } initializer } => initializer.ElementValues.SelectMany(LoggedValues),
        IInterpolatedStringOperation text => text.Parts.OfType<IInterpolationOperation>().SelectMany(p => LoggedValues(p.Expression)),
        IBinaryOperation binary => LoggedValues(binary.LeftOperand).Concat(LoggedValues(binary.RightOperand)),
        ICoalesceOperation coalesce => LoggedValues(coalesce.Value).Concat(LoggedValues(coalesce.WhenNull)),
        _ => new[] { operation },
    };
}
