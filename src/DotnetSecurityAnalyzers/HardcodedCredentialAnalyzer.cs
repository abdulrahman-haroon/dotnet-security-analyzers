using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace DotnetSecurityAnalyzers;

/// <summary>
/// DSA007: a password written in the source code: in a connection string, a NetworkCredential,
/// or passed to ASP.NET Core Identity. Calls inside an IsDevelopment() check are left alone.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class HardcodedCredentialAnalyzer : DiagnosticAnalyzer
{
    public const string DiagnosticId = "DSA007";

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId,
        title: "Password is hardcoded",
        messageFormat: "This password is written in the source code; anyone with the code or the DLL can read it. Load it from configuration or a secret store.",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "Passwords in source code stay in git history and in the compiled assembly. Read them from a secret store.",
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

            var credential = start.Compilation.GetTypeByMetadataName("System.Net.NetworkCredential");
            var userManager = start.Compilation.GetTypeByMetadataName("Microsoft.AspNetCore.Identity.UserManager`1");

            start.RegisterOperationAction(ctx =>
            {
                var argument = (IArgumentOperation)ctx.Operation;
                if (argument.Parameter is not { Type.SpecialType: SpecialType.System_String } parameter)
                    return;

                var type = parameter.ContainingSymbol.ContainingType?.OriginalDefinition;
                var isPassword = parameter.Name is "password" or "newPassword" && type is not null &&
                                 (SymbolEqualityComparer.Default.Equals(type, credential) ||
                                  SymbolEqualityComparer.Default.Equals(type, userManager));
                if (!isPassword && parameter.Name != "connectionString")
                    return;

                if (HardcodedJwtSigningKeyAnalyzer.Resolve(argument.Value, ctx.CancellationToken).ConstantValue
                        is not { HasValue: true, Value: string value })
                    return;

                var isSecret = isPassword ? !Secrets.IsPlaceholder(value) : Secrets.HasConnectionStringPassword(value);
                if (isSecret && !UnguardedDeveloperExceptionPageAnalyzer.IsGuarded(argument.Value.Syntax))
                    ctx.ReportDiagnostic(Diagnostic.Create(Rule, argument.Value.Syntax.GetLocation()));
            }, OperationKind.Argument);
        });
    }
}
