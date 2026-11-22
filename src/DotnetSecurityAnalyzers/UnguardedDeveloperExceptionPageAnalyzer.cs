using System;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace DotnetSecurityAnalyzers;

/// <summary>
/// DSA004: UseDeveloperExceptionPage() that is not limited to the Development environment.
/// In production it shows stack traces, source snippets, headers and cookies to anyone who triggers an error.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class UnguardedDeveloperExceptionPageAnalyzer : DiagnosticAnalyzer
{
    public const string DiagnosticId = "DSA004";

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId,
        title: "Developer exception page is not limited to Development",
        messageFormat: "UseDeveloperExceptionPage() is not inside an IsDevelopment() check, so production errors would show stack traces and request details to users",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "Wrap UseDeveloperExceptionPage() in if (app.Environment.IsDevelopment()). Since .NET 6, WebApplication already turns it on in Development, so the call can usually be deleted.",
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

            var extensions = start.Compilation.GetTypeByMetadataName("Microsoft.AspNetCore.Builder.DeveloperExceptionPageExtensions");
            if (extensions is null)
                return;

            start.RegisterOperationAction(ctx =>
            {
                var invocation = (IInvocationOperation)ctx.Operation;
                if (invocation.TargetMethod.Name == "UseDeveloperExceptionPage" &&
                    SymbolEqualityComparer.Default.Equals(invocation.TargetMethod.ContainingType, extensions) &&
                    !IsGuarded(invocation.Syntax))
                {
                    ctx.ReportDiagnostic(Diagnostic.Create(Rule, invocation.Syntax.GetLocation()));
                }
            }, OperationKind.Invocation);
        });
    }

    // shortcut: matches IsDevelopment()/IsEnvironment("Development") by name in an enclosing if / ?: ;
    // an early `if (!env.IsDevelopment()) return;` above the call is not recognised.
    private static bool IsGuarded(SyntaxNode call)
    {
        SyntaxNode child = call;
        foreach (var ancestor in call.Ancestors())
        {
            switch (ancestor)
            {
                case IfStatementSyntax ifStatement when child == ifStatement.Statement:
                    if (ChecksDevelopment(ifStatement.Condition, negated: false))
                        return true;
                    break;
                case ElseClauseSyntax { Parent: IfStatementSyntax ifStatement }:
                    if (ChecksDevelopment(ifStatement.Condition, negated: true))
                        return true;
                    break;
                case ConditionalExpressionSyntax conditional when child == conditional.WhenTrue:
                    if (ChecksDevelopment(conditional.Condition, negated: false))
                        return true;
                    break;
                case ConditionalExpressionSyntax conditional when child == conditional.WhenFalse:
                    if (ChecksDevelopment(conditional.Condition, negated: true))
                        return true;
                    break;
                // Startup.ConfigureDevelopment(...) only runs in the Development environment.
                case MethodDeclarationSyntax method:
                    return method.Identifier.ValueText == "ConfigureDevelopment";
                case LocalFunctionStatementSyntax:
                    return false;
            }

            child = ancestor;
        }

        return false;
    }

    // True if the condition contains a Development check with the wanted polarity (`!` flips it).
    private static bool ChecksDevelopment(ExpressionSyntax condition, bool negated) =>
        condition.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>().Any(check =>
            IsDevelopmentCheck(check) && IsNegated(check, condition) == negated);

    private static bool IsDevelopmentCheck(InvocationExpressionSyntax call)
    {
        var name = call.Expression switch
        {
            MemberAccessExpressionSyntax member => member.Name.Identifier.ValueText,
            IdentifierNameSyntax identifier => identifier.Identifier.ValueText,
            _ => null,
        };

        return name == "IsDevelopment" ||
               (name == "IsEnvironment" &&
                call.ArgumentList.Arguments.FirstOrDefault()?.Expression is LiteralExpressionSyntax literal &&
                string.Equals(literal.Token.ValueText, "Development", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsNegated(SyntaxNode node, SyntaxNode root)
    {
        var negated = false;
        for (var current = node.Parent; current is not null && current != root.Parent; current = current.Parent)
        {
            if (current.IsKind(SyntaxKind.LogicalNotExpression))
                negated = !negated;
        }

        return negated;
    }
}
