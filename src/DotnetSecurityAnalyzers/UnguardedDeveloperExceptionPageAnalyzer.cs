using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace DotnetSecurityAnalyzers;

/// <summary>
/// DSA004: a development-only diagnostic feature (developer exception page, migrations endpoint,
/// EF sensitive-data logging, detailed errors sent to clients, PII in identity logs) that is not
/// limited to the Development environment.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class UnguardedDeveloperExceptionPageAnalyzer : DiagnosticAnalyzer
{
    public const string DiagnosticId = "DSA004";

    /// <summary>Diagnostic property naming the feature, so the code fix knows what it is fixing.</summary>
    public const string FeatureProperty = "Feature";

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId,
        title: "Development-only diagnostics enabled outside Development",
        messageFormat: "{0} is not inside an IsDevelopment() check, so in production it {1}",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "Developer error pages, detailed errors and sensitive-data logging help while debugging, but in production they hand internals, personal data or tokens to users or to the logs. Wrap them in if (app.Environment.IsDevelopment()).",
        helpLinkUri: Symbols.HelpLink(DiagnosticId));

    // (declaring type, method) -> what goes wrong in production.
    private static readonly (string Type, string Member, string Risk)[] Methods =
    {
        ("Microsoft.AspNetCore.Builder.DeveloperExceptionPageExtensions", "UseDeveloperExceptionPage", "shows stack traces and request details to users"),
        ("Microsoft.AspNetCore.Builder.MigrationsEndPointExtensions", "UseMigrationsEndPoint", "lets anyone apply pending database migrations through a web request"),
        ("Microsoft.AspNetCore.Builder.DatabaseErrorPageExtensions", "UseDatabaseErrorPage", "shows database errors and schema details to users"),
        ("Microsoft.EntityFrameworkCore.DbContextOptionsBuilder", "EnableSensitiveDataLogging", "writes query parameter values (passwords, personal data) to the logs"),
    };

    // (declaring type, property) set to true -> what goes wrong in production.
    private static readonly (string Type, string Member, string Risk)[] Properties =
    {
        ("Microsoft.AspNetCore.SignalR.HubOptions", "EnableDetailedErrors", "sends exception details to SignalR clients"),
        ("Grpc.AspNetCore.Server.GrpcServiceOptions", "EnableDetailedErrors", "sends exception messages to gRPC clients"),
        ("Microsoft.AspNetCore.Components.Server.CircuitOptions", "DetailedErrors", "sends exception details to the browser"),
        ("Microsoft.IdentityModel.Logging.IdentityModelEventSource", "ShowPII", "writes personal data from tokens and requests to the logs"),
        ("Microsoft.IdentityModel.Logging.IdentityModelEventSource", "LogCompleteSecurityArtifact", "writes complete security tokens to the logs"),
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

            var methods = Resolve(start.Compilation, Methods);
            var properties = Resolve(start.Compilation, Properties);

            if (methods.Count > 0)
                start.RegisterOperationAction(ctx => AnalyzeInvocation(ctx, methods), OperationKind.Invocation);

            if (properties.Count > 0)
                start.RegisterOperationAction(ctx => AnalyzeAssignment(ctx, properties), OperationKind.SimpleAssignment);
        });
    }

    // Keeps only the entries whose declaring type exists in this compilation.
    private static List<(INamedTypeSymbol Type, string Member, string Risk)> Resolve(
        Compilation compilation, (string Type, string Member, string Risk)[] entries)
    {
        var resolved = new List<(INamedTypeSymbol, string, string)>();
        foreach (var (typeName, member, risk) in entries)
        {
            if (compilation.GetTypeByMetadataName(typeName) is { } type)
                resolved.Add((type, member, risk));
        }

        return resolved;
    }

    private static void AnalyzeInvocation(OperationAnalysisContext context, List<(INamedTypeSymbol Type, string Member, string Risk)> methods)
    {
        var invocation = (IInvocationOperation)context.Operation;
        var method = invocation.TargetMethod;
        var match = methods.FirstOrDefault(m => m.Member == method.Name && Symbols.IsOrInherits(method.ContainingType, m.Type));
        if (match.Type is null)
            return;

        // EnableSensitiveDataLogging(false) or EnableSensitiveDataLogging(isDevelopment): switched off or already gated.
        // Only the bool argument counts; for extension methods the receiver (`app`) is an explicit argument too.
        if (invocation.Arguments.Any(a => a.ArgumentKind == ArgumentKind.Explicit &&
                                          a.Parameter?.Type.SpecialType == SpecialType.System_Boolean &&
                                          a.Value.ConstantValue is not { HasValue: true, Value: true }))
            return;

        Report(context, invocation.Syntax, method.Name + "()", match.Risk);
    }

    private static void AnalyzeAssignment(OperationAnalysisContext context, List<(INamedTypeSymbol Type, string Member, string Risk)> properties)
    {
        var assignment = (ISimpleAssignmentOperation)context.Operation;
        if (assignment.Target is not IPropertyReferenceOperation { Property: var property })
            return;

        var match = properties.FirstOrDefault(p => p.Member == property.Name && Symbols.IsOrInherits(property.ContainingType, p.Type));
        if (match.Type is null)
            return;

        // Only a literal `true`; a variable means the author is already deciding when to enable it.
        var value = assignment.Value;
        while (value is IConversionOperation conversion)
            value = conversion.Operand;
        if (value.ConstantValue is not { HasValue: true, Value: true })
            return;

        Report(context, assignment.Syntax, property.Name + " = true", match.Risk);
    }

    private static void Report(OperationAnalysisContext context, SyntaxNode node, string feature, string risk)
    {
        if (IsGuarded(node))
            return;

        var properties = ImmutableDictionary<string, string?>.Empty.Add(FeatureProperty, feature);
        context.ReportDiagnostic(Diagnostic.Create(Rule, node.GetLocation(), properties, feature, risk));
    }

    // shortcut: matches IsDevelopment()/IsEnvironment("Development") by name in an enclosing if / ?: ;
    // an early `if (!env.IsDevelopment()) return;` above the call is not recognised.
    internal static bool IsGuarded(SyntaxNode node)
    {
        SyntaxNode child = node;
        foreach (var ancestor in node.Ancestors())
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
                // Startup.ConfigureDevelopment / ConfigureDevelopmentServices only run in the Development environment.
                case MethodDeclarationSyntax method:
                    return method.Identifier.ValueText is "ConfigureDevelopment" or "ConfigureDevelopmentServices";
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
