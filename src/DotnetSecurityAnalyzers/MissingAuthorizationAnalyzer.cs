using System;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace DotnetSecurityAnalyzers;

/// <summary>
/// DSA001: an endpoint that doesn't say who may call it.
/// Checks MVC / Web API controller actions and minimal API endpoints (app.MapGet etc.).
/// Stays silent when the app protects endpoints globally (fallback policy, global AuthorizeFilter,
/// MapControllers().RequireAuthorization()).
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class MissingAuthorizationAnalyzer : DiagnosticAnalyzer
{
    public const string DiagnosticId = "DSA001";

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId,
        title: "Endpoint has no authorization",
        messageFormat: "'{0}' has no authorization, so anyone can call it. Add [Authorize] / RequireAuthorization(), or [AllowAnonymous] / AllowAnonymous() if it is meant to be public.",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "Every endpoint should state who may call it. ASP.NET Core endpoints are public unless something requires authorization.",
        helpLinkUri: Symbols.HelpLink(DiagnosticId));

    private static readonly ImmutableHashSet<string> MapMethods =
        ImmutableHashSet.Create("Map", "MapGet", "MapPost", "MapPut", "MapDelete", "MapPatch", "MapMethods");

    private static readonly ImmutableHashSet<string> ControllerRouteMethods =
        ImmutableHashSet.Create("MapControllers", "MapControllerRoute", "MapDefaultControllerRoute", "MapAreaControllerRoute");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();

        context.RegisterCompilationStartAction(start =>
        {
            var compilation = start.Compilation;
            var authorizeData = compilation.GetTypeByMetadataName("Microsoft.AspNetCore.Authorization.IAuthorizeData");
            var allowAnonymous = compilation.GetTypeByMetadataName("Microsoft.AspNetCore.Authorization.IAllowAnonymous");
            if (authorizeData is null || allowAnonymous is null)
                return;

            var known = new KnownTypes(compilation, authorizeData, allowAnonymous);

            // Scanned at most once per compilation, and only when an unprotected endpoint is found.
            var cancellation = start.CancellationToken;
            var global = new Lazy<GlobalProtection>(() => GlobalProtection.Scan(compilation, cancellation));

            if (known.ControllerAttribute is not null)
                start.RegisterSymbolAction(ctx => AnalyzeAction(ctx, known, global), SymbolKind.Method);

            if (known.EndpointRouteBuilderExtensions is not null)
                start.RegisterOperationAction(ctx => AnalyzeMinimalApi(ctx, known, global), OperationKind.Invocation);
        });
    }

    // ---------- Controllers ----------

    private static void AnalyzeAction(SymbolAnalysisContext context, KnownTypes known, Lazy<GlobalProtection> global)
    {
        var method = (IMethodSymbol)context.Symbol;
        var controller = method.ContainingType;

        if (!IsAction(method, known) || !IsController(controller, known))
            return;

        if (HasAuthAttribute(method, known) || TypeHasAttribute(controller, known.AuthorizeData) || TypeHasAttribute(controller, known.AllowAnonymous))
            return;

        if (global.Value.AllEndpoints || global.Value.AllControllers)
            return;

        context.ReportDiagnostic(Diagnostic.Create(Rule, method.Locations[0], $"{controller.Name}.{method.Name}"));
    }

    // Mirrors ASP.NET Core's DefaultApplicationModelProvider.IsAction.
    private static bool IsAction(IMethodSymbol method, KnownTypes known)
    {
        if (method.MethodKind != MethodKind.Ordinary || method.DeclaredAccessibility != Accessibility.Public ||
            method.IsStatic || method.IsAbstract || method.IsGenericMethod || method.IsImplicitlyDeclared)
            return false;

        if (known.NonAction is not null && MethodHasAttribute(method, known.NonAction))
            return false;

        // Overrides of object.ToString/Equals/GetHashCode are not actions.
        var root = method;
        while (root.OverriddenMethod is not null)
            root = root.OverriddenMethod;
        if (root.ContainingType.SpecialType == SpecialType.System_Object)
            return false;

        // IDisposable.Dispose() on a controller is not an action.
        return !(method.Name == "Dispose" && method.Parameters.Length == 0 &&
                 Symbols.IsOrInherits(method.ContainingType, known.Disposable));
    }

    // Mirrors ASP.NET Core's ControllerFeatureProvider.IsController.
    private static bool IsController(INamedTypeSymbol type, KnownTypes known)
    {
        if (type.TypeKind != TypeKind.Class || type.IsAbstract || type.IsGenericType || !IsPubliclyVisible(type))
            return false;

        if (known.NonController is not null && TypeHasAttribute(type, known.NonController))
            return false;

        return type.Name.EndsWith("Controller", StringComparison.Ordinal) ||
               TypeHasAttribute(type, known.ControllerAttribute!);
    }

    private static bool IsPubliclyVisible(INamedTypeSymbol type)
    {
        for (INamedTypeSymbol? t = type; t is not null; t = t.ContainingType)
        {
            if (t.DeclaredAccessibility != Accessibility.Public)
                return false;
        }

        return true;
    }

    // Authorization attributes are inherited from base controllers, like ASP.NET Core does.
    private static bool TypeHasAttribute(INamedTypeSymbol? type, INamedTypeSymbol attribute)
    {
        for (var t = type; t is not null; t = t.BaseType)
        {
            if (Symbols.HasAttribute(t, attribute))
                return true;
        }

        return false;
    }

    private static bool MethodHasAttribute(IMethodSymbol? method, INamedTypeSymbol attribute)
    {
        for (var m = method; m is not null; m = m.OverriddenMethod)
        {
            if (Symbols.HasAttribute(m, attribute))
                return true;
        }

        return false;
    }

    private static bool HasAuthAttribute(IMethodSymbol method, KnownTypes known) =>
        MethodHasAttribute(method, known.AuthorizeData) || MethodHasAttribute(method, known.AllowAnonymous);

    // ---------- Minimal APIs ----------

    private static void AnalyzeMinimalApi(OperationAnalysisContext context, KnownTypes known, Lazy<GlobalProtection> global)
    {
        var invocation = (IInvocationOperation)context.Operation;
        var method = invocation.TargetMethod;
        if (!MapMethods.Contains(method.Name) ||
            !SymbolEqualityComparer.Default.Equals(method.ContainingType, known.EndpointRouteBuilderExtensions) ||
            invocation.Arguments.Length < 2)
            return;

        // [Authorize] / [AllowAnonymous] on the handler lambda or method.
        var handler = HandlerMethod(invocation.Arguments[invocation.Arguments.Length - 1].Value);
        if (handler is not null && HasAuthAttribute(handler, known))
            return;

        // .RequireAuthorization() / .AllowAnonymous() later in the same fluent chain.
        IOperation top = invocation;
        while (NextInChain(top) is { } next)
        {
            if (IsAuthConvention(next.TargetMethod.Name))
                return;
            top = next;
        }

        // The endpoint builder is stored or passed on: it may be secured elsewhere, so don't guess.
        if (top.Parent is not IExpressionStatementOperation)
            return;

        if (!IsKnownUnprotected(invocation.Arguments[0].Value, known, context.CancellationToken, depth: 0))
            return;

        if (global.Value.AllEndpoints)
            return;

        var pattern = invocation.Arguments[1].Value.ConstantValue is { HasValue: true, Value: string p } ? $"(\"{p}\")" : "(...)";
        var location = invocation.Syntax is InvocationExpressionSyntax { Expression: MemberAccessExpressionSyntax member }
            ? member.Name.GetLocation()
            : invocation.Syntax.GetLocation();
        context.ReportDiagnostic(Diagnostic.Create(Rule, location, method.Name + pattern));
    }

    private static IMethodSymbol? HandlerMethod(IOperation value)
    {
        while (value is IConversionOperation conversion)
            value = conversion.Operand;
        if (value is IDelegateCreationOperation delegateCreation)
            value = delegateCreation.Target;

        return value switch
        {
            IAnonymousFunctionOperation lambda => lambda.Symbol,
            IMethodReferenceOperation reference => reference.Method,
            _ => null,
        };
    }

    // The invocation that takes `operation` as its receiver (`operation.Next()` or `Ext.Next(operation)`).
    private static IInvocationOperation? NextInChain(IOperation operation)
    {
        var parent = operation.Parent;
        while (parent is IConversionOperation)
        {
            operation = parent;
            parent = parent.Parent;
        }

        if (parent is IInvocationOperation instanceCall && instanceCall.Instance == operation)
            return instanceCall;

        if (parent is IArgumentOperation { Parent: IInvocationOperation extensionCall } argument &&
            extensionCall.TargetMethod.IsExtensionMethod && extensionCall.Arguments.Length > 0 &&
            extensionCall.Arguments[0] == argument)
            return extensionCall;

        return null;
    }

    private static bool IsAuthConvention(string name) => name is "RequireAuthorization" or "AllowAnonymous";

    /// <summary>
    /// True only when we can see the route builder has no authorization: the WebApplication itself,
    /// or a MapGroup(...) chain / local variable with no RequireAuthorization/AllowAnonymous.
    /// Anything we can't follow (a parameter, a field, a helper method) counts as "maybe protected".
    /// </summary>
    private static bool IsKnownUnprotected(IOperation receiver, KnownTypes known, CancellationToken cancellationToken, int depth)
    {
        while (receiver is IConversionOperation conversion)
            receiver = conversion.Operand;

        if (depth > 8)
            return false;

        if (known.WebApplication is not null && SymbolEqualityComparer.Default.Equals(receiver.Type, known.WebApplication))
            return true;

        switch (receiver)
        {
            case IInvocationOperation call when IsAuthConvention(call.TargetMethod.Name):
                return false;

            // app.MapGroup("/x") inherits the conventions of the builder it was created from.
            // Fluent conventions (WithTags, ...) return the same group they were called on.
            case IInvocationOperation call when call.TargetMethod.IsExtensionMethod && call.Arguments.Length > 0 &&
                                                (call.TargetMethod.Name == "MapGroup" || IsFluent(call.TargetMethod)):
                return IsKnownUnprotected(call.Arguments[0].Value, known, cancellationToken, depth + 1);

            case ILocalReferenceOperation local:
                return IsLocalUnprotected(local, known, cancellationToken, depth);

            default:
                return false;
        }
    }

    private static bool IsFluent(IMethodSymbol method) =>
        method.Parameters.Length > 0 &&
        (SymbolEqualityComparer.Default.Equals(method.ReturnType, method.Parameters[0].Type) ||
         method.OriginalDefinition.ReturnType is ITypeParameterSymbol);

    private static bool IsLocalUnprotected(ILocalReferenceOperation local, KnownTypes known, CancellationToken cancellationToken, int depth)
    {
        var model = local.SemanticModel;
        var declarator = local.Local.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax(cancellationToken) as VariableDeclaratorSyntax;
        if (model is null || declarator?.Initializer is null || declarator.SyntaxTree != model.SyntaxTree)
            return false;

        // `group.RequireAuthorization();` as a separate statement anywhere in the same method.
        var body = declarator.Ancestors().FirstOrDefault(n => n is BlockSyntax or CompilationUnitSyntax);
        if (body is not null)
        {
            foreach (var call in body.DescendantNodes().OfType<InvocationExpressionSyntax>())
            {
                if (call.Expression is MemberAccessExpressionSyntax { Name.Identifier.ValueText: var name, Expression: var target } &&
                    IsAuthConvention(name) &&
                    SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(target, cancellationToken).Symbol, local.Local))
                    return false;
            }
        }

        var initializer = model.GetOperation(declarator.Initializer.Value, cancellationToken);
        return initializer is not null && IsKnownUnprotected(initializer, known, cancellationToken, depth + 1);
    }

    // ---------- Global protection ----------

    private sealed class GlobalProtection
    {
        /// <summary>A fallback policy: every endpoint without its own metadata requires authorization.</summary>
        public bool AllEndpoints { get; private set; }

        /// <summary>A global AuthorizeFilter, or MapControllers().RequireAuthorization().</summary>
        public bool AllControllers { get; private set; }

        // shortcut: syntax-only match on well-known API names (no semantic model); a user type with the same names could silence the rule.
        public static GlobalProtection Scan(Compilation compilation, CancellationToken cancellationToken)
        {
            var result = new GlobalProtection();
            foreach (var tree in compilation.SyntaxTrees)
            {
                var text = tree.GetText(cancellationToken).ToString();
                if (text.IndexOf("FallbackPolicy", StringComparison.Ordinal) < 0 &&
                    text.IndexOf("AuthorizeFilter", StringComparison.Ordinal) < 0 &&
                    text.IndexOf("RequireAuthorization", StringComparison.Ordinal) < 0)
                    continue;

                foreach (var node in tree.GetRoot(cancellationToken).DescendantNodes())
                {
                    switch (node)
                    {
                        // options.FallbackPolicy = ...;   (not null)
                        case AssignmentExpressionSyntax assignment
                            when NameOf(assignment.Left) == "FallbackPolicy" && !assignment.Right.IsKind(SyntaxKind.NullLiteralExpression):
                            result.AllEndpoints = true;
                            break;

                        // AddAuthorizationBuilder().SetFallbackPolicy(...)
                        case InvocationExpressionSyntax call
                            when NameOf(call.Expression) == "SetFallbackPolicy" &&
                                 call.ArgumentList.Arguments.FirstOrDefault()?.Expression.IsKind(SyntaxKind.NullLiteralExpression) == false:
                            result.AllEndpoints = true;
                            break;

                        // app.MapControllers().RequireAuthorization()
                        case InvocationExpressionSyntax { Expression: MemberAccessExpressionSyntax { Expression: InvocationExpressionSyntax receiver } } call
                            when NameOf(call.Expression) == "RequireAuthorization" && ControllerRouteMethods.Contains(NameOf(receiver.Expression) ?? ""):
                            result.AllControllers = true;
                            break;

                        // options.Filters.Add(new AuthorizeFilter(...))
                        case ObjectCreationExpressionSyntax creation when NameOf(creation.Type) == "AuthorizeFilter":
                            result.AllControllers = true;
                            break;
                    }
                }
            }

            return result;
        }

        private static string? NameOf(SyntaxNode node) => node switch
        {
            MemberAccessExpressionSyntax member => member.Name.Identifier.ValueText,
            QualifiedNameSyntax qualified => qualified.Right.Identifier.ValueText,
            SimpleNameSyntax simple => simple.Identifier.ValueText,
            _ => null,
        };
    }

    private sealed class KnownTypes(Compilation compilation, INamedTypeSymbol authorizeData, INamedTypeSymbol allowAnonymous)
    {
        public INamedTypeSymbol AuthorizeData { get; } = authorizeData;
        public INamedTypeSymbol AllowAnonymous { get; } = allowAnonymous;
        public INamedTypeSymbol Disposable { get; } = compilation.GetSpecialType(SpecialType.System_IDisposable);
        public INamedTypeSymbol? ControllerAttribute { get; } = compilation.GetTypeByMetadataName("Microsoft.AspNetCore.Mvc.ControllerAttribute");
        public INamedTypeSymbol? NonController { get; } = compilation.GetTypeByMetadataName("Microsoft.AspNetCore.Mvc.NonControllerAttribute");
        public INamedTypeSymbol? NonAction { get; } = compilation.GetTypeByMetadataName("Microsoft.AspNetCore.Mvc.NonActionAttribute");
        public INamedTypeSymbol? EndpointRouteBuilderExtensions { get; } = compilation.GetTypeByMetadataName("Microsoft.AspNetCore.Builder.EndpointRouteBuilderExtensions");
        public INamedTypeSymbol? WebApplication { get; } = compilation.GetTypeByMetadataName("Microsoft.AspNetCore.Builder.WebApplication");
    }
}
