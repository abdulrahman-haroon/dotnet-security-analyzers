using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;

namespace DotnetSecurityAnalyzers;

/// <summary>
/// DSA006: a secret written into appsettings*.json. The files reach the analyzer as AdditionalFiles,
/// added by the package's build/DotnetSecurityAnalyzers.props.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class AppSettingsSecretAnalyzer : DiagnosticAnalyzer
{
    public const string DiagnosticId = "DSA006";

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId,
        title: "Secret stored in appsettings",
        messageFormat: "'{0}' holds a secret in a settings file that is normally committed to source control. Move it to user-secrets or a secret store, then rotate it.",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "Passwords, API keys and signing keys in appsettings.json end up in git history and in every deployment package.",
        helpLinkUri: Symbols.HelpLink(DiagnosticId),
        customTags: WellKnownDiagnosticTags.CompilationEnd);

    private static readonly string[] SecretKeySuffixes =
        { "password", "secret", "secretkey", "apikey", "signingkey", "accountkey", "privatekey", "accesskey" };

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();

        context.RegisterCompilationAction(ctx =>
        {
            if (Symbols.IsTestProject(ctx.Compilation))
                return;

            foreach (var file in ctx.Options.AdditionalFiles)
            {
                if (!IsCheckedSettingsFile(Path.GetFileName(file.Path)) ||
                    file.GetText(ctx.CancellationToken) is not { } text)
                    continue;

                foreach (var (path, value, span) in StringValues(text.ToString()))
                {
                    if (!IsSecret(path, value))
                        continue;

                    var location = Location.Create(file.Path, span, text.Lines.GetLinePositionSpan(span));
                    ctx.ReportDiagnostic(Diagnostic.Create(Rule, location, string.Join(":", path)));
                }
            }
        });
    }

    // appsettings.Development.json is skipped: throwaway local database passwords there are normal.
    private static bool IsCheckedSettingsFile(string name) =>
        name.StartsWith("appsettings", StringComparison.OrdinalIgnoreCase) &&
        name.EndsWith(".json", StringComparison.OrdinalIgnoreCase) &&
        name.IndexOf(".Development.", StringComparison.OrdinalIgnoreCase) < 0;

    private static bool IsSecret(string[] path, string value)
    {
        if (Secrets.HasConnectionStringPassword(value))
            return true;

        // Anything with spaces, a URL or a path is a label or an address, not a key.
        if (path.Length == 0 || Secrets.IsPlaceholder(value) || value.Length < 4 || value.Any(char.IsWhiteSpace) ||
            value.StartsWith("/", StringComparison.Ordinal) || value.IndexOf("://", StringComparison.Ordinal) >= 0 ||
            bool.TryParse(value, out _))
            return false;

        var key = path[path.Length - 1].Replace("_", "").Replace("-", "");
        return SecretKeySuffixes.Any(s => key.EndsWith(s, StringComparison.OrdinalIgnoreCase)) ||
               (key.Equals("key", StringComparison.OrdinalIgnoreCase) &&
                path.Take(path.Length - 1).Any(p => p.IndexOf("jwt", StringComparison.OrdinalIgnoreCase) >= 0));
    }

    // A tiny JSON walker (analyzers can't ship dependencies). It yields every string value with its key
    // path, tolerates comments and trailing commas, and never throws on malformed input.
    private static IEnumerable<(string[] Path, string Value, TextSpan Span)> StringValues(string json)
    {
        var parents = new Stack<string?>();
        string? key = null;
        var i = 0;
        while ((i = SkipTrivia(json, i)) < json.Length)
        {
            var c = json[i];
            if (c == '"')
            {
                var start = i;
                var text = ReadString(json, ref i);
                var next = SkipTrivia(json, i);
                if (next < json.Length && json[next] == ':')
                    key = text;
                else
                    yield return (parents.Reverse().Concat(new[] { key }).OfType<string>().ToArray(), text, TextSpan.FromBounds(start, i));

                continue;
            }

            if (c is '{' or '[')
            {
                parents.Push(key);
                key = null;
            }
            else if (c is '}' or ']')
            {
                key = null;
                if (parents.Count > 0)
                    parents.Pop();
            }

            i++;
        }
    }

    // Starts on the opening quote; leaves `i` just after the closing one.
    private static string ReadString(string json, ref int i)
    {
        var result = new StringBuilder();
        for (i++; i < json.Length && json[i] != '"'; i++)
        {
            // shortcut: \n, \uXXXX etc. are not decoded, only the escaped character is kept; enough to spot secrets.
            if (json[i] == '\\' && i + 1 < json.Length)
                i++;
            result.Append(json[i]);
        }

        if (i < json.Length)
            i++;
        return result.ToString();
    }

    // Skips whitespace and // or /* */ comments.
    private static int SkipTrivia(string json, int i)
    {
        while (i < json.Length)
        {
            if (char.IsWhiteSpace(json[i]))
            {
                i++;
            }
            else if (string.CompareOrdinal(json, i, "//", 0, 2) == 0)
            {
                var end = json.IndexOf('\n', i);
                i = end < 0 ? json.Length : end + 1;
            }
            else if (string.CompareOrdinal(json, i, "/*", 0, 2) == 0)
            {
                var end = json.IndexOf("*/", i + 2, StringComparison.Ordinal);
                i = end < 0 ? json.Length : end + 2;
            }
            else
            {
                break;
            }
        }

        return i;
    }
}
