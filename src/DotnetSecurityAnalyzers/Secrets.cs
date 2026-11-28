using System;
using System.Linq;
using System.Text.RegularExpressions;

namespace DotnetSecurityAnalyzers;

/// <summary>Shared by DSA006 and DSA007: is this value a real secret, or a placeholder?</summary>
internal static class Secrets
{
    private static readonly Regex ConnectionStringPassword = new(
        @"(?:^|;)\s*(?:password|pwd)\s*=\s*(?<value>[^;]*)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(1));

    private static readonly string[] PlaceholderWords =
        { "change", "replace", "your", "placeholder", "example", "xxx", "****", "todo", "secret-here", "goes here" };

    public static bool IsPlaceholder(string value)
    {
        var trimmed = value.Trim().Trim('\'', '"');
        return trimmed.Length == 0 ||
               "<{[$#%_*".IndexOf(trimmed[0]) >= 0 ||
               PlaceholderWords.Any(w => trimmed.IndexOf(w, StringComparison.OrdinalIgnoreCase) >= 0);
    }

    public static bool HasConnectionStringPassword(string value) =>
        ConnectionStringPassword.Matches(value).Cast<Match>().Any(m => !IsPlaceholder(m.Groups["value"].Value));
}
