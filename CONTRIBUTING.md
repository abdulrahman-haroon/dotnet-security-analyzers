# Contributing

Thanks for helping. Issues and pull requests are welcome.

## Quick start

Needs the .NET 8 SDK (`global.json` pins it).

```bash
dotnet restore --locked-mode
dotnet build
dotnet test
dotnet build samples/VulnerableApp   # see every rule fire
```

## Reporting

- **A rule warned about safe code?** Open a *False positive* issue. These are fixed first.
- **A rule missed something?** Open a *Missed issue* issue.
- **A vulnerability in this project itself?** Report it privately, see [SECURITY.md](SECURITY.md).

## Adding a rule

A rule is only worth adding if it finds a **real gap**. First check that Microsoft's built-in rules don't already catch the pattern: add `<AnalysisModeSecurity>All</AnalysisModeSecurity>` to a test project and build it.

Each rule needs:
1. **The analyzer** in `src/DotnetSecurityAnalyzers/`: next free ID `DSAxxx`, category `Security`, severity Warning, help link via `Symbols.HelpLink`. It must do nothing in projects that don't use the relevant API, and **stay silent when it isn't sure**.
2. **Tests** in `tests/`: code that must warn and code that must not, including the tricky safe cases.
3. **A doc page** `docs/rules/DSAxxx.md`: what it finds, why it matters, example, fix, what isn't flagged, limits, OWASP + CWE.
4. **A row** in `src/DotnetSecurityAnalyzers/AnalyzerReleases.Unshipped.md` and in the README rules table.
5. **A demo** in `samples/VulnerableApp` (add the ID to `WarningsNotAsErrors` there).

## Rules for this repo

- Never commit real secrets. Test values must look obviously fake (`FAKE-...`).
- Package versions live in `Directory.Packages.props`. After changing one, run `dotnet restore` to update the `packages.lock.json` files.
- The build treats warnings as errors and fails on packages with known vulnerabilities. Fix them, don't suppress them.
- Roslyn (`Microsoft.CodeAnalysis.*`) is pinned on purpose: its version is the oldest compiler the analyzer can run in.

## Checking for false positives on real apps

The **Real-world check** workflow (Actions tab → Run workflow) builds several popular open-source ASP.NET Core apps with the analyzer and lists every warning. Run it before and after changing a rule.

## License

By contributing, you agree your contribution is licensed under the [MIT License](LICENSE).
