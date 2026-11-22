# dotnet-security-analyzers

[![NuGet](https://img.shields.io/nuget/v/DotnetSecurityAnalyzers.svg)](https://www.nuget.org/packages/DotnetSecurityAnalyzers)
[![Downloads](https://img.shields.io/nuget/dt/DotnetSecurityAnalyzers.svg)](https://www.nuget.org/packages/DotnetSecurityAnalyzers)
[![CI](https://github.com/abdulrahman-haroon/dotnet-security-analyzers/actions/workflows/ci.yml/badge.svg)](https://github.com/abdulrahman-haroon/dotnet-security-analyzers/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Roslyn analyzers that catch **ASP.NET Core security mistakes as you type**, in Visual Studio, Rider, VS Code and `dotnet build`. Free, open source, MIT.

```
Program.cs(34,5): warning DSA001: 'MapPost("/api/transfer")' has no authorization, so anyone can call it.
```

---

## 1. What problem does it solve?

Some security bugs are easy to write and easy to miss in code review:

- an endpoint with no `[Authorize]`, so anyone can call it,
- a CORS policy that lets **any website** make logged-in requests to your API,
- a JWT signing key pasted into the code, so anyone can forge tokens,
- debug features left on in production (error pages, sensitive-data logging, detailed errors),
- a login cookie that JavaScript can read or that travels over plain HTTP.

This package flags them in the editor, before the code is committed, and **fixes most of them in one click** (lightbulb / `Ctrl+.`). It is built to **avoid false alarms**: when it can't be sure (for example, the app protects every endpoint globally), it stays silent.

## 2. Install

```bash
dotnet add package DotnetSecurityAnalyzers
```

That's all. Warnings appear in your IDE and in `dotnet build`. The package adds **nothing** to your app at runtime. It only runs inside the compiler.

## 3. Rules

| ID | What it finds | One-click fix | Maps to |
|----|---------------|---------------|---------|
| [DSA001](docs/rules/DSA001.md) | Controller action or minimal API endpoint with no authorization (understands route groups and app-wide fallback policies) | Add `[Authorize]` / `.RequireAuthorization()`, or `[AllowAnonymous]` / `.AllowAnonymous()` | OWASP A01, CWE-862 |
| [DSA002](docs/rules/DSA002.md) | CORS policy that allows every origin **and** credentials | Replace with `WithOrigins(...)` | OWASP A05, CWE-942 |
| [DSA003](docs/rules/DSA003.md) | JWT signing key (`SymmetricSecurityKey`) hardcoded in source, also through variables | — (needs a human: move it to a secret store) | OWASP A02, CWE-321 |
| [DSA004](docs/rules/DSA004.md) | Debug features left on in production: developer exception page, migrations endpoint, EF sensitive-data logging, detailed errors (SignalR, gRPC, Blazor), `ShowPII` | Wrap in `if (IsDevelopment())`, or remove it | OWASP A05, CWE-209, CWE-532 |
| [DSA005](docs/rules/DSA005.md) | Auth/session/antiforgery cookie with `HttpOnly = false` or `SecurePolicy = None` | Set the safe value | OWASP A05, CWE-614, CWE-1004 |

Each rule page explains the risk, shows the fix, and lists the rule's known limits. Every fix also works as **Fix all** across a document, project or solution.

### Tested on real apps

Before each release, the analyzers run against popular open-source ASP.NET Core apps (the [Real-world check](.github/workflows/realworld.yml) workflow, pinned commits). Latest results:

| App | Warnings | What they were |
|-----|----------|----------------|
| [eShopOnWeb](https://github.com/dotnet-architecture/eShopOnWeb) (Microsoft) | 3 | JWT signing key hardcoded as a constant (×2); login endpoint not marked `[AllowAnonymous]` |
| [fullstackhero](https://github.com/fullstackhero/dotnet-starter-kit) | 1 | An `AllowAll` setting turns on any-origin CORS **with credentials** |
| [nopCommerce](https://github.com/nopSolutions/nopCommerce) | 10 | A config flag can show the developer exception page in production; 9 public endpoints (install wizard, error page, keep-alive, scheduled-task runner) not marked `[AllowAnonymous]` |
| [CleanArchitecture](https://github.com/jasontaylordev/CleanArchitecture) | 0 | — |

**0 false positives** in about 1,300 endpoints. Every warning is either a real security risk or a public endpoint that doesn't say it's public, which is what DSA001 asks you to make explicit.

**Speed.** Time the compiler spent inside this package, as reported by the compiler itself (`-p:ReportAnalyzer=true`):

| App | Our analyzers | All analyzers in that build | Full build |
|-----|---------------|-----------------------------|------------|
| CleanArchitecture | 0.07 s | 0.8 s | ~10 s |
| eShopOnWeb | 0.12 s | 3.0 s | ~20 s |
| fullstackhero | 0.10 s | 88.8 s | ~60 s |
| nopCommerce | 0.28 s | 9.3 s | ~50 s |

That is well under 1% of build time.

## 4. Turn on Microsoft's built-in security rules too

The .NET SDK already ships many security rules (SQL injection, weak crypto, insecure deserialization, disabled certificate or token validation, and more), but **most are switched off by default**. This package does not repeat them. Turn them on by adding one line to your `.csproj`:

```xml
<PropertyGroup>
  <AnalysisModeSecurity>All</AnalysisModeSecurity>
</PropertyGroup>
```

Some of the rules this enables:

| Rule | Finds |
|------|-------|
| CA2100, CA3001 | SQL built from strings / user input |
| CA5350, CA5351 | Weak or broken crypto (MD5, SHA1, DES, ...) |
| CA5394 | `System.Random` used for security |
| CA2300, CA2326 | `BinaryFormatter`, unsafe `TypeNameHandling` |
| CA5359 | Certificate validation turned off |
| CA5391 | MVC action without antiforgery validation |
| CA5404 | JWT token validation checks turned off |

For deeper checks (tracking user input across many methods), add [GitHub CodeQL](https://codeql.github.com/), which is free for public repositories.

## 5. Change a rule's severity or turn it off

In `.editorconfig`:

```ini
[*.cs]
dotnet_diagnostic.DSA001.severity = error   # fail the build
dotnet_diagnostic.DSA002.severity = none    # turn off
```

For one line of code: `#pragma warning disable DSA001`, together with a comment saying why.

**Test projects are skipped automatically.** Projects that reference xUnit, NUnit, MSTest, TUnit or `Microsoft.AspNetCore.Mvc.Testing` get no DSA warnings, because fake keys and throwaway endpoints are normal there.

## 6. See findings in GitHub's Security tab (optional)

You can send the warnings to **Security → Code scanning** on GitHub, where they show up as alerts on pull requests and stay tracked until fixed. Code scanning is free for public repositories; private repositories need GitHub Code Security.

**Step 1.** Add this to a `Directory.Build.props` at the root of your repo. It makes the compiler write one SARIF file per project, only when building in GitHub Actions:

```xml
<Project>
  <PropertyGroup Condition="'$(GITHUB_ACTIONS)' == 'true'">
    <ErrorLog>$(MSBuildThisFileDirectory)sarif/$(MSBuildProjectName).sarif,version=2.1</ErrorLog>
  </PropertyGroup>
</Project>
```

**Step 2.** Add a workflow (or these steps to your existing one):

```yaml
permissions:
  contents: read
  security-events: write   # lets the job upload results to code scanning

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7          # pin actions to a commit SHA in real use
      - uses: actions/setup-dotnet@v6
      - run: mkdir -p sarif                # the compiler won't create the folder itself
      - run: dotnet build

      # GitHub rejects several results files from the same tool in one upload,
      # so give each project its own category.
      - name: One code-scanning category per project
        run: |
          for f in sarif/*.sarif; do
            jq --arg id "dotnet-build/$(basename "$f" .sarif)/" '.runs[].automationDetails = {id: $id}' "$f" > "$f.tmp"
            mv "$f.tmp" "$f"
          done

      - uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: sarif
```

The SARIF files contain **all** compiler warnings, not just DSA ones, so other analyzer warnings in your build will appear in code scanning too.

## 7. How the repo is organised

- [src/DotnetSecurityAnalyzers/](src/DotnetSecurityAnalyzers/): the analyzers (one file per rule). Rule release tracking: [Unshipped](src/DotnetSecurityAnalyzers/AnalyzerReleases.Unshipped.md) / [Shipped](src/DotnetSecurityAnalyzers/AnalyzerReleases.Shipped.md).
- [src/DotnetSecurityAnalyzers.CodeFixes/](src/DotnetSecurityAnalyzers.CodeFixes/): the one-click fixes (one file per rule).
- [src/DotnetSecurityAnalyzers.Package/](src/DotnetSecurityAnalyzers.Package/): builds the single NuGet package containing both.
- [tests/DotnetSecurityAnalyzers.Tests/](tests/DotnetSecurityAnalyzers.Tests/): tests, with code that must warn and code that must not.
- [samples/VulnerableApp/](samples/VulnerableApp/): a deliberately insecure demo app. Building it shows every rule firing.
- [docs/rules/](docs/rules/): one page per rule.
- [eng/realworld/](eng/realworld/): build hook used by the *Real-world check* workflow, which runs the analyzers on popular open-source ASP.NET Core apps to catch false positives.

## 8. Build from source

Needs the .NET 8 SDK (`global.json` pins it).

```bash
dotnet restore --locked-mode   # exact package versions from packages.lock.json
dotnet build
dotnet test
dotnet build samples/VulnerableApp   # see the warnings
```

## 9. Contributing

Issues and pull requests are welcome. False-positive reports are fixed first. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to build, test and add a rule.

## 10. Security

Found a vulnerability in this project? Please report it privately. See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
