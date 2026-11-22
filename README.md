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
- the developer error page left on in production,
- a login cookie that JavaScript can read or that travels over plain HTTP.

This package flags them in the editor, before the code is committed. It is built to **avoid false alarms**: when it can't be sure (for example, the app protects every endpoint globally), it stays silent.

## 2. Install

```bash
dotnet add package DotnetSecurityAnalyzers
```

That's all. Warnings appear in your IDE and in `dotnet build`. The package adds **nothing** to your app at runtime. It only runs inside the compiler.

## 3. Rules

| ID | What it finds | Maps to |
|----|---------------|---------|
| [DSA001](docs/rules/DSA001.md) | Controller action or minimal API endpoint with no authorization (understands route groups and app-wide fallback policies) | OWASP A01, CWE-862 |
| [DSA002](docs/rules/DSA002.md) | CORS policy that allows every origin **and** credentials | OWASP A05, CWE-942 |
| [DSA003](docs/rules/DSA003.md) | JWT signing key (`SymmetricSecurityKey`) hardcoded in source, also through variables | OWASP A02, CWE-321 |
| [DSA004](docs/rules/DSA004.md) | `UseDeveloperExceptionPage()` not limited to Development | OWASP A05, CWE-209 |
| [DSA005](docs/rules/DSA005.md) | Auth/session/antiforgery cookie with `HttpOnly = false` or `SecurePolicy = None` | OWASP A05, CWE-614, CWE-1004 |

Each rule page explains the risk, shows the fix, and lists the rule's known limits.

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

## 6. How the repo is organised

- [src/DotnetSecurityAnalyzers/](src/DotnetSecurityAnalyzers/): the analyzers (one file per rule), packed into the NuGet package. Rule release tracking: [Unshipped](src/DotnetSecurityAnalyzers/AnalyzerReleases.Unshipped.md) / [Shipped](src/DotnetSecurityAnalyzers/AnalyzerReleases.Shipped.md).
- [tests/DotnetSecurityAnalyzers.Tests/](tests/DotnetSecurityAnalyzers.Tests/): tests, with code that must warn and code that must not.
- [samples/VulnerableApp/](samples/VulnerableApp/): a deliberately insecure demo app. Building it shows every rule firing.
- [docs/rules/](docs/rules/): one page per rule.
- [eng/realworld/](eng/realworld/): build hook used by the *Real-world check* workflow, which runs the analyzers on popular open-source ASP.NET Core apps to catch false positives.

## 7. Build from source

Needs the .NET 8 SDK (`global.json` pins it).

```bash
dotnet restore --locked-mode   # exact package versions from packages.lock.json
dotnet build
dotnet test
dotnet build samples/VulnerableApp   # see the warnings
```

## 8. Contributing

Issues and pull requests are welcome. False-positive reports are fixed first. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to build, test and add a rule.

## 9. Security

Found a vulnerability in this project? Please report it privately. See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
