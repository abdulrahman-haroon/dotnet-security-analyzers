# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately through GitHub: go to the **Security** tab of this repository and click **Report a vulnerability**. You will get a reply within 7 days.

Examples of what counts:
- a way to make the analyzer run attacker-controlled code during a build,
- a problem in the published NuGet package or the build pipeline.

A rule that misses a vulnerable pattern (false negative) or flags safe code (false positive) is **not** a security issue. Please open a normal issue for those.

## Supported versions

Only the latest released version gets fixes.
