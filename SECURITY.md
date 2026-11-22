# Security Policy

[README](README.md) · [Contributing](CONTRIBUTING.md)

## Supported versions

| Version | Supported |
|---|---|
| 1.2.x | ✅ |
| < 1.2 | ❌ |

## What counts as a vulnerability in BUGX

BUGX's main security promise is that it **does not send traffic outside the
configured scope** and **does not run unsafe tool options**. Please report
privately if you find, for example:

- a **scope bypass**: a target or discovered asset that should be *out of scope*
  or *unverified* but is treated as in scope (IDNA tricks, trailing dots,
  userinfo, encoded dot-segments, redirects, wildcard edge cases, …);
- a way for a tool to run **without** the authorization gate, confirmation, or
  request policy (required headers, rate limit, `automated_scanning: false`);
- **command or argument injection** through targets, profile values or tool output;
- unsafe tool options getting through (e.g. SQLmap `--dump` / `--os-shell`,
  intrusive Nuclei tags);
- **XSS or injection in generated reports** from scanner output;
- secrets (headers, tokens) written to saved commands, logs or reports in clear text.

Out of scope for this policy: vulnerabilities in the third-party tools that BUGX
drives (report those to their projects), and findings that need an attacker who
can already edit your local profile or config files.

## How to report

**Please do not open a public issue.**

1. Use GitHub's **private vulnerability reporting**: the repository's
   **Security** tab → **Report a vulnerability**.
2. Include the BUGX version (`bugx version`), OS, Python version, a minimal
   profile (use `example.com`), the exact input, and the expected vs. actual
   result.

Please don't include real targets, real scan data or credentials in your report.

## What to expect

This is a single-maintainer open-source project, so responses are best effort:

- acknowledgement within about 7 days;
- a fix or mitigation plan once the issue is confirmed;
- credit in the changelog, if you'd like it.

## Responsible use

BUGX is for **authorized** testing only. Reports about BUGX being used against
systems without permission should go to the affected organisation and the
relevant platform, not to this repository.
