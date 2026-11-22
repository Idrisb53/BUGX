# Configuration

[← README](../README.md) · [Installation](INSTALLATION.md) · **Configuration** · [Usage](USAGE.md) · [Modules](MODULES.md) · [Architecture](ARCHITECTURE.md) · [Troubleshooting](TROUBLESHOOTING.md)

---

BUGX has three layers of configuration:

| Layer | File | Purpose |
|---|---|---|
| Environment | `BUGX_HOME`, `BUGX_OUTPUT_DIR` | Where config is read from and results are written to |
| Global settings | `config/bugx.yaml` | Timeouts, default rate limits, wordlists, Nuclei templates, Playwright MCP, tool paths |
| Program profile | `config/programs/<platform>/<name>.yaml` | Program identity, authorization, **scope**, request **policy** |

- [Environment variables](#environment-variables)
- [Global settings: `config/bugx.yaml`](#global-settings-configbugxyaml)
- [Program profiles](#program-profiles)
- [Request policy](#request-policy)
- [Scope matching rules](#scope-matching-rules)
- [Redirect handling](#redirect-handling)
- [Validating a profile](#validating-a-profile)

---

## Environment variables

| Variable | Default | Effect |
|---|---|---|
| `BUGX_HOME` | The source checkout (editable install), else the current directory | Project root that contains `config/` |
| `BUGX_OUTPUT_DIR` | `$BUGX_HOME/output` | Where scans, findings, evidence, reports and logs are written |

BUGX does not read API keys from the environment. Tools that need credentials
(e.g. Subfinder provider keys, Cloudlist provider config) use **their own**
config files. See [`.env.example`](../.env.example).

## Global settings: `config/bugx.yaml`

Values here are merged over the built-in defaults in
`src/bugx/core/config.py`. Per-program limits belong in the profile, not here.

```yaml
defaults:
  timeout: 600          # seconds per tool run (tools may override)
  rate_limit: 5         # requests/second when a profile has no policy
  concurrency: 5
  version_timeout: 20

wordlists:
  directories:          # first existing file is used (FFUF, Feroxbuster)
    - /usr/share/seclists/Discovery/Web-Content/common.txt
    - /usr/share/wordlists/dirb/common.txt
  api_routes: ""        # Kiterunner .kite or .txt routes file

nuclei:                 # explicit SAFE template selection
  templates: []         # optional explicit template paths (overrides tags)
  tags: [exposure, misconfig, tech, ssl]
  exclude_tags: [dos, fuzz, fuzzing, intrusive, bruteforce, brute-force,
                 default-login, rce, sqli, osint, token-spray]
  severity: [info, low, medium, high, critical]

semgrep:
  config: p/security-audit

playwright_mcp:
  command: [npx, -y, "@playwright/mcp@0.0.86"]
  executable_path: ""   # empty = auto-detect chromium/chrome/edge
  headless: true

tools: {}               # per-tool overrides, see below
```

### Per-tool overrides

```yaml
tools:
  nuclei:
    path: /opt/nuclei/nuclei     # custom binary location
    timeout: 3600                # override defaults.timeout for this tool
  ffuf:
    path: C:\tools\ffuf.exe      # Windows example
  cloudlist:
    provider_config: ~/.config/cloudlist/provider-config.yaml
```

## Program profiles

Profiles live in `config/programs/<platform>/<name>.yaml`, where `<platform>` is
one of `hackerone`, `bugcrowd`, `intigriti`, `yeswehack` or `custom`.

- Create a profile from the interactive workflow (*Configure new program profile*).
  It asks for the name, target URL, policy URL and **one** in-scope asset.
- Or copy [`docs/examples/example-profile.yaml`](examples/example-profile.yaml)
  and edit it.
- BUGX **never edits or overwrites** an existing profile. A new profile with the
  same name gets a `-2`, `-3`, … suffix.
- `config/programs/**` is **gitignored**. Your real profiles stay local.

### Full example (example.com is a reserved demo domain)

```yaml
program:
  id: example-custom              # unique across all profiles
  name: Example
  platform: custom                # hackerone | bugcrowd | intigriti | yeswehack | custom
  program_url: https://www.example.com      # suggested session target
  policy_url: https://www.example.com/security-policy

authorization:
  user_confirmed: true            # BOTH must be true, or everything is blocked
  policy_reviewed: true
  confirmation_date: '2026-11-21'
  evidence_url: https://www.example.com/security-policy

scope:
  assets:                         # ONLY eligible assets listed here can be tested
  - {type: domain, value: example.com,    match: exact,    eligible: true}
  - {type: domain, value: '*.example.com', match: wildcard, eligible: true}
  - {type: url,    value: 'https://api.example.com/v1/*', match: exact, eligible: true}
  excluded_assets:                # exclusions ALWAYS win over assets
  - {type: domain, value: admin.example.com, match: exact}
  - {type: url,    value: 'https://api.example.com/v1/private/*', match: exact}

policy:                           # optional request rules (see below)
  required_headers:
    X-HackerOne-Research: your_username
  user_agent: ''
  rate_limit: 2
  concurrency: 2
  automated_scanning: false
```

### Field reference

| Field | Required | Notes |
|---|---|---|
| `program.id` | yes | Used for the output folder name (`output/<module>/<id>/`) |
| `program.name`, `program.platform` | yes | Platform must match the folder |
| `program.program_url` | yes | Its host is offered as the session target **if it is in scope**. Do not use the platform's program page (e.g. `hackerone.com/...`) here |
| `program.policy_url` | yes | Shown during scope review |
| `authorization.user_confirmed`, `policy_reviewed` | yes | Must both be `true` |
| `scope.assets[]` | yes | `type`: `domain` or `url`. `match`: `exact` or `wildcard`. `eligible: true` is required to test it |
| `scope.excluded_assets[]` | no | Same shape, without `eligible` |
| `policy` | no | See below |

## Request policy

Applied by the execution engine to **every** tool, the JS collector, the
validation replay and the browser.

| Key | Effect |
|---|---|
| `required_headers` | Added to every request. **Tools that cannot send custom headers** (Nikto, LinkFinder, SecretFinder) **are blocked** when this is set |
| `user_agent` | Overrides the User-Agent where the tool supports it |
| `rate_limit` | Requests/second passed to each tool's rate-limit flag (falls back to `defaults.rate_limit`) |
| `concurrency` | Threads/concurrency flag |
| `automated_scanning` | `false` → every vulnerability-analysis scanner is blocked. `true` → allowed after a typed `YES`. Omitted → allowed after `YES`, with a warning to check the policy |

Header values are redacted from the commands saved in scan records.

## Scope matching rules

Implemented in `src/bugx/core/scope.py` (Scope Engine v2.0) and wrapped by
`core/authorization.py` (`ScopeGate`) for every tool input and every discovered
asset.

| Rule | Example (asset → target) |
|---|---|
| `domain` + `exact` matches that host only (any port) | `example.com` → `example.com` ✓, `www.example.com` ✗ |
| `domain` + `wildcard` (`*.x`) matches subdomains, **not** the apex | `*.example.com` → `a.example.com` ✓, `example.com` ✗ |
| `url` assets must match scheme, host, port and path. A trailing `/*` means the path and everything below | `https://api.example.com/v1/*` → `https://api.example.com/v1/users` ✓, `http://api.example.com/v1/users` ✗ |
| Exclusions are checked first | `admin.example.com` → **out of scope** |
| Hostnames are IDNA- and lower-cased, and trailing dots are removed | `EXAMPLE.COM.` = `example.com` |
| Rejected input | IP addresses, userinfo (`a@b`), dot-segments (`/../`, `%2e%2e`), bad ports, non-HTTP schemes → **unverified** |
| Anything not matched | **unverified** → never tested |

Each asset gets one result: **in_scope** (may be tested), **out_of_scope**
(recorded, never tested) or **unverified** (recorded, never tested). The engine
**fails closed**: errors, invalid profiles and unknown states all block.

## Redirect handling

- httpx does not follow redirects. The `Location` is re-checked and recorded.
- The JavaScript collector and the Safe Validation replay follow a redirect only
  if the new URL is in scope.
- Browser inspection does a scope-checked preflight (server redirects),
  re-checks the final page URL (client redirects) and leaves out-of-scope pages
  immediately.

## Validating a profile

```bash
bugx programs                                              # lists profiles; invalid ones are flagged
bugx scope-check www.example.com docs/examples/example-profile.yaml     # passes
bugx scope-check admin.example.com docs/examples/example-profile.yaml   # blocked: excluded
```

`scope-check` exits with `0` when the target is allowed and `1` when it is blocked.

---

Next: [Usage →](USAGE.md)
