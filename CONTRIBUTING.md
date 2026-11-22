# Contributing to BUGX

Thanks for your interest in improving BUGX! This guide explains how to set up a
development environment and what a good contribution looks like.

[README](README.md) · [Architecture](docs/ARCHITECTURE.md) · [Security policy](SECURITY.md)

## Ground rules

1. **Safety first.** BUGX exists to keep testing inside authorized scope. Changes
   that weaken the Scope Engine, the authorization gate, the request policy or the
   confirmation prompts will not be merged.
2. **No live targets in tests or examples.** Use `example.com` (reserved) or the
   localhost mock server in `tests/e2e/`. Never commit real program profiles, scan
   output, tokens or cookies.
3. **Don't break the workflow.** Banner → Platform → Program → Scope review →
   Authorization → Control Center stays as it is, and so does the yellow-and-white
   Rich style.
4. **Be honest in docs.** Document only what is implemented, and mark planned
   features as planned.

## Development setup

```bash
git clone https://github.com/Idrisb53/BUGX.git
cd BUGX
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[browser,dev]"
pytest -m "not e2e" -q
```

## Running tests

```bash
pytest -m "not e2e"     # fast, mocked. Must pass, and this is what CI runs
pytest -m e2e           # real installed tools against a localhost mock server
pytest tests/test_scope_engine_extended.py -q   # a single module
```

Every behaviour change needs a test. Scope or policy changes need tests for
both the allowed **and** the blocked case.

## Code style

- Python 3.10+, type hints where practical.
- `ruff check src tests` is available. The codebase still has historical
  style findings, so please don't add new ones in the code you touch.
- External commands: always through `core/runner.py` (`shell=False`, timeout),
  never `os.system` or `shell=True`.
- UI: reuse `YELLOW` / `WHITE`, `Panel(border_style="bright_yellow")`, `[!]` for
  errors and `[+]` for success.

## Adding a tool adapter

1. Subclass `ToolAdapter` in `src/bugx/modules/<module>/adapters/<tool>.py`.
   Set `key`, `name`, `binaries`, `install`, `supported_os`, `input_kind`,
   `sends_traffic`, `supports_headers`, `intrusive`, and implement `build_args()`
   and `parse()`.
2. Use **safe, non-destructive defaults**. Honour `ctx.policy` (headers, rate,
   concurrency). If the tool can't send required headers, set
   `supports_headers = False` so the engine blocks it.
3. Register it in that module's `registry.py`.
4. Add tests: argument construction with a header-requiring policy, and parsing
   of realistic sample output.
5. Document it in [docs/MODULES.md](docs/MODULES.md) and state its verification
   level honestly.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(recon): add asnmap adapter
fix(scope): reject trailing-dot wildcard bypass
docs: clarify policy.automated_scanning
test(validation): cover redirect to out-of-scope host
```

## Pull requests

- Branch from `main` and keep each PR focused on one change.
- Fill in the pull request template.
- Make sure `pytest -m "not e2e"` passes locally and in CI.
- Update `CHANGELOG.md` under **Unreleased**.

## Reporting bugs and requesting features

Use the issue templates. **Strip target names, tokens, cookies and scan output**
from anything you paste. For security vulnerabilities in BUGX, follow
[SECURITY.md](SECURITY.md) instead of opening a public issue.

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).
