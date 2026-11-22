## Summary

<!-- What does this PR change, and why? Link the issue: Closes #123 -->

## Type of change

- [ ] Bug fix
- [ ] New tool adapter
- [ ] New feature / improvement
- [ ] Documentation
- [ ] Tests / CI
- [ ] Refactor (no behaviour change)

## Safety checklist

- [ ] Every new target input goes through the Scope Engine / `ScopeGate`.
- [ ] Required headers, User-Agent, rate limit and `automated_scanning` are honoured (or the tool is blocked when it can't honour them).
- [ ] External commands run through `core/runner.py` (`shell=False`, timeout).
- [ ] Defaults are safe and non-destructive.
- [ ] No real targets, program profiles, scan output, tokens or cookies are included.

## Testing

- [ ] `pytest -m "not e2e"` passes locally.
- [ ] New/changed behaviour has tests (allowed **and** blocked cases for scope/policy changes).
- [ ] `pytest -m e2e` run locally (if the change touches a tool adapter and the tool is installed).

## Documentation

- [ ] README / `docs/` updated where behaviour changed.
- [ ] `CHANGELOG.md` updated under **Unreleased**.
- [ ] The interactive workflow and the yellow/white UI style are unchanged (or the change is explained above).
