# Agent instructions

## Testing

Use `uv` for every Python test invocation. Do not invoke `pytest` directly.

```console
uv run pytest
uv run tox
```

For every new source file, also run its individual coverage target:

```console
uv run tox -e individual_coverage -- FILENAME
```

Useful focused Firetoll checks:

```console
uv run pytest test/mitmproxy/firetoll
uv run pytest test/mitmproxy/firetoll/test_attribution.py
uv run pytest test/mitmproxy/firetoll/test_redact.py test/mitmproxy/firetoll/test_mcp_server.py
uv run pytest test/mitmproxy/firetoll/test_x402.py
uv run pytest test/mitmproxy/firetoll/test_ci_diff_budget.py
```

When adding or changing mitmproxy options, regenerate the checked-in web option bindings before testing:

```console
uv run python web/gen/options_js.py
```

`test/mitmproxy/tools/web/test_app.py::test_generated_files` verifies that `web/src/js/ducks/_options_gen.ts` matches the generator output.

## Firetoll scope

Firetoll is an observe-only feature integrated into this mitmproxy fork. Its implementation and tests are self-contained:

- Source: `mitmproxy/firetoll/`
- Tests: `test/mitmproxy/firetoll/`
- Bundled detector data: `mitmproxy/firetoll/data/`

Core mitmproxy should remain unchanged except for the intentional wiring and packaging points:

- `mitmproxy/addons/__init__.py`
- `mitmproxy/contentviews/__init__.py`
- `pyproject.toml`
- `README.md`
- `.github/workflows/main.yml`
- `AGENTS.md`
- `.mcp.json` and `.codex/config.toml` (per-agent MCP server definitions, see below)
- `mitmproxy/utils/pyinstaller/hook-mitmproxy.firetoll.py` (bundles `data/*.yaml` into standalone binaries)
- `test/mitmproxy/test_firetoll.py` (tests `firetoll/__init__.py`'s `firetoll_addons()`)
- `uv.lock` and `web/src/js/ducks/_options_gen.ts` (generated files kept in sync with `pyproject.toml`/`options.py`)

The CI diff-budget check in `mitmproxy/firetoll/ci_diff_budget.py` must be updated whenever another outside path is deliberately added. Do not broaden the exception casually.

## Architecture invariants

1. Firetoll must never alter, delay, or replay a proxied flow.
2. A detector exception must be logged and isolated from the flow.
3. Every `Finding` must contain non-empty evidence.
4. Process attribution occurs at `client_connected`; flow metadata receives the result at `requestheaders`.
5. Attribution must degrade honestly to User-Agent or `unknown`; never infer a process from a late socket lookup.
6. Body capture is opt-in, capped at 64 KiB, and redacted unless `firetoll_body_access=full` was explicitly selected before capture.
7. MCP is a separate stdio process using `ReadOnlyStore`; it may audit body reads but must not mutate session data or proxy options.
8. Retention is enforced in code, not only documented.
9. x402 is observe/decode/quote only. Do not add wallet keys, signing, payment headers, transaction submission, auto-payment, or settlement claims to this package.

## Adding a detector

Implement a detector under `mitmproxy/firetoll/classify/` with a `name` and `detect(flow) -> list[Finding]`. Register it in `default_detectors()` and add focused tests under `test/mitmproxy/firetoll/`.

Use `confidence="signature"` only for an explicit protocol/corpus match. Use `confidence="heuristic"` for shape-based inference. Put exact triggering headers, paths, status codes, or body keys in `evidence`; put structured, non-sensitive derived values in `facts`.

Keep vendor knowledge in YAML corpora. Do not vendor GPL/CC-BY-SA tracking lists into this MIT-licensed repository. Preserve the runtime `firetoll_corpus_dir` extension point.

## Privacy rules

Do not add raw prompt, completion, credential, cookie, authorization, or identifier values to findings, reports, or the MCP API. Use redaction, byte counts, hashes, and short hashed prefixes where correlation is required. If a new body-bearing path is added, test the access gate, truncation, redaction marker, and audit log.

If changing the schema, update both `Store` and `ReadOnlyStore`, retention behavior, tests, and report/MCP consumers. Keep the SQLite file and parent directory permissioned `0600`/`0700`.

## Commands and options

The default store is `~/.mitmproxy/firetoll/session.sqlite`. The primary commands are:

```console
mitmdump --set firetoll_report=true
uv run firetoll-mcp --store-path ~/.mitmproxy/firetoll/session.sqlite
```

The proxy-side options are defined only in `mitmproxy/firetoll/options.py`. Do not register the same option elsewhere. `firetoll_body_access` controls what the MCP server may return; the MCP process cannot widen it.

`.codex/config.toml` and `.mcp.json` both declare the same `firetoll` MCP server (`uv run firetoll-mcp`) so Codex and Claude Code discover it the same way. Keep the command/args identical across both files. Codex has no interactive approval step, so it needs the explicit `enabled = false` default; Claude Code's own per-project MCP approval prompt is the equivalent gate, so `.mcp.json` does not need (and cannot express) an `enabled` flag.

The user-facing command names are `firetoll.report` and `firetoll.wipe`. Report exports use a base path and produce `.json` and `.md` files.

## Documentation and change hygiene

Document shipped behavior in `README.md` and this file. Do not make a plan document a runtime dependency or refer users to a deleted plan. Keep roadmap ideas out of operational instructions unless they are explicitly labeled as unimplemented.

Preserve unrelated working-tree changes. Before committing, review:

```console
git status --short
git diff -- README.md AGENTS.md
```
