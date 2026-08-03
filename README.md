# mitmproxy

[![Continuous Integration Status](https://github.com/mitmproxy/mitmproxy/actions/workflows/main.yml/badge.svg?branch=main)](https://github.com/mitmproxy/mitmproxy/actions?query=branch%3Amain)

`mitmproxy` is an interactive, SSL/TLS-capable intercepting proxy with interfaces for HTTP/1, HTTP/2, WebSockets, and more.

- `mitmproxy` — interactive terminal interface
- `mitmdump` — command-line capture and replay interface
- `mitmweb` — web interface

Install and general documentation are available at [mitmproxy.org](https://mitmproxy.org/) and [docs.mitmproxy.org](https://docs.mitmproxy.org/stable/). To develop from source, read [CONTRIBUTING.md](./CONTRIBUTING.md).

## Firetoll

This fork includes Firetoll: an observe-only traffic enrichment layer that makes a mitmproxy session queryable by a human or an AI agent. It adds process attribution, detector-backed findings, privacy-aware session storage, terminal/JSON/Markdown reports, and a separate MCP server.

Firetoll never changes proxied traffic. A detector failure is isolated and cannot fail a flow. Findings are attached to `flow.metadata["firetoll.findings"]`, so they survive `.mitm` serialization.

### Quick start

Run the proxy separately from the MCP server. Firetoll is enabled by default and writes its session database to `~/.mitmproxy/firetoll/session.sqlite`.

```console
uv run mitmdump
```

The regular proxy listens on `http://127.0.0.1:8080`. Applications must be
explicitly configured to use it; starting `firetoll-mcp` does not start a
proxy listener or discover applications by itself. For example, configure a
terminal shell and the commands launched from it with:

```console
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
export http_proxy="$HTTP_PROXY"
export https_proxy="$HTTPS_PROXY"
```

On macOS, HTTPS clients must trust mitmproxy's interception CA. After the
proxy has generated `~/.mitmproxy/mitmproxy-ca-cert.pem`, trust it in the
login keychain:

```console
security add-trusted-cert \
  -d \
  -r trustRoot \
  -k "$HOME/Library/Keychains/login.keychain-db" \
  "$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
```

Restart the client after installing the CA. An `UnknownIssuer` error means
the application reached the proxy but does not yet trust this certificate.

#### OpenAI Codex CLI

The `codex` command starts a native Rust binary behind its Node launcher. As a
result, `NODE_EXTRA_CA_CERTS` alone is not sufficient for Codex to trust the
mitmproxy CA; install the CA in the macOS login keychain as shown above, then
fully quit and restart Codex. Other terminal clients may instead honor
`NODE_EXTRA_CA_CERTS` or another client-specific CA-bundle variable.

For an opt-in zsh setup, add this block to `~/.zshrc` and open a new shell:

```zsh
export MITMPROXY_ENABLED=0
if [[ "$MITMPROXY_ENABLED" == "1" ]]; then
  export HTTP_PROXY="http://127.0.0.1:8080"
  export HTTPS_PROXY="$HTTP_PROXY"
  export ALL_PROXY="$HTTP_PROXY"
  export http_proxy="$HTTP_PROXY"
  export https_proxy="$HTTPS_PROXY"
  export all_proxy="$ALL_PROXY"
else
  unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
fi
```

Set `MITMPROXY_ENABLED=1` to enable proxying for newly opened shells, or
`MITMPROXY_ENABLED=0` to disable it. The terminal emulator itself is not the
traffic source; commands and applications launched from its shell inherit the
proxy environment.

To verify the path without relying on an application-specific client:

```console
curl https://example.com
```

During an interactive session, use `firetoll.report`. To export both formats, set a base path:

```console
mitmdump \
  --set firetoll_report=true \
  --set firetoll_report_path=/tmp/firetoll-session
```

This writes `/tmp/firetoll-session.json` and `/tmp/firetoll-session.md`.

### MCP access

`firetoll-mcp` is a separate stdio process. It opens the SQLite store read-only, never runs in the proxy data path, and cannot broaden the capture policy after the session was recorded. Enable it only when a session exists and you intend to expose that session to an agent.

```console
uv run firetoll-mcp --store-path ~/.mitmproxy/firetoll/session.sqlite
```

Two checked-in, per-agent config files wire up the same `uv run firetoll-mcp` server so it works out of the box in either coding tool, gated behind that tool's own opt-in mechanism:

- **Codex**: `.codex/config.toml` defines the `firetoll` server with `enabled = false`. Flip it to `true` to use it.
- **Claude Code**: `.mcp.json` defines the same server. Claude Code prompts to approve project-scoped MCP servers the first time they're used, which is the equivalent opt-in gate.

The server provides tools for session totals, attributed applications, flow queries, evidence-backed findings, identity joins, AI-agent activity, x402 offers, redaction rules, stored body metadata, bounded body reads, and the body-access audit log. `get_body` returns a 4 KiB window by default; use `offset` and `limit` or `get_body_range` for explicit bounded reads. `list_bodies` returns metadata without content. Reads are capped at 64 KiB per call and remain audit-logged.

### What Firetoll detects

- Telemetry and analytics sinks, including corpus signatures and JSON event heuristics.
- AI-agent egress, including provider requests, MCP JSON-RPC, model identifiers, byte counts, and WebSocket upgrade handshakes.
- Trackers and identity joins: the same identifier observed across multiple eTLD+1 domains.
- Bot detection and fingerprinting signals, plus a stable TLS client-profile hash.
- x402 `402 Payment Required` offers, with normalized network identifiers and a dry-run cost quote.

Each finding has a class, label, confidence (`signature` or `heuristic`), and non-empty evidence describing the header, path, or body key that triggered it.

### Privacy and evidence boundaries

Metadata and findings are stored by default; bodies are not. Enable bounded body capture explicitly:

```console
mitmdump \
  --set firetoll_store_bodies=true \
  --set firetoll_body_access=redacted
```

`redacted` removes prompt/completion fields, secret-named JSON fields, common credentials, emails, IP addresses, phone numbers, and card-shaped values before storage. Captured bodies are capped at 64 KiB. `full` stores raw bodies and is intended only for a deliberate, audited local workflow; MCP body reads are logged. `none` refuses body reads even when bodies exist.

The report explicitly counts unattributed flows, CONNECT-only flows, streamed bodies, truncation, and the fact that WebSocket frame capture is off by default. An absent finding means “not observed by this capture configuration,” not “safe” or “not present.”

The store is mode `0600`, its directory is mode `0700`, identifier values are salted and hashed, and rows older than `firetoll_retention_hours` (24 by default) are deleted on startup and during periodic sweeps. To erase the current session, run `firetoll.wipe`.

### Options

| Option | Default | Purpose |
|---|---:|---|
| `firetoll` | `true` | Enable enrichment, storage, and commands. |
| `firetoll_attribution` | `true` | Resolve client sockets to local processes; fall back to User-Agent. |
| `firetoll_store_bodies` | `false` | Capture request/response bodies after applying the selected access policy. |
| `firetoll_body_access` | `redacted` | MCP body policy: `none`, `redacted`, or `full`. |
| `firetoll_retention_hours` | `24` | Retention window for stored flow data. |
| `firetoll_corpus_dir` | empty | Directory containing additional `telemetry.yaml` and `trackers.yaml` files. |
| `firetoll_report` | `false` | Print a report when the proxy exits. |
| `firetoll_report_path` | empty | Base path for JSON and Markdown exports. |
| `firetoll_store_path` | platform default | Override the SQLite path. |

Corpus files are data, not code. Bundled corpora can be extended at runtime with `--set firetoll_corpus_dir=/path/to/corpus`; supplied files are merged with the bundled files.

### x402 boundary

Firetoll decodes common x402 offer shapes, maps known network names to CAIP-2 identifiers, renders offers in the content view, and exposes a dry-run quote. It does not hold keys, sign authorizations, submit transactions, inject payment headers, replay requests, or claim settlement. The x402 feature is an observation and explanation layer.

### Source layout

```text
mitmproxy/firetoll/
  attribution.py       client connection → process/User-Agent attribution
  classify/             telemetry, agent-egress, tracker, and bot detectors
  enrich.py             detector orchestration and flow metadata
  finding.py            evidence-backed finding contract
  redact.py             body redaction and 64 KiB cap
  store.py              permissioned SQLite store and retention
  report.py             terminal, JSON, and Markdown reports
  x402.py               offer parsing, detection, and dry-run quotes
  x402_contentview.py   x402 content view
  mcp/server.py         separate read-only stdio MCP server
  data/                 bundled detector corpora
test/mitmproxy/firetoll/ Firetoll unit and integration tests
```

The Firetoll CI job enforces a small upstream diff budget. New feature code and tests belong under the two Firetoll directories; core wiring is limited to the documented addon/contentview registration, packaging, repository documentation, workflow, and budget-check files.
