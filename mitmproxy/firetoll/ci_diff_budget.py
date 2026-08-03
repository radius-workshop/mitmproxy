"""CI gate: keep the upstream diff budget honest.

Firetoll lives entirely in mitmproxy/firetoll/ (and its tests in
test/mitmproxy/firetoll/) so this fork stays rebaseable and its observe-only
pieces stay upstreamable. This script fails if a diff against upstream
mitmproxy/mitmproxy's `main` branch touches anything outside that package
plus a short, explicit allowlist of wiring points.

Usage: python -m mitmproxy.firetoll.ci_diff_budget [--base-ref REF]
"""

from __future__ import annotations

import argparse
import subprocess
import sys

# Every other file firetoll is allowed to touch outside its own package.
# Adding to this list is a deliberate decision, not something that should
# happen as a side effect of an unrelated change.
ALLOWED_PATHS = {
    "mitmproxy/addons/__init__.py",  # wires firetoll_addons() into default_addons()
    "mitmproxy/contentviews/__init__.py",  # registers the x402 contentview
    "pyproject.toml",  # new deps + firetoll-mcp console script
    "README.md",  # a Firetoll section
    "AGENTS.md",  # Firetoll development guide and mandatory test commands
    ".github/workflows/main.yml",  # this gate itself
    ".mcp.json",  # Claude Code project-scoped firetoll-mcp definition
    ".codex/config.toml",  # Codex project-scoped firetoll-mcp definition
}

EXCLUDED_PATH_PREFIXES = (
    "mitmproxy/firetoll/",
    "test/mitmproxy/firetoll/",
)

DEFAULT_BASE_REF = "upstream-mitmproxy/main"


def changed_files(base_ref: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", f"{base_ref}...HEAD"],
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in result.stdout.splitlines() if line]


def offending_files(files: list[str]) -> list[str]:
    return [
        f
        for f in files
        if f not in ALLOWED_PATHS and not f.startswith(EXCLUDED_PATH_PREFIXES)
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-ref",
        default=DEFAULT_BASE_REF,
        help=f"upstream ref to diff against (default: {DEFAULT_BASE_REF})",
    )
    args = parser.parse_args(argv)

    files = changed_files(args.base_ref)
    offenders = offending_files(files)
    if offenders:
        print(
            "firetoll upstream diff budget exceeded - files outside the allowlist:",
            file=sys.stderr,
        )
        for f in offenders:
            print(f"  {f}", file=sys.stderr)
        print(
            "\nEither move this change into mitmproxy/firetoll/, or add the path to "
            "ALLOWED_PATHS in mitmproxy/firetoll/ci_diff_budget.py if it's a "
            "deliberate new touch point.",
            file=sys.stderr,
        )
        return 1

    print(
        f"firetoll diff budget OK: {len(files)} file(s) changed vs "
        f"{args.base_ref}, all within budget."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
