"""Shared corpus loading for signature-based detectors (telemetry, trackers):
a named vendor matched by exact host, host suffix, or path pattern, loaded
from data/<corpus_name>.yaml and optionally extended by a user corpus_dir.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path

from ruamel.yaml import YAML

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@dataclass
class Vendor:
    name: str
    hosts: frozenset[str] = field(default_factory=frozenset)
    host_suffixes: tuple[str, ...] = ()
    path_patterns: tuple[re.Pattern, ...] = ()

    def matches(self, host: str, path: str) -> bool:
        if host in self.hosts:
            return True
        if any(host.endswith(suffix) for suffix in self.host_suffixes):
            return True
        return any(pattern.search(path) for pattern in self.path_patterns)


def _parse(text: str) -> list[Vendor]:
    data = YAML(typ="safe", pure=True).load(text) or {}
    return [
        Vendor(
            name=entry["name"],
            hosts=frozenset(entry.get("hosts", [])),
            host_suffixes=tuple(entry.get("host_suffixes", [])),
            path_patterns=tuple(re.compile(p) for p in entry.get("path_patterns", [])),
        )
        for entry in data.get("vendors", [])
    ]


def load_vendors(corpus_name: str, corpus_dir: str | None = None) -> list[Vendor]:
    vendors = _parse((_DATA_DIR / f"{corpus_name}.yaml").read_text())
    if corpus_dir:
        override = Path(corpus_dir) / f"{corpus_name}.yaml"
        if override.exists():
            vendors.extend(_parse(override.read_text()))
        else:
            logger.warning(
                f"firetoll: no {corpus_name}.yaml in corpus dir {corpus_dir}"
            )
    return vendors
