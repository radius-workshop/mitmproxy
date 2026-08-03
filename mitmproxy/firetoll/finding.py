"""The honesty contract: every enrichment result is a Finding.

A Finding must be able to point at the exact bytes that produced it. Code that
constructs one without evidence is a bug, not a style choice - see
`Finding.__post_init__`.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Literal

FindingClass = Literal[
    "telemetry",
    "agent_egress",
    "tracker",
    "identity_join",
    "botdetect",
    "x402",
]

Confidence = Literal["signature", "heuristic"]


@dataclass
class Finding:
    cls: FindingClass
    label: str
    confidence: Confidence
    evidence: list[str]
    facts: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.evidence:
            raise ValueError(
                f"Finding(cls={self.cls!r}, label={self.label!r}) has no evidence. "
                "A Finding must cite the header/path/body key that fired."
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "cls": self.cls,
            "label": self.label,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "facts": dict(self.facts),
        }
