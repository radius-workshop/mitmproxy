import pytest

from mitmproxy.firetoll.finding import Finding


class TestFindingConstruction:
    def test_minimal_construction(self):
        f = Finding(
            cls="telemetry",
            label="posthog",
            confidence="signature",
            evidence=["host:us.i.posthog.com"],
        )
        assert f.cls == "telemetry"
        assert f.label == "posthog"
        assert f.confidence == "signature"
        assert f.evidence == ["host:us.i.posthog.com"]

    def test_facts_defaults_to_empty_dict(self):
        f = Finding(
            cls="tracker",
            label="segment",
            confidence="heuristic",
            evidence=["path:/v1/track"],
        )
        assert f.facts == {}

    def test_facts_default_is_not_shared_between_instances(self):
        # dataclass `field(default_factory=dict)` must give each instance its
        # own dict - a shared mutable default would leak facts across findings.
        a = Finding(
            cls="tracker", label="a", confidence="heuristic", evidence=["e"]
        )
        b = Finding(
            cls="tracker", label="b", confidence="heuristic", evidence=["e"]
        )
        a.facts["leaked"] = True
        assert b.facts == {}

    def test_explicit_facts_are_kept(self):
        f = Finding(
            cls="x402",
            label="offer",
            confidence="signature",
            evidence=["header:X-Payment"],
            facts={"amount": "100", "currency": "USDC"},
        )
        assert f.facts == {"amount": "100", "currency": "USDC"}

    def test_all_finding_classes_are_constructible(self):
        for cls in (
            "telemetry",
            "agent_egress",
            "tracker",
            "identity_join",
            "botdetect",
            "x402",
        ):
            f = Finding(
                cls=cls, label="label", confidence="heuristic", evidence=["e"]
            )
            assert f.cls == cls

    def test_both_confidence_levels_are_constructible(self):
        for confidence in ("signature", "heuristic"):
            f = Finding(
                cls="telemetry",
                label="label",
                confidence=confidence,
                evidence=["e"],
            )
            assert f.confidence == confidence


class TestFindingPostInit:
    def test_empty_evidence_list_raises(self):
        with pytest.raises(ValueError, match="has no evidence"):
            Finding(cls="telemetry", label="posthog", confidence="signature", evidence=[])

    def test_error_message_includes_cls_and_label(self):
        with pytest.raises(ValueError, match=r"cls='telemetry'.*label='posthog'"):
            Finding(cls="telemetry", label="posthog", confidence="signature", evidence=[])


class TestFindingToDict:
    def test_to_dict_returns_all_fields(self):
        f = Finding(
            cls="botdetect",
            label="cloudflare-challenge",
            confidence="heuristic",
            evidence=["status:403"],
            facts={"provider": "cloudflare"},
        )
        assert f.to_dict() == {
            "cls": "botdetect",
            "label": "cloudflare-challenge",
            "confidence": "heuristic",
            "evidence": ["status:403"],
            "facts": {"provider": "cloudflare"},
        }

    def test_to_dict_copies_evidence_and_facts(self):
        # to_dict() must not hand back references to the Finding's own
        # mutable containers - mutating the result must not mutate the
        # Finding.
        evidence = ["header:x"]
        facts = {"k": "v"}
        f = Finding(
            cls="tracker",
            label="segment",
            confidence="heuristic",
            evidence=evidence,
            facts=facts,
        )
        d = f.to_dict()
        d["evidence"].append("mutated")
        d["facts"]["k"] = "mutated"
        assert f.evidence == ["header:x"]
        assert f.facts == {"k": "v"}
