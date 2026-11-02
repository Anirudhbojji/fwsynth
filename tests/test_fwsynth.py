"""Offline tests: evaluation, oracle conflicts, boundary probes, and the
full CEGIS loop with a mock LLM that first produces a buggy ruleset."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from fwsynth.evaluator import SpecConflict, evaluate, spec_verdict
from fwsynth.llm import MockBackend, _extract_json
from fwsynth.model import Packet, Property, Rule, Ruleset, Spec
from fwsynth.probes import generate_probes, probes_for_property
from fwsynth.render import render_nftables
from fwsynth.synth import synthesize
from fwsynth.verifier import verify

LAB = "10.20.0.0/24"
ANY = "0.0.0.0/0"


def lab_spec() -> Spec:
    return Spec(default="deny", properties=[
        Property("allow", LAB, ANY, "udp", 53, 53, "lab DNS"),
        Property("allow", LAB, ANY, "tcp", 443, 443, "lab HTTPS"),
        Property("deny", LAB, ANY, "tcp", 23, 23, "no telnet from lab"),
    ])


def good_rules() -> Ruleset:
    return Ruleset(default="deny", rules=[
        Rule("allow", LAB, ANY, "udp", 53, 53, "dns"),
        Rule("allow", LAB, ANY, "tcp", 443, 443, "https"),
    ])


# ---------- evaluator ----------

def test_first_match_wins():
    rs = Ruleset(default="deny", rules=[
        Rule("deny", "10.20.0.0/24", ANY, "tcp", 443, 443, "specific deny"),
        Rule("allow", "10.0.0.0/8", ANY, "tcp", 443, 443, "broad allow"),
    ])
    action, rule = evaluate(rs, Packet("10.20.0.5", "1.1.1.1", "tcp", 443))
    assert action == "deny" and rule.comment == "specific deny"
    action, _ = evaluate(rs, Packet("10.99.0.5", "1.1.1.1", "tcp", 443))
    assert action == "allow"


def test_default_applies_when_nothing_matches():
    action, rule = evaluate(good_rules(), Packet("172.16.0.1", "1.1.1.1", "tcp", 80))
    assert action == "deny" and rule is None


def test_port_range_and_cidr_edges():
    rs = Ruleset(default="deny", rules=[
        Rule("allow", "10.20.0.0/24", ANY, "tcp", 8000, 8080, "range"),
    ])
    assert evaluate(rs, Packet("10.20.0.0", "1.1.1.1", "tcp", 8000))[0] == "allow"
    assert evaluate(rs, Packet("10.20.0.255", "1.1.1.1", "tcp", 8080))[0] == "allow"
    assert evaluate(rs, Packet("10.20.1.0", "1.1.1.1", "tcp", 8000))[0] == "deny"
    assert evaluate(rs, Packet("10.20.0.5", "1.1.1.1", "tcp", 7999))[0] == "deny"
    assert evaluate(rs, Packet("10.20.0.5", "1.1.1.1", "tcp", 8081))[0] == "deny"


# ---------- spec oracle ----------

def test_oracle_verdicts():
    spec = lab_spec()
    assert spec_verdict(spec, Packet("10.20.0.9", "8.8.8.8", "udp", 53)) == "allow"
    assert spec_verdict(spec, Packet("10.20.0.9", "8.8.8.8", "tcp", 23)) == "deny"
    assert spec_verdict(spec, Packet("192.0.2.1", "8.8.8.8", "tcp", 80)) == "deny"


def test_oracle_detects_contradictory_spec():
    spec = Spec(default="deny", properties=[
        Property("allow", LAB, ANY, "tcp", 443, 443, "allow https"),
        Property("deny", "10.20.0.0/25", ANY, "tcp", 443, 443, "deny overlap"),
    ])
    verdict = spec_verdict(spec, Packet("10.20.0.5", "1.1.1.1", "tcp", 443))
    assert isinstance(verdict, SpecConflict)


# ---------- probes ----------

def test_probes_cover_boundaries():
    prop = Property("allow", LAB, ANY, "tcp", 8000, 8080, "x")
    pkts = probes_for_property(prop)
    srcs = {p.src for p in pkts}
    ports = {p.dport for p in pkts}
    assert {"10.20.0.0", "10.20.0.255", "10.19.255.255", "10.20.1.0"} <= srcs
    assert {7999, 8000, 8080, 8081} <= ports
    assert any(p.proto == "udp" for p in pkts)  # wrong-protocol probe


# ---------- verifier ----------

def test_verifier_passes_correct_ruleset():
    verdict = verify(lab_spec(), good_rules())
    assert verdict.ok and verdict.probes_run > 30


def test_verifier_catches_off_by_one_port():
    buggy = Ruleset(default="deny", rules=[
        Rule("allow", LAB, ANY, "udp", 53, 53, "dns"),
        Rule("allow", LAB, ANY, "tcp", 443, 444, "https BUT range too wide"),
    ])
    verdict = verify(lab_spec(), buggy)
    # 444 isn't allowed by any spec property -> must fall to default deny
    assert not verdict.ok
    assert any(c.packet.dport == 444 and c.expected == "deny" and c.got == "allow"
               for c in verdict.counterexamples)


def test_verifier_catches_wrong_rule_order():
    buggy = Ruleset(default="allow", rules=[  # wrong default too
        Rule("allow", ANY, ANY, "any", 0, 65535, "allow all first"),
        Rule("deny", LAB, ANY, "tcp", 23, 23, "unreachable telnet deny"),
    ])
    verdict = verify(lab_spec(), buggy)
    assert not verdict.ok
    assert any(c.packet.dport == 23 and c.expected == "deny" for c in verdict.counterexamples)


# ---------- full CEGIS loop with mock LLM ----------

def test_pipeline_repairs_buggy_ruleset():
    spec_json = lab_spec().to_dict()
    buggy = {"default": "deny", "rules": [
        {"action": "allow", "src": LAB, "dst": ANY, "proto": "udp",
         "dport_lo": 53, "dport_hi": 53, "comment": "dns"},
        {"action": "allow", "src": LAB, "dst": ANY, "proto": "tcp",
         "dport_lo": 0, "dport_hi": 65535, "comment": "BUG: all tcp allowed"},
    ]}
    fixed = good_rules().to_dict()
    backend = MockBackend([spec_json, buggy, fixed])

    result = synthesize("lab policy", backend, max_repairs=2)
    assert result.ok
    assert result.repairs_used == 1
    # the repair prompt must have carried concrete counterexamples
    assert "Counterexamples" in backend.calls[2][1]
    assert "spec requires DENY" in backend.calls[2][1]


def test_pipeline_refuses_when_repairs_exhausted():
    spec_json = lab_spec().to_dict()
    always_buggy = {"default": "allow", "rules": []}
    backend = MockBackend([spec_json, always_buggy, always_buggy])
    result = synthesize("lab policy", backend, max_repairs=1)
    assert not result.ok
    assert result.verdict.counterexamples


def test_pipeline_surfaces_spec_conflict():
    conflict_spec = {"default": "deny", "properties": [
        {"action": "allow", "src": LAB, "dst": ANY, "proto": "tcp",
         "dport_lo": 443, "dport_hi": 443, "description": "a"},
        {"action": "deny", "src": LAB, "dst": ANY, "proto": "tcp",
         "dport_lo": 443, "dport_hi": 443, "description": "b"},
    ]}
    backend = MockBackend([conflict_spec, {"default": "deny", "rules": []}])
    result = synthesize("contradictory", backend, max_repairs=1)
    assert not result.ok
    assert result.verdict.spec_conflicts


# ---------- render ----------

def test_render_nftables():
    nft = render_nftables(good_rules())
    assert "policy drop;" in nft
    assert "ip saddr 10.20.0.0/24 udp dport 53 accept" in nft
    assert "ip saddr 10.20.0.0/24 tcp dport 443 accept" in nft
    assert "ip daddr" not in nft  # 0.0.0.0/0 dst omitted


def test_extract_json_from_noisy_output():
    assert _extract_json('noise {"a": {"b": 1}} trailing')["a"]["b"] == 1
