"""Deterministic packet evaluation.

Two engines, same packets:
  - evaluate(ruleset, pkt): first-match-wins over the ordered rules — the
    system under test.
  - spec_verdict(spec, pkt): all matching constraints must agree — the oracle.
    Disagreeing constraints mean the intent itself is contradictory, which is
    reported as a SpecConflict rather than papered over.
"""

from dataclasses import dataclass
from ipaddress import ip_address

from .model import Packet, Property, Rule, Ruleset, Spec


@dataclass
class SpecConflict:
    packet: Packet
    properties: list[Property]


def _matches(entry, pkt: Packet) -> bool:
    if entry.proto != "any" and entry.proto != pkt.proto:
        return False
    if ip_address(pkt.src) not in entry.src_net:
        return False
    if ip_address(pkt.dst) not in entry.dst_net:
        return False
    if pkt.proto != "icmp" and not (entry.dport_lo <= pkt.dport <= entry.dport_hi):
        return False
    return True


def evaluate(ruleset: Ruleset, pkt: Packet) -> tuple[str, Rule | None]:
    """First-match-wins verdict: (action, matching rule or None for default)."""
    for rule in ruleset.rules:
        if _matches(rule, pkt):
            return rule.action, rule
    return ruleset.default, None


def spec_verdict(spec: Spec, pkt: Packet) -> str | SpecConflict:
    """Oracle verdict: the action every matching constraint demands,
    the default if none match, or a SpecConflict if constraints disagree."""
    matching = [p for p in spec.properties if _matches(p, pkt)]
    if not matching:
        return spec.default
    actions = {p.action for p in matching}
    if len(actions) > 1:
        return SpecConflict(packet=pkt, properties=matching)
    return actions.pop()
