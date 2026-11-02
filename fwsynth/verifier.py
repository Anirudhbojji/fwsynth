"""The deterministic half of the CEGIS loop.

Runs every boundary probe through both the spec oracle and the candidate
ruleset. Disagreements become counterexamples; spec-internal contradictions
are surfaced separately so the user can fix the intent rather than blaming
the ruleset.
"""

from dataclasses import dataclass, field

from .evaluator import SpecConflict, evaluate, spec_verdict
from .model import Packet, Ruleset, Spec
from .probes import generate_probes


@dataclass
class Counterexample:
    packet: Packet
    expected: str
    got: str

    def describe(self) -> str:
        return f"{self.packet}: spec requires {self.expected.upper()}, ruleset gives {self.got.upper()}"


@dataclass
class Verdict:
    probes_run: int = 0
    counterexamples: list[Counterexample] = field(default_factory=list)
    spec_conflicts: list[SpecConflict] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.counterexamples and not self.spec_conflicts


def verify(spec: Spec, ruleset: Ruleset) -> Verdict:
    verdict = Verdict()
    for pkt in generate_probes(spec):
        expected = spec_verdict(spec, pkt)
        if isinstance(expected, SpecConflict):
            verdict.spec_conflicts.append(expected)
            continue
        got, _ = evaluate(ruleset, pkt)
        verdict.probes_run += 1
        if got != expected:
            verdict.counterexamples.append(
                Counterexample(packet=pkt, expected=expected, got=got))
    return verdict
