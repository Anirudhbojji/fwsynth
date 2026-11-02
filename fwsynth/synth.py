"""The CEGIS pipeline: LLM proposes, the verifier disposes.

   English intent
     -> LLM: structured spec (the oracle)
     -> LLM: ordered ruleset (the candidate)
     -> verifier: boundary probes, spec vs ruleset
     -> disagree? counterexamples go back to the LLM for repair (bounded)
     -> agree?    deterministic render to nftables
"""

import json
from dataclasses import dataclass, field

from .llm import LLMBackend
from .model import Ruleset, Spec
from .verifier import Verdict, verify

_PORT_FIELDS = {
    "dport_lo": {"type": "integer"},
    "dport_hi": {"type": "integer"},
}

SPEC_SCHEMA = {
    "type": "object",
    "properties": {
        "default": {"type": "string", "enum": ["allow", "deny"]},
        "properties": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["allow", "deny"]},
                    "src": {"type": "string"},
                    "dst": {"type": "string"},
                    "proto": {"type": "string", "enum": ["tcp", "udp", "icmp", "any"]},
                    **_PORT_FIELDS,
                    "description": {"type": "string"},
                },
                "required": ["action", "src", "dst", "proto",
                             "dport_lo", "dport_hi", "description"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["default", "properties"],
    "additionalProperties": False,
}

RULES_SCHEMA = {
    "type": "object",
    "properties": {
        "default": {"type": "string", "enum": ["allow", "deny"]},
        "rules": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["allow", "deny"]},
                    "src": {"type": "string"},
                    "dst": {"type": "string"},
                    "proto": {"type": "string", "enum": ["tcp", "udp", "icmp", "any"]},
                    **_PORT_FIELDS,
                    "comment": {"type": "string"},
                },
                "required": ["action", "src", "dst", "proto",
                             "dport_lo", "dport_hi", "comment"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["default", "rules"],
    "additionalProperties": False,
}

SPEC_SYSTEM = """You translate firewall intent written in English into a formal, \
machine-checkable specification. Each property is a constraint: EVERY packet \
matching (src CIDR, dst CIDR, proto, dport range) MUST receive the action. \
Use 0.0.0.0/0 for 'anywhere', dport range 0-65535 for 'any port', dport 0-0 \
for icmp. Cover every allow AND every deny the intent implies, and choose the \
default the intent implies (deny if unstated). Properties must not contradict \
each other on any packet. This is a stateless model: express intent in terms \
of the initiating direction only."""

RULES_SYSTEM = """You are a firewall engineer. Produce an ORDERED first-match-wins \
rule list implementing the given specification exactly. More specific rules \
must precede broader ones. Every packet class in the spec must get its \
required action, including packets just outside each range (they fall through \
to later rules or the default). Use 0.0.0.0/0 for 'anywhere' and 0-65535 for \
'any port'."""

REPAIR_SYSTEM = RULES_SYSTEM + """

Your previous ruleset FAILED verification. You will receive the spec, your \
previous ruleset, and concrete counterexample packets with the verdict the \
spec requires versus the verdict your ruleset produced. Fix the ruleset so \
every counterexample gets the required verdict without breaking the rest."""


@dataclass
class SynthesisResult:
    spec: Spec
    ruleset: Ruleset | None
    verdict: Verdict | None
    repairs_used: int = 0
    history: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.verdict is not None and self.verdict.ok


def synthesize(intent: str, backend: LLMBackend, max_repairs: int = 3,
               log=lambda msg: None) -> SynthesisResult:
    log("pass 1: intent -> formal spec")
    spec = Spec.from_dict(backend.generate_json(SPEC_SYSTEM, intent, SPEC_SCHEMA))

    log("pass 2: spec -> ordered ruleset")
    rules_prompt = (f"Original intent:\n{intent}\n\n"
                    f"Specification:\n{json.dumps(spec.to_dict(), indent=2)}")
    ruleset = Ruleset.from_dict(
        backend.generate_json(RULES_SYSTEM, rules_prompt, RULES_SCHEMA))

    result = SynthesisResult(spec=spec, ruleset=ruleset, verdict=None)
    for attempt in range(max_repairs + 1):
        verdict = verify(spec, ruleset)
        result.verdict = verdict
        result.ruleset = ruleset
        if verdict.spec_conflicts:
            log("spec is self-contradictory — refusing to emit rules")
            return result
        if verdict.ok:
            log(f"verified: {verdict.probes_run} boundary probes, 0 disagreements"
                + (f" (after {attempt} repair(s))" if attempt else ""))
            result.repairs_used = attempt
            return result

        result.history.append(
            f"attempt {attempt}: {len(verdict.counterexamples)} counterexample(s)")
        if attempt == max_repairs:
            log("repair budget exhausted — refusing to emit unverified rules")
            return result

        log(f"verification failed ({len(verdict.counterexamples)} counterexamples) "
            f"-> repair pass {attempt + 1}")
        ce_text = "\n".join(f"- {c.describe()}" for c in verdict.counterexamples[:20])
        repair_prompt = (
            f"Specification:\n{json.dumps(spec.to_dict(), indent=2)}\n\n"
            f"Previous (incorrect) ruleset:\n{json.dumps(ruleset.to_dict(), indent=2)}\n\n"
            f"Counterexamples:\n{ce_text}")
        ruleset = Ruleset.from_dict(
            backend.generate_json(REPAIR_SYSTEM, repair_prompt, RULES_SCHEMA))

    return result
