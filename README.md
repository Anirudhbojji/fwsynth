# fwsynth

**English intent → verified firewall rules.** An LLM writes the rules; a deterministic packet simulator proves they implement your intent before a single line is emitted. If the proof fails, concrete counterexample packets go back to the LLM for repair — classic **CEGIS (counterexample-guided synthesis), with an LLM as the synthesizer**.

```
  "Lab subnet may reach anywhere on tcp/443 and udp/53.
   Telnet from the lab is forbidden. Everything else denied."
          │
          ▼ LLM pass 1
  formal spec ───────────────► the oracle: packet classes -> required verdicts
          │
          ▼ LLM pass 2
  ordered ruleset ───────────► the candidate: first-match-wins rules
          │
          ▼ deterministic verifier (no LLM)
  boundary probes: CIDR edges ±1, port corners ±1, wrong protocols,
  background traffic — every probe judged by BOTH oracle and candidate
          │
   ┌──────┴──────┐
   ▼             ▼
 agree        disagree ──► counterexamples ──► LLM repair pass (bounded)
   │
   ▼
 deterministic render ──► nftables
```

**The trust model:** never trust the LLM's rules directly. Trust them only after a simulator has fired boundary-case packets at them and the verdicts match the spec on every single one. The output is accompanied by the probe count — and if verification can't be achieved within the repair budget, fwsynth **refuses to emit rules** rather than emitting unproven ones.

## Why this is hard (and interesting)

The classic failure modes of LLM-generated firewall rules are exactly the ones boundary probing catches:

- **off-by-one port ranges** (443–444 instead of 443) — caught by the `hi+1` probe
- **wrong rule order** (broad allow shadowing a specific deny) — caught because first-match-wins is simulated, not assumed
- **inverted/oversized CIDRs** — caught by network/broadcast ±1 probes
- **wrong default policy** — caught by background-traffic probes
- **contradictory intent** — caught *before* generation: if the spec itself demands allow AND deny for the same packet, fwsynth reports the conflict instead of silently picking one

## Usage

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# with an Anthropic API key (structured outputs — schema enforced server-side)
export ANTHROPIC_API_KEY=...
python -m fwsynth compile "lab subnet 10.20.0.0/24 may reach anywhere on tcp 443 \
  and udp 53; telnet from the lab is forbidden; everything else denied" \
  --out rules.nft --json-out ir.json

# zero API key: uses your local `claude` CLI (Claude Code) as the engine
python -m fwsynth compile "..." --backend claude-cli

# re-verify a saved ruleset against its spec (pure simulation, no LLM)
python -m fwsynth check --ir ir.json

# ask the ruleset about one packet
python -m fwsynth simulate --ir ir.json -p 10.20.0.9,8.8.8.8,udp,53
```

Example output:

```
[fwsynth] pass 1: intent -> formal spec
[fwsynth] pass 2: spec -> ordered ruleset
[fwsynth] verified: 94 boundary probes, 0 disagreements

# spec: 4 properties | probes: 94 | repairs: 0
table inet fwsynth {
  chain forward {
    type filter hook forward priority 0; policy drop;
    ip saddr 10.20.0.0/24 tcp dport 23 drop comment "no telnet from lab"
    ip saddr 10.20.0.0/24 udp dport 53 accept comment "lab DNS"
    ...
  }
}
```

## Design notes

- **Two independent LLM derivations cross-check each other.** The spec and the ruleset are generated separately; a generation error must appear in *both*, in a consistent way, to slip through — and the boundary probes make that extremely unlikely.
- **Verification is the trust anchor, and it contains no LLM.** The probe generator, the two packet-evaluation engines, and the renderer are plain deterministic Python, covered by an offline test suite (including a mock-LLM test proving the repair loop fixes a deliberately buggy ruleset using counterexamples).
- **Structured outputs** (Anthropic API) enforce the JSON schema server-side, so responses parse by construction; the claude-CLI backend uses strict-JSON prompting with balanced-brace extraction as a fallback path.
- **Stateless model, by design.** The simulator models stateless L3/L4 filtering (no conntrack). For stateful firewalls, the rendered output is the initiating-direction policy; add your own `ct state established,related accept` preamble. Scope limitations are stated rather than hidden.

## Tests

```bash
pytest tests/ -v   # fully offline — the LLM is mocked
```

The suite covers first-match semantics, CIDR/port boundary behavior, oracle conflict detection, probe coverage, verifier catches (off-by-one ports, shadowed rules, wrong defaults), the full repair loop, the refuse-when-unverifiable path, and the nftables renderer.
