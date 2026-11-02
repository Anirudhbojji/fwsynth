"""fwsynth CLI."""

import json
from pathlib import Path

import click

from .evaluator import evaluate
from .llm import pick_backend
from .model import Packet, Ruleset, Spec
from .render import render_nftables
from .synth import synthesize
from .verifier import verify


@click.group()
def cli() -> None:
    """Intent -> verified firewall rules (LLM proposes, simulator disposes)."""


@cli.command()
@click.argument("intent")
@click.option("--backend", "-b", default="auto",
              type=click.Choice(["auto", "anthropic", "claude-cli"]))
@click.option("--model", default=None, help="Override the model.")
@click.option("--max-repairs", default=3, show_default=True)
@click.option("--out", type=click.Path(dir_okay=False, path_type=Path),
              help="Write nftables output here.")
@click.option("--json-out", type=click.Path(dir_okay=False, path_type=Path),
              help="Write the verified spec+ruleset IR here.")
def compile(intent: str, backend: str, model: str | None, max_repairs: int,
            out: Path | None, json_out: Path | None) -> None:
    """Compile an English INTENT into verified nftables rules."""
    llm = pick_backend(backend, model)
    result = synthesize(intent, llm, max_repairs=max_repairs,
                        log=lambda m: click.secho(f"[fwsynth] {m}", fg="cyan"))

    if result.verdict and result.verdict.spec_conflicts:
        click.secho("\nSPEC CONFLICT — the intent contradicts itself:", fg="red", bold=True)
        for c in result.verdict.spec_conflicts[:5]:
            descs = " vs ".join(f"{p.action}:{p.description or p.src}" for p in c.properties)
            click.secho(f"  {c.packet}: {descs}", fg="red")
        raise SystemExit(2)

    if not result.ok:
        click.secho("\nVERIFICATION FAILED — refusing to emit rules.", fg="red", bold=True)
        for c in (result.verdict.counterexamples if result.verdict else [])[:10]:
            click.secho(f"  {c.describe()}", fg="red")
        raise SystemExit(1)

    nft = render_nftables(result.ruleset)
    click.echo()
    click.secho(f"# spec: {len(result.spec.properties)} properties | "
                f"probes: {result.verdict.probes_run} | repairs: {result.repairs_used}",
                fg="green", bold=True)
    click.echo(nft)

    if out:
        out.write_text(nft)
        click.secho(f"written to {out}", fg="green")
    if json_out:
        json_out.write_text(json.dumps(
            {"spec": result.spec.to_dict(), "ruleset": result.ruleset.to_dict()}, indent=2))
        click.secho(f"IR written to {json_out}", fg="green")


@cli.command()
@click.option("--ir", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="IR file from `compile --json-out` (spec + ruleset).")
def check(ir: Path) -> None:
    """Re-verify a saved ruleset against its spec (no LLM involved)."""
    data = json.loads(ir.read_text())
    spec, ruleset = Spec.from_dict(data["spec"]), Ruleset.from_dict(data["ruleset"])
    verdict = verify(spec, ruleset)
    if verdict.ok:
        click.secho(f"OK — {verdict.probes_run} probes, 0 disagreements", fg="green")
    else:
        for c in verdict.counterexamples:
            click.secho(f"  {c.describe()}", fg="red")
        raise SystemExit(1)


@cli.command()
@click.option("--ir", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--packet", "-p", required=True,
              help="src,dst,proto,dport — e.g. 10.20.0.9,8.8.8.8,udp,53")
def simulate(ir: Path, packet: str) -> None:
    """Ask the ruleset what happens to one packet."""
    src, dst, proto, dport = packet.split(",")
    pkt = Packet(src=src.strip(), dst=dst.strip(), proto=proto.strip(), dport=int(dport))
    data = json.loads(ir.read_text())
    ruleset = Ruleset.from_dict(data["ruleset"])
    action, rule = evaluate(ruleset, pkt)
    why = f"rule: {rule.comment or rule.src + ' -> ' + rule.dst}" if rule else "default policy"
    color = "green" if action == "allow" else "red"
    click.secho(f"{pkt} -> {action.upper()} ({why})", fg=color)


if __name__ == "__main__":
    cli()
