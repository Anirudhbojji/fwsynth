"""Pluggable LLM backends.

- AnthropicBackend: the Anthropic SDK with structured outputs — the schema is
  enforced server-side, so responses parse by construction.
- ClaudeCLIBackend: shells out to a local `claude` CLI (Claude Code) — zero
  API key needed on a machine with Claude Code installed.
- MockBackend: canned responses, for deterministic offline tests.
"""

import json
import os
import subprocess
from typing import Protocol

DEFAULT_MODEL = "claude-opus-4-8"


class LLMBackend(Protocol):
    def generate_json(self, system: str, user: str, schema: dict) -> dict: ...


class AnthropicBackend:
    def __init__(self, model: str = DEFAULT_MODEL) -> None:
        import anthropic
        self.client = anthropic.Anthropic()
        self.model = model

    def generate_json(self, system: str, user: str, schema: dict) -> dict:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=16000,
            thinking={"type": "adaptive"},
            system=system,
            messages=[{"role": "user", "content": user}],
            output_config={"format": {"type": "json_schema", "schema": schema}},
        )
        text = next(b.text for b in response.content if b.type == "text")
        return json.loads(text)


class ClaudeCLIBackend:
    """Uses `claude -p` (Claude Code print mode) as the inference engine."""

    def __init__(self, model: str | None = None) -> None:
        self.model = model

    def generate_json(self, system: str, user: str, schema: dict) -> dict:
        prompt = (
            f"{system}\n\n"
            f"Respond with ONLY a JSON object (no prose, no code fences) that "
            f"validates against this JSON schema:\n{json.dumps(schema)}\n\n"
            f"---\n{user}"
        )
        cmd = ["claude", "-p", "--output-format", "text"]
        if self.model:
            cmd += ["--model", self.model]
        result = subprocess.run(
            cmd, input=prompt, capture_output=True, text=True,
            timeout=600, cwd=os.environ.get("TMPDIR", "/tmp"),
        )
        if result.returncode != 0:
            raise RuntimeError(f"claude CLI failed: {result.stderr.strip()[:500]}")
        return _extract_json(result.stdout)


class MockBackend:
    """Replays a fixed sequence of responses (tests only)."""

    def __init__(self, responses: list[dict]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str]] = []

    def generate_json(self, system: str, user: str, schema: dict) -> dict:
        self.calls.append((system, user))
        if not self.responses:
            raise RuntimeError("MockBackend exhausted")
        return self.responses.pop(0)


def _extract_json(text: str) -> dict:
    """Pull the first top-level JSON object out of possibly-noisy output."""
    start = text.find("{")
    if start == -1:
        raise ValueError(f"no JSON object in output: {text[:200]!r}")
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i + 1])
    raise ValueError("unbalanced JSON object in output")


def pick_backend(name: str = "auto", model: str | None = None) -> LLMBackend:
    if name == "anthropic" or (name == "auto" and os.environ.get("ANTHROPIC_API_KEY")):
        return AnthropicBackend(model or DEFAULT_MODEL)
    if name in ("claude-cli", "auto"):
        return ClaudeCLIBackend(model)
    raise ValueError(f"unknown backend: {name}")
