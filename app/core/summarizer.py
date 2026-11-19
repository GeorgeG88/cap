"""Optional plain-language report summary using a local Ollama model.

Detection never depends on this module: the model only receives already
aggregated statistics (no raw log lines) and its output is shown as clearly
labelled, AI-generated text that the analyst must verify.

Ollama runs language models on the local machine and offers a small HTTP
API. Two endpoints are used:
  GET  /api/tags      list the installed models (for the Settings page)
  POST /api/generate  send a prompt and receive the model's answer
Because the model runs locally, no firewall data leaves the network.
"""

from __future__ import annotations

import json

import requests

# Local models can be slow on modest hardware, so allow up to two minutes.
TIMEOUT = 120


class SummaryError(Exception):
    """Any problem talking to Ollama; shown to the user as a message."""
    pass


def list_models(base_url: str, timeout: int = 3) -> list:
    """Return installed model names, or raise SummaryError if Ollama is unreachable.

    A short timeout keeps the Settings page fast when Ollama is not running.
    """
    try:
        resp = requests.get(base_url.rstrip("/") + "/api/tags", timeout=timeout)
        resp.raise_for_status()
        return sorted(m["name"] for m in resp.json().get("models", []))
    except (requests.RequestException, ValueError, KeyError) as exc:
        raise SummaryError(f"Ollama not reachable at {base_url}: {exc.__class__.__name__}") from exc


def build_prompt(stats: dict, alerts: list) -> str:
    """Write the instructions and data for the model.

    Only aggregated figures and alert summaries are included (at most 40
    alerts), never raw log lines. This keeps the prompt short and limits
    what text from the network can reach the model. The instructions tell
    the model to use only the given data, to reduce invented facts.
    """
    alert_lines = []
    for a in alerts[:40]:
        summary = (a.details or {}).get("summary", "")
        alert_lines.append(f"- [{a.severity}] {a.rule_name} from {a.src_ip}, "
                           f"{a.first_seen:%Y-%m-%d %H:%M} to {a.last_seen:%H:%M}, {summary}, status {a.status}")
    data = {
        "scope": stats["scope"],
        "events": stats["events"],
        "alerts_by_severity": stats["alerts"]["by_severity"],
        "alerts_by_rule": stats["alerts"]["by_rule"],
        "top_sources": stats["top_sources"][:5],
        "top_ports": stats["top_ports"][:5],
    }
    return (
        "You are a security analyst writing a short report section for a small organisation's "
        "IT staff. Using ONLY the firewall statistics and alerts below, write 2-3 short paragraphs: "
        "(1) what happened overall, (2) the most important threats and which source IPs are involved, "
        "(3) concrete recommended actions. Do not invent facts, IPs or numbers that are not in the data. "
        "Plain text only, no markdown.\n\n"
        f"STATISTICS:\n{json.dumps(data, indent=1, default=str)}\n\n"
        "ALERTS:\n" + ("\n".join(alert_lines) if alert_lines else "(none)")
    )


def summarize(base_url: str, model: str, stats: dict, alerts: list) -> str:
    """Ask the selected model for a summary and return its text."""
    if not model:
        raise SummaryError("No Ollama model selected (Settings page).")
    try:
        # stream=False returns the whole answer in one response.
        # A low temperature makes the output more factual and less creative.
        resp = requests.post(base_url.rstrip("/") + "/api/generate",
                             json={"model": model, "prompt": build_prompt(stats, alerts),
                                   "stream": False, "options": {"temperature": 0.2}},
                             timeout=TIMEOUT)
        resp.raise_for_status()
        text = resp.json().get("response", "").strip()
    except (requests.RequestException, ValueError) as exc:
        raise SummaryError(f"Ollama request failed: {exc.__class__.__name__}") from exc
    if not text:
        raise SummaryError("The model returned an empty response.")
    return text
