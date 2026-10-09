"""LLM triage for honeypot alerts.

Pipeline per run: load alerts (local detections, a JSONL file, or Sentinel) ->
skip alerts already triaged (SQLite store) -> enrich (honeypot activity, asset
inventory, threat intel) -> group into cases (same source, or shared attacker
infrastructure) -> one Claude call per case -> validated verdict per alert ->
store, JSONL, and optionally a Sentinel incident comment/update.

    # Offline: local detections over a Cowrie log, then triage
    python -m triage.triage_agent --events data/raw/cowrie_simulated.json

    # One call per alert instead of per case
    python -m triage.triage_agent --events data/raw/cowrie_simulated.json --mode alert

    # Production: every 10 minutes, Sentinel detections over the last hour, comments on incidents
    python -m triage.triage_agent --sentinel --lookback 1h --watch 10m --writeback comment

    # See exactly what would be sent, without calling the API
    python -m triage.triage_agent --events data/raw/cowrie_simulated.json --limit 1 --dry-run
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from typing import Any, Literal

import anthropic
from dotenv import load_dotenv
from pydantic import BaseModel, ValidationError

from triage.correlate import Case, build_cases
from triage.enrich import EventSource, IntelCache, LocalEventSource, enrich

log = logging.getLogger("triage")

PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "triage_prompt.txt"
DEFAULT_MODEL = "claude-opus-5-5"
DEFAULT_EFFORT = "medium"
FALLBACK_BETA = "server-side-fallback-2026-07-01"
MAX_CASE_SOURCES = 8  # sources with full enrichment in one case request; the rest are listed by IP only

Verdict = Literal["malicious", "suspicious", "benign"]
Severity = Literal["critical", "high", "medium", "low", "informational"]
SEVERITIES: tuple[str, ...] = ("informational", "low", "medium", "high", "critical")


class Technique(BaseModel):
    id: str
    name: str


class TriageResult(BaseModel):
    verdict: Verdict
    severity: Severity
    confidence: float
    attack_techniques: list[Technique]
    summary: str
    key_evidence: list[str]
    recommended_actions: list[str]
    escalate: bool


# Hand-written so it stays within what structured outputs accepts (no numeric bounds).
OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["malicious", "suspicious", "benign"]},
        "severity": {"type": "string", "enum": list(reversed(SEVERITIES))},
        "confidence": {"type": "number", "description": "0.0 to 1.0"},
        "attack_techniques": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"id": {"type": "string"}, "name": {"type": "string"}},
                "required": ["id", "name"],
                "additionalProperties": False,
            },
        },
        "summary": {"type": "string"},
        "key_evidence": {"type": "array", "items": {"type": "string"}},
        "recommended_actions": {"type": "array", "items": {"type": "string"}},
        "escalate": {"type": "boolean"},
    },
    "required": ["verdict", "severity", "confidence", "attack_techniques", "summary", "key_evidence",
                 "recommended_actions", "escalate"],
    "additionalProperties": False,
}


def build_user_message(alert: dict[str, Any], enrichment: dict[str, Any]) -> str:
    return (
        "<alert>\n" + json.dumps(alert, indent=1) + "\n</alert>\n\n"
        "<enrichment>\n" + json.dumps(enrichment, indent=1) + "\n</enrichment>\n\n"
        "Triage this alert."
    )


def build_case_message(case: Case) -> str:
    ips = case.src_ips
    enrichment: dict[str, Any] = {ip: case.contexts[ip] for ip in ips[:MAX_CASE_SOURCES]}
    if len(ips) > MAX_CASE_SOURCES:
        enrichment["_omitted_sources"] = ips[MAX_CASE_SOURCES:]
    return (
        "<case>\n" + json.dumps(case.summary(), indent=1) + "\n</case>\n\n"
        "<enrichment>\n" + json.dumps(enrichment, indent=1) + "\n</enrichment>\n\n"
        "Triage this case. Your verdict applies to every alert in it."
    )


class TriageAgent:
    def __init__(self, client: anthropic.Anthropic | None = None, model: str | None = None,
                 effort: str | None = None, fallbacks: bool | None = None, system_prompt: str | None = None,
                 budget=None):
        self.client = client or anthropic.Anthropic(max_retries=4)
        self.budget = budget  # triage.budget.DailyBudget or None
        self.model = model or os.getenv("TRIAGE_MODEL", DEFAULT_MODEL)
        self.effort = effort if effort is not None else os.getenv("TRIAGE_EFFORT", DEFAULT_EFFORT)
        self.fallbacks = fallbacks if fallbacks is not None else os.getenv("TRIAGE_FALLBACKS", "default") != "off"
        self.system_prompt = system_prompt or PROMPT_PATH.read_text(encoding="utf-8")

    def request_params(self, user_message: str) -> dict[str, Any]:
        output_config: dict[str, Any] = {"format": {"type": "json_schema", "schema": OUTPUT_SCHEMA}}
        if self.effort:
            output_config["effort"] = self.effort
        params: dict[str, Any] = {
            "model": self.model,
            "max_tokens": 16000,
            # The system prompt is identical for every request, so cache it.
            "system": [{"type": "text", "text": self.system_prompt, "cache_control": {"type": "ephemeral"}}],
            "messages": [{"role": "user", "content": user_message}],
            "output_config": output_config,
        }
        if self.fallbacks:
            # Security content can trip the safety classifiers; "default" re-runs a declined
            # request on Anthropic's recommended fallback model for that refusal category.
            params["betas"] = [FALLBACK_BETA]
            params["fallbacks"] = "default"
        return params

    def triage(self, alert: dict[str, Any], enrichment: dict[str, Any]) -> dict[str, Any]:
        """One request for one alert."""
        return {"alert_id": alert["alert_id"], **self._call(build_user_message(alert, enrichment))}

    def triage_case(self, case: Case) -> list[dict[str, Any]]:
        """One request for a whole case; returns one record per alert, in case.alerts order.

        Token usage is attached to the first alert's record only, so summing usage
        over records gives the true cost.
        """
        shared = self._call(build_case_message(case))
        records = []
        for i, alert in enumerate(case.alerts):
            record = {"alert_id": alert["alert_id"], "case_id": case.case_id, "case_size": len(case.alerts), **shared}
            if i:
                record.pop("usage", None)
                record["latency_ms"] = None
            records.append(record)
        return records

    def _call(self, user_message: str) -> dict[str, Any]:
        record: dict[str, Any] = {"model_requested": self.model, "triage": None}
        if self.budget is not None and not self.budget.allow():
            record["error"] = f"daily budget exhausted ({self.budget.describe()}); retried tomorrow"
            return record
        started = time.monotonic()
        try:
            response = self.client.beta.messages.create(**self.request_params(user_message))
        except anthropic.APIStatusError as exc:
            record["error"] = f"API error {exc.status_code}: {exc.message}"
            return record
        except anthropic.APIConnectionError as exc:
            record["error"] = f"connection error: {exc}"
            return record
        finally:
            record["latency_ms"] = round((time.monotonic() - started) * 1000)

        usage = response.usage
        record.update({
            "model_served": response.model,
            "stop_reason": response.stop_reason,
            "request_id": getattr(response, "_request_id", None),
            "usage": {
                "input_tokens": usage.input_tokens,
                "output_tokens": usage.output_tokens,
                "cache_read_input_tokens": getattr(usage, "cache_read_input_tokens", 0) or 0,
                "cache_creation_input_tokens": getattr(usage, "cache_creation_input_tokens", 0) or 0,
            },
        })
        if self.budget is not None:
            self.budget.record(record["usage"], response.model)
        if response.stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            record["error"] = f"refused (category: {getattr(details, 'category', None)})"
            return record
        if response.stop_reason == "max_tokens":
            record["error"] = "hit max_tokens before finishing the verdict"
            return record

        text = next((b.text for b in response.content if b.type == "text"), None)
        if text is None:
            record["error"] = "no text block in response"
            return record
        try:
            data = json.loads(text)
            data["confidence"] = min(1.0, max(0.0, float(data.get("confidence", 0))))
            record["triage"] = TriageResult.model_validate(data).model_dump()
        except (json.JSONDecodeError, ValidationError, TypeError, ValueError) as exc:
            record["error"] = f"invalid verdict JSON: {exc}"
            record["raw_text"] = text[:2000]
        return record


def triage_pairs(agent: TriageAgent, pairs: list[tuple[dict[str, Any], dict[str, Any]]], mode: str,
                 workers: int) -> dict[str, dict[str, Any]]:
    """Triage (alert, enrichment) pairs per case or per alert. Returns alert_id -> result record."""
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        if mode == "case":
            results = [r for batch in pool.map(agent.triage_case, build_cases(pairs)) for r in batch]
        else:
            results = list(pool.map(lambda p: agent.triage(*p), pairs))
    return {r["alert_id"]: r for r in results}


def parse_duration(text: str) -> timedelta:
    match = re.fullmatch(r"(\d+)\s*([mhd])", text.strip())
    if not match:
        raise argparse.ArgumentTypeError("use e.g. 90m, 24h, 7d")
    value, unit = int(match.group(1)), match.group(2)
    return timedelta(**{{"m": "minutes", "h": "hours", "d": "days"}[unit]: value})


parse_lookback = parse_duration  # backwards-compatible name


def load_alerts(args: argparse.Namespace) -> tuple[list[dict[str, Any]], EventSource | None]:
    if args.sentinel:
        from triage.sentinel import SentinelEventSource

        workspace = os.getenv("AZURE_LOG_ANALYTICS_WORKSPACE_ID")
        if not workspace:
            sys.exit("Set AZURE_LOG_ANALYTICS_WORKSPACE_ID to use --sentinel")
        source = SentinelEventSource(workspace)
        return source.run_detections(args.lookback, args.rule), source

    if not args.events:
        sys.exit("Provide --events (Cowrie log) or --sentinel")
    from detections.local_rules import run_all
    from ingestion.parsers.cowrie_parser import load_events

    events = load_events(args.events)
    source = LocalEventSource(events)
    if args.alerts:
        alerts = [json.loads(line) for line in Path(args.alerts).read_text(encoding="utf-8").splitlines() if line.strip()]
    else:
        alerts = run_all(events)
    if args.rule:
        alerts = [a for a in alerts if a["rule_id"] in args.rule]
    return alerts, source


def print_summary(pairs, results) -> None:
    print(f"\n{'alert':<15} {'case':<16} {'src_ip':<15} {'verdict':<10} {'sev':<13} {'esc':<4} summary", file=sys.stderr)
    for alert, _ in pairs:
        result = results[alert["alert_id"]]
        t = result.get("triage")
        line = (f"{t['verdict']:<10} {t['severity']:<13} {'yes' if t['escalate'] else 'no':<4} {t['summary'][:60]}"
                if t else f"ERROR: {result.get('error')}")
        print(f"{alert['alert_id']:<15} {result.get('case_id') or '-':<16} {alert['src_ip']:<15} {line}", file=sys.stderr)


def run_cycle(args: argparse.Namespace, agent: TriageAgent | None, store, writer, cache: IntelCache) -> int:
    alerts, source = load_alerts(args)
    total = len(alerts)
    if store is not None and not args.retriage:
        done = store.triaged_ids(a["alert_id"] for a in alerts)
        alerts = [a for a in alerts if a["alert_id"] not in done]
        log.info("%d alerts, %d already triaged, %d new", total, total - len(alerts), len(alerts))
    if args.limit:
        alerts = alerts[: args.limit]
    if not alerts:
        log.info("Nothing new to triage")
        return 0

    pairs = [(alert, enrich(alert, source, with_intel=not args.no_intel, cache=cache, payload_dir=args.payload_dir))
             for alert in alerts]

    if args.dry_run:
        dry = TriageAgent(client=anthropic.Anthropic(api_key="dry-run"))
        message = build_case_message(build_cases(pairs)[0]) if args.mode == "case" else build_user_message(*pairs[0])
        params = dry.request_params(message)
        params["system"] = [{**params["system"][0], "text": f"<{len(dry.system_prompt)} chars from {PROMPT_PATH.name}>"}]
        print(json.dumps(params, indent=2))
        return 0

    assert agent is not None
    results = triage_pairs(agent, pairs, args.mode, args.workers)
    calls = len({r.get("case_id") or r["alert_id"] for r in results.values()})
    log.info("%d alerts triaged with %d API call(s)", len(results), calls)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a" if args.watch else "w", encoding="utf-8") as fh:
        for alert, enrichment in pairs:
            result = results[alert["alert_id"]]
            fh.write(json.dumps({"alert": alert, "enrichment": enrichment, "result": result}) + "\n")
            if store is not None:
                store.save(alert, enrichment, result)

    if writer is not None:
        for alert, _ in pairs:
            result = results[alert["alert_id"]]
            if not result.get("triage"):
                continue
            try:
                status = writer.apply(alert, result)
            except Exception as exc:  # one failed write-back must not stop the rest
                log.error("Write-back failed for %s: %s", alert["alert_id"], exc)
                continue
            if store is not None:
                store.mark_written_back(alert["alert_id"], status, writer.last_incident_id)

    print_summary(pairs, results)
    errors = sum(1 for r in results.values() if not r.get("triage"))
    print(f"\n{len(results) - errors}/{len(results)} triaged in {calls} call(s), {errors} errors -> {out}", file=sys.stderr)
    return 1 if errors == len(results) else 0


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = parser.add_argument_group("alert source")
    src.add_argument("--events", help="Cowrie log (raw cowrie.json or normalized rows) for local detections + context")
    src.add_argument("--alerts", help="pre-computed alerts (JSONL); context still comes from --events")
    src.add_argument("--sentinel", action="store_true", help="run the KQL detections in Sentinel instead")
    src.add_argument("--lookback", type=parse_duration, default=timedelta(hours=24), help="Sentinel window (default 24h)")
    parser.add_argument("--rule", action="append", help="only this rule id (repeatable), e.g. 02_download_command")
    parser.add_argument("--mode", choices=("case", "alert"), default="case",
                        help="one request per correlated case (default) or per alert")
    parser.add_argument("--limit", type=int, help="triage at most N new alerts per cycle")
    parser.add_argument("--workers", type=int, default=4, help="parallel API calls")
    parser.add_argument("--no-intel", action="store_true", help="skip AbuseIPDB/GreyNoise lookups")
    parser.add_argument("--dry-run", action="store_true", help="print the first request and exit")
    parser.add_argument("--out", default="data/processed/triage_results.jsonl")
    parser.add_argument("--db", default=os.getenv("TRIAGE_DB", "data/soc.db"), help="SQLite store ('' to disable)")
    parser.add_argument("--retriage", action="store_true", help="triage alerts again even if the store has a verdict")
    parser.add_argument("--watch", type=parse_duration, help="repeat every interval (e.g. 10m) until stopped")
    parser.add_argument("--writeback", choices=("off", "comment", "update", "close"), default="off",
                        help="write verdicts to Sentinel incidents (needs AZURE_WORKSPACE_RESOURCE_ID)")
    parser.add_argument("--daily-budget", type=float, default=float(os.getenv("TRIAGE_DAILY_BUDGET_USD") or 0),
                        help="stop calling the API once today's estimated spend reaches this many USD (0 = no cap)")
    parser.add_argument("--payload-dir", default=os.getenv("COWRIE_DOWNLOADS_DIR"),
                        help="Cowrie downloads directory; captured payloads are statically analysed for the model")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    from triage.store import Store

    store = Store(args.db) if args.db and not args.dry_run else None
    writer = None
    if args.writeback != "off" and not args.dry_run:
        from triage.writeback import SentinelWriter

        workspace = os.getenv("AZURE_WORKSPACE_RESOURCE_ID")
        if not workspace:
            sys.exit("Set AZURE_WORKSPACE_RESOURCE_ID (printed by siem/infra/deploy.ps1) to use --writeback")
        writer = SentinelWriter(workspace, mode=args.writeback)
    budget = None
    if args.daily_budget > 0 and not args.dry_run:
        from triage.budget import DailyBudget

        budget = DailyBudget(args.daily_budget, store)
        log.info("Daily budget: %s", budget.describe())
    agent = None if args.dry_run else TriageAgent(budget=budget)
    cache = IntelCache()

    if not args.watch:
        return run_cycle(args, agent, store, writer, cache)

    stopping = False

    def stop(*_: Any) -> None:
        nonlocal stopping
        stopping = True
        log.info("Stopping after this cycle")

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    while not stopping:
        try:
            run_cycle(args, agent, store, writer, cache)
        except Exception:
            log.exception("Triage cycle failed; retrying next interval")
        deadline = time.monotonic() + args.watch.total_seconds()
        while not stopping and time.monotonic() < deadline:
            time.sleep(1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
