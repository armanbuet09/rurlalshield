"""Explicit local synthetic experiment. Default mode makes no network requests."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src" / "external_ai"), str(ROOT / "src" / "lambda" / "triage")]
import adapter
import experiment

SOURCES = ["src/external_ai/adapter.py", "src/external_ai/experiment.py", "src/external_ai/handler.py",
           "src/lambda/triage/policy.py", "src/lambda/triage/prompts.py", "scripts/external-ai-experiment.py",
           "scripts/external-ai-stack.ts"]


def source_hashes():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}


def load_key(env_file: Path | None):
    if env_file:
        # Parse only a literal env assignment; never execute an env file as shell code.
        matches = [line.split("=", 1)[1].strip().strip("\"'") for line in env_file.read_text(encoding="utf-8-sig").splitlines()
                   if line.strip().startswith("OPENAI_API_KEY=")]
        if len(matches) != 1:
            raise adapter.ExperimentError("missing_or_ambiguous_local_credential")
        return matches[0]
    return os.environ.get("OPENAI_API_KEY", "")


def write_evidence(records: list, plan: dict, directory: Path):
    directory.mkdir(parents=True, exist_ok=False)
    files = {}
    for name, data in [("plan.json", plan)] + [(r["case_id"] + ".json", r) for r in records]:
        path = directory / name
        path.write_text(json.dumps(data, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    index = {"kind": "separate_synthetic_external_ai_experiment", "files": files,
             "attempted_requests": len(records), "valid_responses": sum(r["status"] == "valid_response" for r in records),
             "estimated_usd_known": sum(r["estimated_usd"] or 0 for r in records),
             "unknown_cost_requests": sum(r["estimated_usd"] is None for r in records),
             "all_costs_known": bool(records) and all(r["estimated_usd"] is not None for r in records),
             "five_day_pilot_data": False, "actions_executed": 0}
    (directory / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    verified = all(hashlib.sha256((directory / name).read_bytes()).hexdigest() == sha for name, sha in files.items())
    if not verified:
        raise adapter.ExperimentError("evidence_verification_failed")
    return index


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--live", action="store_true")
    mode.add_argument("--package", action="store_true", help="Stage a standalone Lambda asset; no AWS calls")
    parser.add_argument("--case", choices=experiment.CASE_IDS, action="append")
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--acknowledge-external-processing", action="store_true")
    parser.add_argument("--max-estimated-usd", type=float, default=0.05)
    args = parser.parse_args()
    cases = args.case or list(experiment.CASE_IDS)
    if len(set(cases)) != len(cases):
        parser.error("Each synthetic case may be requested once per run")
    plan = {"created_at": datetime.now(timezone.utc).isoformat(), "mode": "live" if args.live else "offline_plan",
            "provider": "OpenAI direct API", "model": adapter.MODEL, "case_ids": cases,
            "source_sha256": source_hashes(), "rates_usd_per_million": adapter.RATES,
            "rate_date": adapter.RATE_DATE, "requests": {case: experiment.prepare(case)[0] for case in cases},
            "max_requests": len(cases), "max_output_tokens_per_request": adapter.MAX_OUTPUT_TOKENS,
            "automatic_retries": 0, "actions_executed": 0, "five_day_pilot_unchanged": True,
            "cost_limit_note": "Estimate guard, not an API billing cap; missing usage stops the run."}
    if args.package:
        destination = ROOT / "cdk.out" / "external-ai-asset"
        destination.mkdir(parents=True, exist_ok=True)
        # Copy exactly the five reviewed runtime files. Never copy env/config/evidence.
        for source in SOURCES[:5]:
            shutil.copyfile(ROOT / source, destination / Path(source).name)
        (destination / "source-manifest.json").write_text(json.dumps(plan["source_sha256"], indent=2) + "\n")
        print(json.dumps({"status": "packaged_only", "path": str(destination), "aws_calls": 0}))
        return
    records = []
    if args.live:
        if not args.acknowledge_external_processing:
            parser.error("Live mode requires --acknowledge-external-processing")
        if not 0 < args.max_estimated_usd <= 0.05:
            parser.error("This tiny pilot permits a positive estimate guard no greater than USD 0.05")
        key = load_key(args.env_file)
        if not key:
            raise adapter.ExperimentError("missing_local_credential")
        spent = 0
        for case in cases:
            # Reserve USD .01 per small request; this is conservative planning, not metering enforcement.
            if spent + 0.01 > args.max_estimated_usd:
                plan["stopped_reason"] = "estimate_guard"
                break
            record = experiment.evaluate(case, key, str(args.ca_file) if args.ca_file else None)
            records.append(record)
            if record["status"] != "valid_response" or record["estimated_usd"] is None:
                plan["stopped_reason"] = "failed_or_unknown_cost_request"
                break
            spent += record["estimated_usd"]
    destination = ROOT / "research-evidence" / "ai-experiments" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    index = write_evidence(records, plan, destination)
    print(json.dumps({"status": "live_recorded" if args.live else "offline_plan_only", "directory": str(destination),
                      "attempted_requests": index["attempted_requests"], "valid_responses": index["valid_responses"],
                      "estimated_usd_known": index["estimated_usd_known"], "unknown_cost_requests": index["unknown_cost_requests"]}))


if __name__ == "__main__":
    try:
        main()
    except adapter.ExperimentError as exc:
        print(json.dumps({"status": exc.code}), file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError):
        print('{"status":"local_file_or_configuration_error"}', file=sys.stderr)
        sys.exit(1)
