"""Isolated, bounded GPT-5.6 Luna Mantle compatibility probe.

Uses existing temporary AWS credentials with SigV4. No API keys, deployments,
agreement acceptance, workflow invocations, or containment actions are created.
At most three inference requests: 64 + 1,400 + 1,400 output tokens. This test is
research instrumentation, separate from the frozen non-AI observation.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cdk.out/python-tools"))
sys.path.insert(0, str(ROOT / "src/lambda/triage"))
import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.httpsession import URLLib3Session
import policy
import prompts
from test_policy import asff_event

REGION = "us-east-2"
MODEL = "openai.gpt-5.6-luna"
ORIGIN = "https://bedrock-mantle.us-east-2.api.aws"
BASE = ORIGIN + "/openai/v1"
PROFILE = "ruralshield-research"


def validate_contract(value, schema, location="assessment"):
    """Validate every constraint used by the current flat assessment contract.

    This is intentionally not represented as a complete JSON Schema engine.
    Unknown schema keywords fail the probe rather than silently being ignored.
    """
    supported = {"type", "properties", "required", "additionalProperties", "items",
                 "enum", "minimum", "maximum", "minItems", "maxItems", "description"}
    assert not set(schema)-supported, "Unsupported contract constraints"
    kind = schema["type"]
    if kind == "object":
        assert isinstance(value, dict), f"{location}: expected object"
        assert set(schema.get("required", [])) <= value.keys(), f"{location}: required fields missing"
        if schema.get("additionalProperties") is False:
            assert value.keys() <= schema["properties"].keys(), f"{location}: unexpected fields"
        for key, sub in schema["properties"].items():
            if key in value:
                validate_contract(value[key], sub, location+"."+key)
    elif kind == "string":
        assert isinstance(value, str), f"{location}: expected string"
    elif kind == "number":
        assert type(value) in (int, float) and math.isfinite(value), f"{location}: expected finite number"
        assert value >= schema.get("minimum", -math.inf), f"{location}: below minimum"
        assert value <= schema.get("maximum", math.inf), f"{location}: above maximum"
    elif kind == "array":
        assert isinstance(value, list), f"{location}: expected array"
        assert len(value) >= schema.get("minItems", 0), f"{location}: too few items"
        assert len(value) <= schema.get("maxItems", math.inf), f"{location}: too many items"
        for i, item in enumerate(value):
            validate_contract(item, schema["items"], f"{location}[{i}]")
    else:
        raise ValueError("Unsupported assessment type: "+kind)
    if "enum" in schema:
        assert value in schema["enum"], f"{location}: invalid enum"


def main():
    connectivity_only = "--connectivity-only" in sys.argv
    session = boto3.Session(profile_name=PROFILE, region_name=REGION)
    identity = session.client("sts").get_caller_identity()
    assert identity["Account"] == "123456789012"
    assert identity["Arn"].endswith(":user/ruralshield-deployer")
    credentials = session.get_credentials().get_frozen_credentials()
    # Never save signed headers, credential objects, refresh tokens, or API keys.
    transport = URLLib3Session(verify=session._session.get_config_variable("ca_bundle") or True,
                              timeout=(10, 60))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = ROOT / "research-evidence/model-tests" / ("mantle-luna-"+stamp)
    out.mkdir(parents=True, exist_ok=False)
    state_path = ROOT / "cdk.out/observation-state.json"
    state_hash = sha256(state_path.read_bytes()).hexdigest()
    state = json.loads(state_path.read_text())
    report = {"startedAt": datetime.now(timezone.utc).isoformat(), "modelId": MODEL,
              "region": REGION, "endpoint": BASE, "authentication": "existing AWS temporary credentials, SigV4",
              "condition": "isolated synthetic model compatibility test; outside frozen non-AI pilot",
              "scope": "connectivity-only" if connectivity_only else "connectivity and two structured triage cases",
              "outputTokenBudget": 64 if connectivity_only else 2864, "requests": [], "checks": {},
              "guardrailsTested": False, "containmentExecuted": False, "pilotModified": False,
              "limitations": "Tiny synthetic compatibility probes; not triage accuracy, safety, clinical validation, or a Sentinel end-to-end run."}

    def save():
        (out / "result.json").write_text(json.dumps(report, indent=2, default=str)+"\n", encoding="utf-8")

    def observer_snapshot():
        f = session.client("lambda").get_function_configuration(FunctionName=state["outputs"]["RunnerName"])
        return {"codeSha256": f["CodeSha256"], "state": f["State"],
                "ruleState": session.client("events").describe_rule(Name=state["outputs"]["RuleName"])["State"],
                "matchesFrozenCode": f["CodeSha256"] == state["manifest"]["instrumentationCodeSha256"]}

    def request(name, path, payload=None):
        assert path in ("/models", "/chat/completions")
        if payload is not None:
            assert payload["model"] == MODEL
            assert sum(x.get("maxCompletionTokens", 0) for x in report["requests"])+payload["max_completion_tokens"] <= 2864
            (out / (name+"-request.json")).write_text(json.dumps(payload, indent=2)+"\n", encoding="utf-8")
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        # Catalog listing is endpoint-wide; closed OpenAI inference uses its
        # model-specific /openai/v1 route. A catalog failure is informational.
        url = ORIGIN+"/v1/models" if path == "/models" else BASE+path
        req = AWSRequest(method="POST" if payload is not None else "GET", url=url,
                         data=body, headers={"Content-Type": "application/json", "Accept": "application/json"})
        SigV4Auth(credentials, "bedrock-mantle", REGION).add_auth(req)
        started = time.monotonic()
        record = {"name": name, "method": req.method, "url": url,
                  "maxCompletionTokens": payload["max_completion_tokens"] if payload else 0}
        report["requests"].append(record)
        try:
            response = transport.send(req.prepare())
            text = response.content.decode("utf-8", errors="replace")
            for secret in (credentials.access_key, credentials.secret_key, credentials.token):
                if secret:
                    text = text.replace(secret, "[REDACTED]")
            try:
                data = json.loads(text)
            except ValueError:
                data = {"nonJsonResponse": text[:500]}
            record.update({"httpStatus": response.status_code,
                           "clientElapsedMs": round((time.monotonic()-started)*1000, 2),
                           "requestId": response.headers.get("x-amzn-requestid") or response.headers.get("x-request-id"),
                           "usage": data.get("usage")})
            (out / (name+"-response.json")).write_text(json.dumps(data, indent=2)+"\n", encoding="utf-8")
            if response.status_code != 200:
                record["error"] = data.get("error", data)
            save()
            print(json.dumps(record), flush=True)
            return response.status_code, data
        except Exception as e:
            record["transportError"] = type(e).__name__
            record["clientElapsedMs"] = round((time.monotonic()-started)*1000, 2)
            save()
            raise

    report["observerBefore"] = observer_snapshot()
    assert report["observerBefore"]["matchesFrozenCode"]
    try:
        status, models = request("model-list", "/models")
        report["checks"]["modelListed"] = status == 200 and any(x.get("id") == MODEL for x in models.get("data", []))
        status, reply = request("connectivity", "/chat/completions", {
            "model": MODEL, "messages": [{"role": "user", "content": "Reply with exactly RURALSHIELD_MODEL_OK. Synthetic connectivity test only."}],
            "max_completion_tokens": 64, "reasoning_effort": "none", "stream": False})
        report["checks"]["connectivity"] = status == 200 and reply.get("choices", [{}])[0].get("message", {}).get("content", "").strip() == "RURALSHIELD_MODEL_OK"
        if not report["checks"]["connectivity"]:
            report["blockedAt"] = "connectivity"
            return False
        if connectivity_only:
            return True
        schema = copy.deepcopy(prompts.RECORD_TRIAGE_TOOL["toolSpec"]["inputSchema"]["json"])
        schema["additionalProperties"] = False
        for name, event, expected_mode in [
            ("synthetic-threat", asff_event(), "APPROVAL"),
            ("synthetic-posture", asff_event(ProductName="Security Hub",
                Types=["Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices"],
                Resources=[{"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::synthetic-test-bucket"}]), "NOTIFY"),
        ]:
            finding = policy.normalize_finding(event)
            for target in finding.targets:
                target.protected = False
            payload = {"model": MODEL, "messages": [
                {"role": "system", "content": prompts.SYSTEM_PROMPT},
                {"role": "user", "content": prompts.build_user_message(finding, {"notes": ["Synthetic offline fixture. No AWS enrichment calls or actions."]})}],
                "tools": [{"type": "function", "function": {"name": "record_triage",
                    "description": prompts.RECORD_TRIAGE_TOOL["toolSpec"]["description"],
                    "parameters": schema, "strict": True}}],
                "tool_choice": {"type": "function", "function": {"name": "record_triage"}},
                "parallel_tool_calls": False, "max_completion_tokens": 1400,
                "reasoning_effort": "none", "stream": False}
            status, reply = request(name, "/chat/completions", payload)
            if status != 200:
                report["blockedAt"] = name
                break
            choice = reply["choices"][0]
            calls = choice["message"].get("tool_calls", [])
            assert len(calls) == 1 and calls[0]["function"]["name"] == "record_triage", "Expected one named tool call"
            assessment = json.loads(calls[0]["function"]["arguments"])
            validate_contract(assessment, schema)
            decision = policy.decide(finding, assessment["recommended_playbook"], assessment["confidence"], False, model_used=True)
            assert decision.action_mode == expected_mode, "Unexpected offline policy route"
            report["checks"][name] = {"namedToolCall": True, "contractValidated": True,
                "finishReason": choice.get("finish_reason"), "playbook": assessment["recommended_playbook"],
                "offlinePolicyMode": decision.action_mode, "automaticContainmentEnabled": False}
            (out / (name+"-offline-policy.json")).write_text(json.dumps(decision.to_dict(), indent=2)+"\n")
            save()
    finally:
        report["observerAfter"] = observer_snapshot()
        report["checks"]["frozenObserverUnchanged"] = report["observerBefore"] == report["observerAfter"]
        report["checks"]["localObservationManifestUnchanged"] = state_hash == sha256(state_path.read_bytes()).hexdigest()
        report["finishedAt"] = datetime.now(timezone.utc).isoformat()
        report["evidenceDirectory"] = str(out.relative_to(ROOT))
        report["probeSourceSha256"] = sha256(Path(__file__).read_bytes()).hexdigest()
        report["promptSha256"] = sha256((ROOT/"src/lambda/triage/prompts.py").read_bytes()).hexdigest()
        report["policySha256"] = sha256((ROOT/"src/lambda/triage/policy.py").read_bytes()).hexdigest()
        for filename, source in [("probe-source.py", Path(__file__)),
                                 ("triage-prompts-source.py", ROOT/"src/lambda/triage/prompts.py"),
                                 ("triage-policy-source.py", ROOT/"src/lambda/triage/policy.py"),
                                 ("synthetic-fixtures-source.py", ROOT/"src/lambda/triage/test_policy.py")]:
            (out/filename).write_bytes(source.read_bytes())
        save()
        print(json.dumps({"evidenceDirectory": report["evidenceDirectory"], "checks": report["checks"],
                          "blockedAt": report.get("blockedAt"), "finishedAt": report["finishedAt"]}, indent=2), flush=True)
        assert report["checks"]["frozenObserverUnchanged"], "Frozen observer state changed during probe"
        assert report["checks"]["localObservationManifestUnchanged"], "Frozen observation manifest changed during probe"
    required = ["connectivity", "synthetic-threat", "synthetic-posture",
                "frozenObserverUnchanged", "localObservationManifestUnchanged"]
    return not report.get("blockedAt") and all(report["checks"].get(key) for key in required)


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
