"""Responses API transport and independent validation; no AWS action clients."""
from __future__ import annotations

import copy
import json
import math
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from typing import Any

ENDPOINT = "https://api.openai.com/v1/responses"
MODEL = "gpt-6-luna"
RATES = {"input": 0.10, "cached_input": 0.01, "cache_write_30m": 0.125,
         "cache_write_12h": 0.25, "output": 0.50}
RATE_DATE = "2026-10-31"
MAX_OUTPUT_TOKENS = 600
MAX_RESPONSE_BYTES = 262144
SAFE_ERROR_CODES = frozenset({
    "insufficient_quota", "credit_balance_exhausted", "organization_spend_limit_exceeded",
    "organization_usage_limit_exceeded", "project_spend_limit_exceeded", "rate_limit_exceeded",
    "slow_down", "invalid_api_key", "model_not_found", "permission_denied", "server_error",
})


class ExperimentError(Exception):
    """Only safe classifications enter logs, never HTTP bodies or exception text."""
    def __init__(self, code: str, **metadata: Any):
        super().__init__(code)
        self.code, self.metadata = code, metadata


def strict_json(text: str) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result
    try:
        return json.loads(text, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))
    except (ValueError, TypeError, RecursionError):
        raise ExperimentError("invalid_json") from None


def tool_schema(spec: dict) -> dict:
    schema = copy.deepcopy(spec["inputSchema"]["json"])
    schema["additionalProperties"] = False
    return {"type": "function", "name": spec["name"], "description": spec["description"],
            "parameters": schema, "strict": True}


def validate_assessment(value: Any, schema: dict) -> dict:
    if not isinstance(value, dict) or set(value) != set(schema["required"]):
        raise ExperimentError("invalid_assessment_fields")
    for key, rule in schema["properties"].items():
        item = value[key]
        kind = rule["type"]
        if kind == "string" and (not isinstance(item, str) or len(item) > 6000):
            raise ExperimentError("invalid_assessment_string")
        if "enum" in rule and item not in rule["enum"]:
            raise ExperimentError("invalid_assessment_enum")
        if kind == "number" and (type(item) not in (int, float) or not math.isfinite(item)
                                  or not rule.get("minimum", -math.inf) <= item <= rule.get("maximum", math.inf)):
            raise ExperimentError("invalid_assessment_number")
        if kind == "array" and (not isinstance(item, list)
                                 or not rule.get("minItems", 0) <= len(item) <= rule.get("maxItems", 20)
                                 or any(not isinstance(s, str) or len(s) > 6000 for s in item)):
            raise ExperimentError("invalid_assessment_array")
    return value


def parse_output(response: dict, tool: dict | None) -> Any:
    if response.get("status") != "completed":
        raise ExperimentError("incomplete_response")
    output = response.get("output")
    if not isinstance(output, list):
        raise ExperimentError("missing_output")
    for item in output:
        if not isinstance(item, dict) or ("content" in item and not isinstance(item["content"], list)):
            raise ExperimentError("invalid_output_shape")
    if any(c.get("type") == "refusal" for o in output
           for c in o.get("content", []) if isinstance(c, dict)):
        raise ExperimentError("refusal")
    # Reasoning summaries may be present; all actionable output must match our contract.
    actionable = [o for o in output if not isinstance(o, dict) or o.get("type") != "reasoning"]
    if tool:
        if len(actionable) != 1 or not isinstance(actionable[0], dict):
            raise ExperimentError("unexpected_tool_output")
        call = actionable[0]
        if (call.get("type") != "function_call" or call.get("name") != "record_triage"
                or call.get("status") != "completed"):
            raise ExperimentError("unexpected_tool_output")
        return validate_assessment(strict_json(call.get("arguments")), tool["parameters"])
    if len(actionable) != 1 or not isinstance(actionable[0], dict) or actionable[0].get("type") != "message":
        raise ExperimentError("unexpected_narration_output")
    content = actionable[0].get("content", [])
    if not content or any(not isinstance(c, dict) or c.get("type") != "output_text" for c in content):
        raise ExperimentError("unexpected_narration_output")
    if any(not isinstance(c.get("text"), str) for c in content):
        raise ExperimentError("invalid_narration")
    text = "\n".join(c["text"] for c in content)
    if not text.strip() or len(text) > 12000:
        raise ExperimentError("invalid_narration")
    return text


def usage_cost(response: dict) -> dict:
    usage = response.get("usage")
    if not isinstance(usage, dict):
        return {"usage": None, "estimated_usd": None, "cost_status": "unknown_usage"}
    inp, out = usage.get("input_tokens"), usage.get("output_tokens")
    details = usage.get("input_tokens_details")
    cached = details.get("cached_tokens") if isinstance(details, dict) else None
    writes = details.get("cache_write_tokens") if isinstance(details, dict) else None
    valid = lambda n: type(n) is int and n >= 0
    if not valid(inp) or not valid(out):
        return {"usage": usage, "estimated_usd": None, "cost_status": "invalid_usage"}
    if cached is None or writes is None:
        return {"usage": usage, "estimated_usd": None, "cost_status": "unknown_cache_usage"}
    if not valid(cached) or not valid(writes) or cached + writes > inp:
        return {"usage": usage, "estimated_usd": None, "cost_status": "invalid_usage"}
    lifetimes = details.get("cache_write_tokens_details")
    # This experiment sends no cache lifetime overrides: the documented default is 30m.
    short, long = writes, 0
    status = "token_estimate_default_30m" if writes else "token_estimate"
    if lifetimes is not None:
        if not isinstance(lifetimes, dict):
            return {"usage": usage, "estimated_usd": None, "cost_status": "invalid_usage"}
        short, long = lifetimes.get("ttl_30m_tokens"), lifetimes.get("ttl_12h_tokens")
        if not valid(short) or not valid(long) or short + long != writes:
            return {"usage": usage, "estimated_usd": None, "cost_status": "invalid_usage"}
        status = "token_estimate"
    if inp > 272000:
        return {"usage": usage, "estimated_usd": None, "cost_status": "unpriced_long_context"}
    cost = ((inp - cached - writes) * RATES["input"] + cached * RATES["cached_input"]
            + short * RATES["cache_write_30m"] + long * RATES["cache_write_12h"]
            + out * RATES["output"]) / 1000000
    return {"usage": usage, "estimated_usd": cost, "cost_status": status}


def request_body(system: str, user: str, tool: dict | None = None) -> dict:
    body = {"model": MODEL, "instructions": system, "input": user, "store": False,
            "max_output_tokens": MAX_OUTPUT_TOKENS, "reasoning": {"effort": "none"}}
    if tool:
        body.update(tools=[tool], tool_choice={"type": "function", "name": "record_triage"},
                    parallel_tool_calls=False)
    return body


def call_api(body: dict, key: str, ca_file: str | None = None, opener=None) -> dict:
    if not isinstance(key, str) or not key.startswith("sk-") or any(c.isspace() for c in key):
        raise ExperimentError("invalid_local_credential")
    request = urllib.request.Request(ENDPOINT, data=json.dumps(body, allow_nan=False).encode(),
                                     headers={"Authorization": "Bearer " + key,
                                              "Content-Type": "application/json"}, method="POST")
    # Reject redirects rather than forwarding the credential to another endpoint.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    start = time.perf_counter()
    try:
        context = ssl.create_default_context(cafile=ca_file)
        transport = opener or urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context)).open
        with transport(request, timeout=45) as result:
            raw = result.read(MAX_RESPONSE_BYTES + 1)
            request_id = result.headers.get("x-request-id", "")
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ExperimentError("oversized_response")
        response = strict_json(raw.decode("utf-8"))
        if not isinstance(response, dict):
            raise ExperimentError("invalid_response_object")
        return {"response": response, "elapsed_ms": (time.perf_counter() - start) * 1000,
                "request_id": request_id if re.fullmatch(r"[A-Za-z0-9_-]{0,150}", request_id) else None}
    except urllib.error.HTTPError as exc:
        safe_code = "unclassified"
        # Retain only a closed set of provider codes; never store error message/body text.
        try:
            raw_error = exc.read(16385)
            if len(raw_error) <= 16384:
                payload = strict_json(raw_error.decode("utf-8"))
                error = payload.get("error") if isinstance(payload, dict) else None
                code = error.get("code") if isinstance(error, dict) else None
                if isinstance(code, str) and code in SAFE_ERROR_CODES:
                    safe_code = code
        except (OSError, UnicodeError, ExperimentError, AttributeError, TypeError):
            pass
        request_id = (exc.headers or {}).get("x-request-id", "")
        raise ExperimentError("http_error", http_status=exc.code, provider_error_code=safe_code,
                              request_id=request_id if re.fullmatch(r"[A-Za-z0-9_-]{0,150}", request_id) else None,
                              elapsed_ms=(time.perf_counter() - start) * 1000) from None
    except (urllib.error.URLError, OSError, socket.timeout, UnicodeError):
        raise ExperimentError("network_or_tls_error", elapsed_ms=(time.perf_counter() - start) * 1000) from None
