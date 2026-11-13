> Historical research documentation. Dated entries describe the original study, not the state of a new deployment. Account identifiers and operator email addresses in this public snapshot are examples. Private evidence and account configuration are not distributed. See [public release notes](PUBLIC_RELEASE.md).

# Isolated GPT-5.6 Luna Mantle check

Status recorded 26 October 2026, through 22:44:06 UTC (5:44 PM Chicago).

This is a separate synthetic compatibility check, not a change to the active
five-day non-AI pilot and not an end-to-end Sentinel experiment. No successful
inference, generated triage assessment, or model-quality result was collected.

## Completed observations

| Check | Observed result |
|---|---|
| Region/model | Ohio (`us-east-2`), `openai.gpt-5.6-luna` |
| Applied Mantle quotas | 2,000,000 input tokens/minute; 200,000 output tokens/minute |
| Applied Runtime cross-region quotas | US and global routes both 0 tokens/minute |
| Initial agreement status | `NOT_AVAILABLE` |
| Agreement action | Explicit human approval obtained for internal synthetic research; `CreateFoundationModelAgreement` returned HTTP 202 at 22:40:52 UTC |
| Subsequent agreement status | `AVAILABLE`, verified at 22:41:47 UTC |
| Mantle catalog | `GET /v1/models` returned HTTP 200 and listed Luna with status `available` |
| Mantle inference | `POST /openai/v1/chat/completions` returned HTTP 401, `access_denied` / `permission_denied_error`: the model is not available for this account |
| Inference attempts | Three total: one before agreement activation, two afterward; each requested at most 64 output tokens |
| Structured model calls | Skipped after connectivity rejection; not counted as passes |
| Existing observer | Deployed code hash matched the frozen manifest before/after every probe; observer remained Active and load rule ENABLED |
| Frozen local manifest | Hash unchanged before/after every probe |

The nonzero quotas, accepted agreement, and catalog entry do not establish usable
inference authorization. The service error directs the account holder to AWS
Sales for additional access options. The underlying account restriction and its
resolution time are not established. AWS documents that access restrictions may
remain after the activation prerequisites have been completed; this is distinct
from a missing token quota.

The initial catalog read used `/openai/v1/models` and returned 404. The later
endpoint-wide `/v1/models` read succeeded. Both initial and corrected probes used
the model card's `/openai/v1/chat/completions` inference route and received the
same account-access rejection. Preserve all attempts when interpreting evidence.

## Test boundaries

`scripts/test_mantle_luna.py` uses the existing temporary AWS credentials and
SigV4 signing service `bedrock-mantle`. It creates no API key, changes no IAM
permission or Support plan, and never calls the deployed application, Step
Functions, approval endpoints, or containment handlers. The separately approved
agreement request was submitted using the reviewed commercial offer; this was
the only model-access mutation. No application or observation stack was deployed.

The prepared extended probe translates the current `record_triage` schema to an
OpenAI-compatible function tool, requests exactly that tool, validates all
constraints present in the current flat assessment contract, and runs the
existing Python policy locally with automatic containment disabled. Selected
offline checks passed for valid/invalid contract data and the synthetic threat
and posture policy routes. These are harness checks, not generated-model results.

Private receipts, synthetic requests and responses, prompt/policy/probe source
copies, and a hash index are under `research-evidence/model-tests/`. The summary
is `luna-mantle-20261026-summary.json`; all raw private evidence remains ignored
by Git. These files are separate from final five-day archival and do not open
any closeout or retirement gate. No response returned token usage; this alone
is not a billing statement. Any activation/probe-related billing belongs to
separate instrumentation overhead, not a measured non-AI treatment cost.

## Use in RuralShield

Luna cannot presently be described as a working model for this account. After
AWS resolves inference access, rerun the bounded probes before selecting it for
a separately identified AI condition. A successful simple response would still
not validate the structured tool contract, model quality, or response workflow.

The current Sentinel implementation calls Bedrock Runtime Converse. Mantle uses
OpenAI-compatible Chat Completions/Responses and does not provide inline Bedrock
Guardrails. A future integration therefore needs an explicit transport adapter,
appropriate scoped Mantle permissions, contract validation, and independently
designed/tested guardrail handling. Do not silently drop the guardrail or alter
the deterministic policy. The weekly report's model client also needs review.

The approved scope is internal synthetic research. The OpenAI Bedrock agreement
contains restrictions on providing cybersecurity products/services to third
parties without written approval. The research authorization is not approval
to offer a model-backed RuralShield service to hospitals or other third parties.

## Primary documentation

- [AWS Luna model card](https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-openai-gpt-56-luna.html)
- [AWS endpoint/API, IAM, and guardrail distinctions](https://docs.aws.amazon.com/bedrock/latest/userguide/endpoints.html)
- [AWS model-access prerequisites and status interpretation](https://docs.aws.amazon.com/bedrock/latest/userguide/model-access.html)
- [OpenAI Bedrock agreement](https://aws.amazon.com/legal/bedrock/third-party-models/#OpenAI)
- [OpenAI Luna model documentation](https://developers.openai.com/api/docs/models/gpt-5.6-luna)
