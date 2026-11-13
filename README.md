# RuralShield

Research prototype for AWS serverless security infrastructure and policy-bounded AI triage in resource-constrained healthcare settings.

RuralShield uses AWS CDK (TypeScript), Python Lambda handlers and a YAML workload configuration. It provisions workload infrastructure, security-service integrations, encrypted storage, backups and a finding-response workflow. Model recommendations pass through a deterministic policy before notification, approval or a supported containment action.

This release includes two distinct paths:

- **AWS Bedrock Sentinel:** the original infrastructure integration in `lib/constructs/ai-sentinel.ts` and `src/lambda/`. Successful live Bedrock inference was not established in the research study.
- **Separate external AI experiment:** a direct OpenAI adapter and isolated synthetic workflow in `src/external_ai/`, `src/external_ai_workflow/` and `scripts/ai-workflow-stack.ts`. This is separate from the non-AI pilot and is not a replacement provider wired into the original Sentinel.

The five-day non-AI pilot and the separate AI experiment must be reported separately. Offline tests and synthesis do not establish clinical effectiveness, HIPAA compliance, production readiness or model accuracy.

## Install and verify locally

Use Node.js 20 or later, npm and Python 3.12. The research operational scripts were developed on Windows; some use `.venv/Scripts/python.exe` explicitly.

```sh
git clone https://github.com/armanbuet09/rurlalshield.git
cd rurlalshield
npm ci
python -m venv .venv
```

Activate the virtual environment, then install the AWS Python SDK:

```sh
python -m pip install boto3
npm run build
npm test -- --runInBand
npm run verify:local
python -m unittest discover -s src/lambda/triage -p 'test_*.py'
python test/test_security_handlers.py
python test/test_external_ai.py
python test/test_ai_workflow.py
node --test scripts/test-observation-worker.cjs
```

`verify:local` synthesizes with an example AWS account and writes its static-check report to `cdk.out/local-verification/verification.json`; it does not deploy. Additional archival and cleanup safety tests are in `scripts/test_*.py`. **Do not run `scripts/test_mantle_luna.py` as an offline test:** it is a live model probe.

## Configure an AWS deployment

1. Copy `rural-shield.example.yaml` to `rural-shield.yaml`; set your organization, alert email, region, workload and optional account/DR region.
2. Review every enabled service, retention period, IAM permission and estimated cost. For an initial non-AI deployment set `security.aiTriage.enabled: false` and `security.aiTriage.autoContainment: false`. The supplied full-feature example enables both; do not treat it as the frozen research configuration.
3. Configure your own AWS CLI identity, bootstrap the intended regions, and inspect the synthesized templates and `cdk diff` before deploying. Existing account-level security services require appropriate `existingResources` settings.
4. Confirm the SNS email subscription. AI use additionally requires model/provider access, accepted terms and billing; availability in the original account is not transferable.

```sh
npx cdk synth --all
npx cdk diff --all
npx cdk deploy --all --require-approval broadening
```

Deployment creates billable services. S3 Object Lock, backup retention and retained KMS keys can leave resources and costs after stack deletion. Do not deploy real patient data without an independent security, operational and regulatory review.

## Research operations and documentation

- [Design](docs/DESIGN.md), [control mapping](docs/CONTROL_MAPPING.md), [threat model](docs/THREAT_MODEL.md).
- [Separate AI workflow](docs/AI_WORKFLOW_DEPLOYMENT.md) and [external-provider experiment](docs/EXTERNAL_AI_EXPERIMENT.md).
- [Non-AI pilot](docs/NONAI_PILOT.md), [native closeout](docs/NONAI_CLOSEOUT.md) and [local evidence/retirement](docs/LOCAL_EVIDENCE.md).
- [Public release notes and verification](docs/PUBLIC_RELEASE.md).

The operational documents contain dated research records. They are not a current deployment dashboard. Research scripts require operator-reviewed manifests, resource inventories and account settings that are intentionally not published. Replace example identifiers consistently; do not bypass ownership, evidence or cleanup gates to make an old command run. Never rerun an old observation window or merge new AI traffic into its results.

## Public release scope

This is a fresh source snapshot, not the private research repository's Git history. It includes implementation, offline tests, example configuration and reviewed documentation. Account identifiers, operator email and the research KMS key ID are replaced with examples. The paper, figures, PDFs, credentials, local configuration, raw evidence and generated output are excluded. The authors retain the original research archive separately.

## License

Apache-2.0; see [LICENSE](LICENSE).
