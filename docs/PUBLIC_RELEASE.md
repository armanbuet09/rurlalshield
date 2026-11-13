# Public source release

This initial public snapshot was prepared on 12 November 2026 from the RuralShield research implementation. Its Git history intentionally starts here so that private papers and operational artifacts from the working repository are not published.

## Sanitization and reproducibility

- Implementation, tests, example configuration and operational documentation are included.
- The study account is represented by `123456789012`, the alert destination by `research-alerts@example.com`, and the research KMS key ID by `00000000-0000-4000-8000-000000000000`.
- These values are placeholders, not access to a working deployment. Historical scripts have pinned assumptions and need explicit review for a new account and a new experiment.
- Local configuration, authentication material, generated assets, raw evidence, paper sources and paper diagrams/PDFs are excluded. Evidence references in the research documents identify private records; they are not downloadable public artifacts.
- The original frozen workload, Git history, paper versions and private evidence were not modified to produce this snapshot. Identifier substitutions mean this snapshot is not byte-identical to the frozen source archive.
- The original Bedrock path, isolated direct-provider experiments and offline scripted controls remain distinct. Do not interpret a passing mocked test as live model inference.

## Verification

The build, Jest suite, offline synthesis and Python/Node safety tests are run against this public snapshot before its initial commit. Exact results are recorded below after verification. No AWS deployment, cleanup or paid model request is part of public release verification.

Verified for this snapshot on 12 November 2026:

- TypeScript build: passed.
- Jest: 37 tests passed across four suites.
- Python: 128 offline tests passed across ten test files.
- Observation worker: five Node.js tests passed.
- Offline CDK synthesis: four stacks, zero unsuppressed static-check errors, one warning; CDK deprecation warnings remain.
- Python sources compile successfully.
- Reviewed publishable paths and scanned for known private account/contact values, common API-key/access-key patterns and private-key headers; no matches remained.

The Python checks used Python 3.12; the closeout test requires boto3 (verified with 1.44.2). Runtime dependencies are installed locally and not committed. npm reports deprecated transitive `inflight` and `glob` packages; this release does not upgrade the frozen dependency lockfile or claim a dependency-security audit.
