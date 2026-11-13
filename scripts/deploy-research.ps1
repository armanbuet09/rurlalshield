[CmdletBinding()]
param([string]$Profile = 'ruralshield-research')

$ErrorActionPreference = 'Stop'
$taskRepoRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $taskRepoRoot
$taskOldProfile = $env:AWS_PROFILE
$taskOldCaBundle = $env:NODE_EXTRA_CA_CERTS
try {
    $env:AWS_PROFILE = $Profile
    # This host's existing trusted CA bundle is needed for Node behind Norton TLS inspection.
    $taskCaBundle = Join-Path $env:USERPROFILE '.aws\ruralshield-ca-bundle.pem'
    if (Test-Path -LiteralPath $taskCaBundle) { $env:NODE_EXTRA_CA_CERTS = $taskCaBundle }

    & npx cdk synth --quiet --context config=rural-shield.yaml --output cdk.out/research-preflight --profile $Profile
    if ($LASTEXITCODE -ne 0) { throw 'Synthesis failed; deployment stopped.' }
    & npm run preflight:aws
    if ($LASTEXITCODE -ne 0) { throw 'AWS prerequisites are not satisfied; no RuralShield stacks were deployed.' }
    # The operator must have accepted the configured third-party model terms.
    & npm run smoke:model
    if ($LASTEXITCODE -ne 0) { throw 'Model invocation failed; deployment stopped.' }
    & npx cdk diff --app cdk.out/research-preflight --change-set false --profile $Profile
    if ($LASTEXITCODE -ne 0) { throw 'Could not review the deployment diff.' }
    & npx cdk deploy --app cdk.out/research-preflight --all --profile $Profile --require-approval broadening --outputs-file cdk.out/deployment-outputs.json
    if ($LASTEXITCODE -ne 0) { throw 'Deployment did not complete; inspect CloudFormation events before retrying.' }
} finally {
    $env:AWS_PROFILE = $taskOldProfile
    $env:NODE_EXTRA_CA_CERTS = $taskOldCaBundle
    Pop-Location
}
