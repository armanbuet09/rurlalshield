/**
 * RuralShield configuration model.
 *
 * A rural hospital IT generalist should be able to describe their workload in a
 * ~40-line YAML file and get a HIPAA-aligned, serverless, AI-monitored deployment.
 * Everything security-relevant has a safe default; the operator can only *add*
 * exposure deliberately (e.g. allowInternetEgress), never remove a control by omission.
 */
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';

export type ComputeType = 'lambda' | 'container';

export interface LambdaCompute {
  type: 'lambda';
  /** Directory containing the operator's function code (bundled as an asset). */
  codePath: string;
  /** e.g. "app.handler" */
  handler: string;
  /** e.g. "python3.12" | "nodejs22.x" | "java21" */
  runtime: string;
  memoryMb?: number;
  timeoutSeconds?: number;
  /** Reserved concurrency (HIPAA.Security-LambdaConcurrency). Default 50. */
  reservedConcurrency?: number;
  /** Non-secret environment variables. Secrets must come from Secrets Manager. */
  environment?: Record<string, string>;
}

export interface ContainerCompute {
  type: 'container';
  /** Fully-qualified image URI (ECR recommended so Inspector scans it) or a local Dockerfile directory. */
  image: string;
  containerPort: number;
  cpu?: number;
  memoryMb?: number;
  desiredCount?: number;
  /** HTTPS listener requires a certificate; HTTP->HTTPS redirect is always on. */
  certificateArn: string;
  domainName: string;
  environment?: Record<string, string>;
}

export interface WorkloadConfig {
  name: string;
  compute: LambdaCompute | ContainerCompute;
  data: {
    dynamodb?: boolean;
    aurora?: boolean;
    auroraEngineVersion?: string; // e.g. "16.4"
    auroraMinAcu?: number;         // 0 enables auto-pause (cost), 0.5 keeps warm
    auroraMaxAcu?: number;
    auroraPort?: number;
    phiBucket?: boolean;
  };
  handlesPhi: boolean;
  /** CORS origins allowed to call the API (patient portal front-end, etc.). */
  allowedOrigins?: string[];
  /** Adds NAT gateways + egress subnets. Default false (private-isolated, VPC endpoints only). */
  allowInternetEgress?: boolean;
  /** The operator's own code calls Amazon Bedrock (adds a private Bedrock Runtime endpoint). */
  usesBedrock?: boolean;
}

export interface SecurityConfig {
  threatDetection: {
    guardDuty: boolean;
    securityHub: boolean;
    inspector: boolean;
    macie: boolean;
    /** Enable GuardDuty Malware Protection for the PHI bucket (object scanning on upload). */
    s3MalwareProtection?: boolean;
  };
  aiTriage: {
    enabled: boolean;
    /** Bedrock model or inference-profile ID. Verify with `aws bedrock list-inference-profiles`. */
    modelId: string;
    /** Exact backing foundation-model ARNs from Bedrock GetInferenceProfile. Required for profiles. */
    modelResourceArns?: string[];
    /** Allow reversible low-risk containment without a human (see policy.py AUTO_ALLOWED). */
    autoContainment: boolean;
    approvalTimeoutHours?: number;
    /** Minimum Security Hub severity label routed to the triage pipeline. */
    minimumSeverity?: 'MEDIUM' | 'HIGH' | 'CRITICAL';
  };
  resilience: {
    backupRetentionDays: number;
    /** Secondary region for immutable backup copies + PHI bucket replication. */
    drRegion?: string;
    restoreTesting: boolean;
  };
  compliance: {
    configRules: boolean;
    weeklyReport: boolean;
    /** CloudWatch Logs retention for application logs (years). Audit trail in S3 is always 6 years. */
    appLogRetentionYears?: 1 | 2 | 3 | 5 | 6;
  };
  /** Skip creating account-singletons that already exist in the account/region. */
  existingResources?: {
    guardDutyDetector?: boolean;
    configRecorder?: boolean;
    securityHub?: boolean;
    macieSession?: boolean;
    cloudTrail?: boolean;
  };
}

export interface OrganizationConfig {
  name: string;
  /** Short, DNS-safe slug used in resource names. Derived from name if omitted. */
  slug?: string;
  environment: 'dev' | 'staging' | 'prod';
  /** Receives security alerts, approval requests and the weekly posture report. */
  contactEmail: string;
  /** Optional second channel (e.g., on-call). */
  secondaryContactEmail?: string;
  account?: string;
  region: string;
}

export interface RuralShieldConfig {
  organization: OrganizationConfig;
  workload: WorkloadConfig;
  security: SecurityConfig;
}

/** Framework version stamped on every resource (tag rural-shield:version). */
export const FRAMEWORK_VERSION = '0.1.0';

export function slugify(input: string): string {
  return input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 24);
}

function fail(msg: string): never {
  throw new Error(`[rural-shield config] ${msg}`);
}

function isEmail(s: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
}

export function applyDefaults(raw: RuralShieldConfig): RuralShieldConfig {
  const cfg: RuralShieldConfig = JSON.parse(JSON.stringify(raw));
  cfg.organization.slug = cfg.organization.slug ?? slugify(cfg.organization.name);
  cfg.workload.data = cfg.workload.data ?? {};
  cfg.workload.data.auroraEngineVersion = cfg.workload.data.auroraEngineVersion ?? '16.4';
  cfg.workload.data.auroraMinAcu = cfg.workload.data.auroraMinAcu ?? 0.5;
  cfg.workload.data.auroraMaxAcu = cfg.workload.data.auroraMaxAcu ?? 4;
  cfg.workload.data.auroraPort = cfg.workload.data.auroraPort ?? 5433;
  cfg.workload.allowInternetEgress = cfg.workload.allowInternetEgress ?? false;
  cfg.workload.usesBedrock = cfg.workload.usesBedrock ?? false;
  if (cfg.workload.compute.type === 'lambda') {
    cfg.workload.compute.memoryMb = cfg.workload.compute.memoryMb ?? 512;
    cfg.workload.compute.timeoutSeconds = cfg.workload.compute.timeoutSeconds ?? 15;
    cfg.workload.compute.reservedConcurrency = cfg.workload.compute.reservedConcurrency ?? 50;
  } else {
    cfg.workload.compute.cpu = cfg.workload.compute.cpu ?? 512;
    cfg.workload.compute.memoryMb = cfg.workload.compute.memoryMb ?? 1024;
    cfg.workload.compute.desiredCount = cfg.workload.compute.desiredCount ?? 2;
  }
  cfg.security.threatDetection.s3MalwareProtection =
    cfg.security.threatDetection.s3MalwareProtection ?? (cfg.security.threatDetection.guardDuty && !!cfg.workload.data.phiBucket);
  cfg.security.aiTriage.approvalTimeoutHours = cfg.security.aiTriage.approvalTimeoutHours ?? 24;
  cfg.security.aiTriage.minimumSeverity = cfg.security.aiTriage.minimumSeverity ?? 'HIGH';
  cfg.security.compliance.appLogRetentionYears = cfg.security.compliance.appLogRetentionYears ?? 1;
  cfg.security.existingResources = cfg.security.existingResources ?? {};
  return cfg;
}

export function validateConfig(cfg: RuralShieldConfig): void {
  if (!cfg.organization?.name) fail('organization.name is required');
  if (!['dev', 'staging', 'prod'].includes(cfg.organization.environment)) fail('organization.environment must be dev|staging|prod');
  if (!isEmail(cfg.organization.contactEmail)) fail('organization.contactEmail must be a valid e-mail address');
  if (!cfg.organization.region) fail('organization.region is required');
  if (!cfg.workload?.name) fail('workload.name is required');
  if (!/^[a-z][a-z0-9-]{2,30}$/.test(cfg.workload.name)) fail('workload.name must be lowercase, DNS-safe, 3-31 chars');
  const c = cfg.workload.compute;
  if (c.type === 'lambda') {
    if (!c.codePath || !c.handler || !c.runtime) fail('lambda compute requires codePath, handler, runtime');
  } else if (c.type === 'container') {
    if (!c.image || !c.containerPort) fail('container compute requires image and containerPort');
    if (!c.certificateArn || !c.domainName) fail('container compute requires certificateArn and domainName (HTTPS is mandatory)');
  } else {
    fail('workload.compute.type must be "lambda" or "container"');
  }
  if (cfg.security.resilience.backupRetentionDays < 35) {
    fail('resilience.backupRetentionDays must be >= 35 (ransomware dwell time regularly exceeds 30 days)');
  }
  if (cfg.security.resilience.drRegion && cfg.security.resilience.drRegion === cfg.organization.region) {
    fail('resilience.drRegion must differ from organization.region');
  }
  if (cfg.security.aiTriage.enabled && !cfg.security.aiTriage.modelId) fail('aiTriage.modelId is required when aiTriage.enabled');
  if (cfg.security.aiTriage.enabled) {
    const ai = cfg.security.aiTriage;
    if (!Number.isInteger(ai.approvalTimeoutHours) || ai.approvalTimeoutHours! < 1 || ai.approvalTimeoutHours! > 168) {
      fail('aiTriage.approvalTimeoutHours must be 1-168 hours (less than the 30-day signing-key rotation interval)');
    }
    if (/[*?]/.test(ai.modelId)) fail('aiTriage.modelId must not contain IAM wildcards');
    const isProfile = /^(us|eu|apac|global)\./.test(ai.modelId) || ai.modelId.includes(':inference-profile/') || ai.modelId.includes(':application-inference-profile/');
    if (isProfile && !ai.modelResourceArns?.length) fail('aiTriage.modelResourceArns must list the exact backing models for an inference profile');
    if (ai.modelResourceArns?.some(arn => !/^arn:aws(?:-cn|-us-gov)?:bedrock:[a-z0-9-]*::foundation-model\/[A-Za-z0-9.\-_:]+$/.test(arn))) {
      fail('aiTriage.modelResourceArns must contain exact foundation-model ARNs without wildcards');
    }
  }
  if (cfg.workload.handlesPhi && !cfg.security.threatDetection.guardDuty) {
    fail('A PHI workload must keep GuardDuty enabled (HIPAA §164.312(b) audit controls / HPH CPG "Detect & Respond")');
  }
}

export function loadConfig(configPath?: string): RuralShieldConfig {
  const p = configPath ?? process.env.RSHIELD_CONFIG ?? path.join(process.cwd(), 'rural-shield.yaml');
  if (!fs.existsSync(p)) {
    fail(`config file not found at ${p}. Copy rural-shield.example.yaml to rural-shield.yaml and edit it.`);
  }
  const raw = yaml.load(fs.readFileSync(p, 'utf8')) as RuralShieldConfig;
  const cfg = applyDefaults(raw);
  validateConfig(cfg);
  return cfg;
}
