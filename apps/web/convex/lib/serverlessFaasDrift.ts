// WS-77 — Serverless & FaaS Security Configuration Drift Detector:
// pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to serverless function and Function-as-a-Service (FaaS) security
// configuration files. This scanner focuses on the *function deployment layer*
// — configurations that govern IAM permissions, API Gateway authentication,
// runtime environment variables, event trigger security, and edge function
// deployment policies across all major serverless platforms.
//
// DISTINCT from:
//   WS-60  securityConfigDrift       — application-level JWT/CORS/session
//                                      configs inside backend service code
//   WS-62  cloudSecurityDrift        — cloud-wide IAM resource policies,
//                                      KMS keys, VPC security groups;
//                                      WS-77 covers per-function IAM bindings
//   WS-66  certPkiDrift              — certificate and PKI key material;
//                                      WS-77 covers function deployment certs
//   WS-73  cicdPipelineSecurityDrift — pipeline orchestration configs;
//                                      WS-77 covers the function definitions
//
// Covered rule groups (8 rules):
//
//   SERVERLESS_FRAMEWORK_DRIFT       — serverless.yml/yaml/ts (Serverless Framework)
//   AWS_LAMBDA_SAM_DRIFT             — AWS SAM samconfig.toml and template.yaml
//   AZURE_FUNCTION_SECURITY_DRIFT    — Azure Functions host.json and local.settings.json
//   CLOUDFLARE_WORKER_DRIFT          — Cloudflare Workers wrangler.toml/json
//   GCP_CLOUD_RUN_DRIFT              — Cloud Run service/job YAML and App Engine app.yaml
//   EDGE_DEPLOY_CONFIG_DRIFT         — Netlify, Vercel, Fly.io, Render deployment configs
//   FUNCTION_IAM_PERMISSION_DRIFT    — function execution role/policy files (user)
//   KNATIVE_OPENWHISK_DRIFT          — Knative serving/eventing CRDs and OpenWhisk manifests
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Vendor directory exclusion applied to all paths.
//   • Same penalty/cap scoring model as WS-60–76 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (matchedPath + matchCount).
//   • serverless.yml/yaml/ts are globally unambiguous Serverless Framework configs.
//   • samconfig.toml/yaml are globally unambiguous AWS SAM configs.
//   • local.settings.json is globally unambiguous Azure Functions.
//   • wrangler.toml/json/jsonc are globally unambiguous Cloudflare Workers.
//   • netlify.toml/fly.toml/vercel.json are globally unambiguous edge platform configs.
//   • template.yaml gated on sam-app/lambda/functions dirs (too generic ungated).
//   • isFunctionIamPermissionFile is the user contribution — see JSDoc below.
//
// Exports:
//   isFunctionIamPermissionFile   — user contribution point (see JSDoc below)
//   SERVERLESS_FAAS_RULES         — readonly rule registry
//   scanServerlessFaasDrift       — main scanner, returns ServerlessFaasDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ServerlessFaasRuleId =
  | 'SERVERLESS_FRAMEWORK_DRIFT'
  | 'AWS_LAMBDA_SAM_DRIFT'
  | 'AZURE_FUNCTION_SECURITY_DRIFT'
  | 'CLOUDFLARE_WORKER_DRIFT'
  | 'GCP_CLOUD_RUN_DRIFT'
  | 'EDGE_DEPLOY_CONFIG_DRIFT'
  | 'FUNCTION_IAM_PERMISSION_DRIFT'
  | 'KNATIVE_OPENWHISK_DRIFT'

export type ServerlessFaasSeverity = 'high' | 'medium' | 'low'
export type ServerlessFaasRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type ServerlessFaasDriftFinding = {
  ruleId: ServerlessFaasRuleId
  severity: ServerlessFaasSeverity
  matchedPath: string
  matchCount: number
  description: string
  recommendation: string
}

export type ServerlessFaasDriftResult = {
  riskScore: number
  riskLevel: ServerlessFaasRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: ServerlessFaasDriftFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// Vendor exclusion
// ---------------------------------------------------------------------------

const VENDOR_DIRS = [
  'node_modules/',
  'vendor/',
  '.git/',
  'dist/',
  'build/',
  '.next/',
  '.nuxt/',
]

function isVendor(p: string): boolean {
  return VENDOR_DIRS.some((v) => p.includes(v))
}

// ---------------------------------------------------------------------------
// Directory sets used for gating ambiguous filenames
// ---------------------------------------------------------------------------

const SAM_DIRS     = ['sam-app/', '.aws-sam/', 'sam/', 'aws-sam/']
const LAMBDA_DIRS  = ['lambda/', 'functions/', 'serverless/', 'src/functions/', 'src/lambda/']
const AZURE_DIRS   = [
  'azure-functions/', 'azure/', 'functions/', 'api/', 'httptrigger/',
  'blobtrigger/', 'queuetrigger/', 'timertrigger/',
]
const GCP_DIRS     = [
  'cloud-run/', 'cloudrun/', 'gcp/', 'google-cloud/', 'appengine/',
  'cloud-functions/', 'cloudfunctions/', 'gcp/appengine/',
]
const KNATIVE_DIRS = ['knative/', 'knative-serving/', 'knative-eventing/', 'serving/knative/']
const OWH_DIRS     = ['openwhisk/', 'owh/', 'whisk/', 'wsk/']

function inAnyDir(pathLower: string, dirs: readonly string[]): boolean {
  return dirs.some((d) => pathLower.includes(d))
}

// ---------------------------------------------------------------------------
// Rule 1: SERVERLESS_FRAMEWORK_DRIFT (high)
// Serverless Framework multi-cloud configuration files
// ---------------------------------------------------------------------------

function isServerlessFrameworkConfig(_pathLower: string, base: string): boolean {
  // Canonical top-level configs — globally unambiguous
  if (
    base === 'serverless.yml' ||
    base === 'serverless.yaml' ||
    base === 'serverless.ts' ||
    base === 'serverless.json'
  ) return true

  // Stage-specific configs: serverless.prod.yml, serverless.staging.yaml
  if (
    base.startsWith('serverless.') &&
    (base.endsWith('.yml') || base.endsWith('.yaml'))
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 2: AWS_LAMBDA_SAM_DRIFT (high)
// AWS Serverless Application Model configs and Lambda templates
// ---------------------------------------------------------------------------

const SAM_UNGATED = new Set(['samconfig.toml', 'samconfig.yaml', 'samconfig.yml'])

function isAwsLambdaSamConfig(pathLower: string, base: string): boolean {
  // Globally unambiguous SAM CLI config files
  if (SAM_UNGATED.has(base)) return true

  // SAM/Lambda template files — gated because template.yaml is very generic
  if (
    inAnyDir(pathLower, [...SAM_DIRS, ...LAMBDA_DIRS]) &&
    (base === 'template.yaml' || base === 'template.yml' || base === 'template.json')
  ) return true

  // Lambda function config JSON in lambda dirs
  if (
    inAnyDir(pathLower, LAMBDA_DIRS) &&
    (
      base === 'lambda.json' ||
      base === 'lambda-function.json' ||
      base === 'function-definition.json' ||
      (base.startsWith('lambda-') && base.endsWith('.json'))
    )
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 3: AZURE_FUNCTION_SECURITY_DRIFT (high)
// Azure Functions host configuration and settings files
// ---------------------------------------------------------------------------

function isAzureFunctionConfig(pathLower: string, base: string): boolean {
  // Globally unambiguous Azure Functions local secrets file (contains connection strings)
  if (base === 'local.settings.json') return true

  // Azure Functions function binding definition — gated (function.json is generic)
  if (base === 'function.json' && inAnyDir(pathLower, AZURE_DIRS)) return true

  // Azure Functions host config — gated (host.json is used elsewhere)
  if (base === 'host.json' && inAnyDir(pathLower, AZURE_DIRS)) return true

  // Azure Durable Functions or extension bundle configs
  if (
    (base === 'extensions.json' || base === 'azure-functions.json') &&
    inAnyDir(pathLower, AZURE_DIRS)
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 4: CLOUDFLARE_WORKER_DRIFT (high)
// Cloudflare Workers configuration via Wrangler CLI
// ---------------------------------------------------------------------------

const CF_UNGATED = new Set(['wrangler.toml', 'wrangler.json', 'wrangler.jsonc', 'wrangler.yaml'])

function isCloudflareWorkerConfig(_pathLower: string, base: string): boolean {
  if (CF_UNGATED.has(base)) return true

  // Environment-specific Wrangler configs: wrangler.prod.toml, wrangler-dev.json
  if (
    (base.startsWith('wrangler.') || base.startsWith('wrangler-')) &&
    (base.endsWith('.toml') || base.endsWith('.json') || base.endsWith('.yaml'))
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 5: GCP_CLOUD_RUN_DRIFT (medium)
// Google Cloud Run, Cloud Functions, and App Engine configs
// ---------------------------------------------------------------------------

const CLOUD_RUN_UNGATED = new Set([
  'cloud-run-service.yaml',
  'cloud-run-service.yml',
  'cloud-run-job.yaml',
  'cloud-run-job.yml',
  'cloudfunctions.yaml',
  'cloudfunctions.yml',
])

function isGcpCloudRunConfig(pathLower: string, base: string): boolean {
  // Globally unambiguous Cloud Run filenames
  if (CLOUD_RUN_UNGATED.has(base)) return true

  // service.yaml / service.yml in Cloud Run directories
  if (
    inAnyDir(pathLower, GCP_DIRS) &&
    (base === 'service.yaml' || base === 'service.yml' || base === 'service.json')
  ) return true

  // App Engine app.yaml — gated on appengine/gcp dirs (too generic ungated)
  if (base === 'app.yaml' && inAnyDir(pathLower, GCP_DIRS)) return true

  // Cloud Build config in GCP dirs (defines function deployment steps)
  if (
    inAnyDir(pathLower, GCP_DIRS) &&
    (base === 'cloudbuild.yaml' || base === 'cloudbuild.yml' || base === 'cloudbuild.json')
  ) return true

  // cloud- prefixed YAML in GCP dirs
  if (
    inAnyDir(pathLower, GCP_DIRS) &&
    base.startsWith('cloud-') &&
    (base.endsWith('.yaml') || base.endsWith('.yml'))
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 6: EDGE_DEPLOY_CONFIG_DRIFT (medium)
// Netlify, Vercel, Fly.io, Render edge deployment configurations
// ---------------------------------------------------------------------------

const EDGE_UNGATED = new Set([
  'netlify.toml',
  'fly.toml',
  'vercel.json',
  'vercel.yaml',
  'render.yaml',
  'render.yml',
])

function isEdgeDeployConfig(_pathLower: string, base: string): boolean {
  if (EDGE_UNGATED.has(base)) return true

  // Netlify config variants
  if (base.startsWith('netlify.') && base.endsWith('.toml')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 7: FUNCTION_IAM_PERMISSION_DRIFT (medium)  — USER CONTRIBUTION
//
// Detects changes to IAM permission and execution role files that govern
// what cloud resources a serverless function can access. Misconfigured
// function IAM is one of the most common serverless security failures:
// overly permissive execution roles let a compromised function exfiltrate
// data or escalate privileges across the cloud account.
//
// User contribution: implement the detection logic for your function
// IAM permission file naming conventions.
//
// Considerations when implementing:
//   1. Scope: Limit to files that look like IAM role/policy definitions
//      inside function deployment directories — not application code.
//   2. Name patterns: Common convention includes `execution-role.json`,
//      `lambda-role.json`, `function-policy.json`, `iam-role.json`,
//      `trust-policy.json`, `permissions.json` inside lambda/ dirs.
//   3. Directory gating: Without directory gating, `permissions.json`
//      or `role.json` would match too broadly (e.g. RBAC permissions
//      in frontend apps, not IAM).
//   4. Trade-off: strict (require both function dir AND IAM keyword in
//      name) vs. loose (any JSON with a permissions/role keyword in a
//      broadly-named dir) — strict produces fewer false positives.
//
// Parameters:
//   pathLower — fully lowercased, forward-slash normalised path
//   base      — lowercased basename (filename without directory)
//
// Returns true if the file looks like a serverless function IAM permission
// or execution role definition.
// ---------------------------------------------------------------------------

export function isFunctionIamPermissionFile(pathLower: string, base: string): boolean {
  if (!inAnyDir(pathLower, LAMBDA_DIRS)) return false

  // Must be a JSON or YAML file (IAM policies are always structured data)
  if (
    !base.endsWith('.json') &&
    !base.endsWith('.yaml') &&
    !base.endsWith('.yml')
  ) return false

  // File name must contain an IAM-related keyword
  const IAM_KEYWORDS = [
    'role', 'policy', 'permission', 'iam', 'execution', 'trust', 'assume',
  ]
  return IAM_KEYWORDS.some((kw) => base.includes(kw))
}

// ---------------------------------------------------------------------------
// Rule 8: KNATIVE_OPENWHISK_DRIFT (low)
// Self-hosted FaaS platforms: Knative serving/eventing and Apache OpenWhisk
// ---------------------------------------------------------------------------

const KNATIVE_CRD_NAMES = new Set([
  'kservice.yaml', 'kservice.yml',
  'ksvc.yaml', 'ksvc.yml',
  'serving.yaml', 'serving.yml',
  'trigger.yaml', 'trigger.yml',
  'broker.yaml', 'broker.yml',
  'eventing.yaml', 'eventing.yml',
])

const OPENWHISK_UNGATED = new Set([
  'wskprops',   // OpenWhisk CLI config file (no extension, globally unique)
  '.wskprops',  // Hidden variant
])

function isKnativeOpenWhiskConfig(pathLower: string, base: string): boolean {
  // Globally unambiguous OpenWhisk CLI config
  if (OPENWHISK_UNGATED.has(base)) return true

  // Knative CRD names in knative directories
  if (inAnyDir(pathLower, KNATIVE_DIRS) && KNATIVE_CRD_NAMES.has(base)) return true

  // OpenWhisk manifest and deploy files in openwhisk directories
  if (
    inAnyDir(pathLower, OWH_DIRS) &&
    (base === 'manifest.yaml' || base === 'manifest.yml' || base === 'deploy.yaml')
  ) return true

  // knative- prefixed configs
  if (
    (base.startsWith('knative-') || base.startsWith('kn-')) &&
    (base.endsWith('.yaml') || base.endsWith('.yml'))
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

export const SERVERLESS_FAAS_RULES: ReadonlyArray<{
  id: ServerlessFaasRuleId
  severity: ServerlessFaasSeverity
  description: string
  recommendation: string
  match: (pathLower: string, base: string) => boolean
}> = [
  {
    id: 'SERVERLESS_FRAMEWORK_DRIFT',
    severity: 'high',
    description: 'Serverless Framework configuration change detected (serverless.yml/yaml/ts).',
    recommendation:
      'Review IAM permissions in provider.iamRoleStatements, per-function roles, and environment variable references before deploying.',
    match: isServerlessFrameworkConfig,
  },
  {
    id: 'AWS_LAMBDA_SAM_DRIFT',
    severity: 'high',
    description: 'AWS SAM or Lambda configuration change detected (samconfig.toml, template.yaml).',
    recommendation:
      'Verify SAM template IAM policies follow least privilege, API Gateway auth is configured, and no overly broad resource wildcards exist.',
    match: isAwsLambdaSamConfig,
  },
  {
    id: 'AZURE_FUNCTION_SECURITY_DRIFT',
    severity: 'high',
    description: 'Azure Functions configuration change detected (host.json, local.settings.json, function.json).',
    recommendation:
      'Ensure local.settings.json is not committed with real connection strings, auth level is not anonymous, and managed identity is used over secrets.',
    match: isAzureFunctionConfig,
  },
  {
    id: 'CLOUDFLARE_WORKER_DRIFT',
    severity: 'high',
    description: 'Cloudflare Workers configuration change detected (wrangler.toml/json).',
    recommendation:
      'Audit wrangler config for exposed API tokens/secrets in vars, verify route patterns do not expose unintended endpoints, and confirm KV/D1 bindings are scoped correctly.',
    match: isCloudflareWorkerConfig,
  },
  {
    id: 'GCP_CLOUD_RUN_DRIFT',
    severity: 'medium',
    description: 'Google Cloud Run or App Engine configuration change detected.',
    recommendation:
      'Review service account bindings, ingress settings (internal vs. all-traffic), and authentication requirements for Cloud Run services.',
    match: isGcpCloudRunConfig,
  },
  {
    id: 'EDGE_DEPLOY_CONFIG_DRIFT',
    severity: 'medium',
    description: 'Edge deployment configuration change detected (Netlify/Vercel/Fly.io/Render).',
    recommendation:
      'Audit edge function routes, environment variable references, redirect rules, and header security policies in the deployment config.',
    match: isEdgeDeployConfig,
  },
  {
    id: 'FUNCTION_IAM_PERMISSION_DRIFT',
    severity: 'medium',
    description: 'Serverless function IAM role or execution policy file change detected.',
    recommendation:
      'Verify the function execution role follows least privilege and does not grant wildcard resource access to sensitive services.',
    match: isFunctionIamPermissionFile,
  },
  {
    id: 'KNATIVE_OPENWHISK_DRIFT',
    severity: 'low',
    description: 'Knative or Apache OpenWhisk configuration change detected.',
    recommendation:
      'Review Knative Service authentication settings, event trigger sources, and OpenWhisk package bindings for unintended public exposure.',
    match: isKnativeOpenWhiskConfig,
  },
]

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

const SEVERITY_PENALTIES: Record<ServerlessFaasSeverity, { per: number; cap: number }> = {
  high:   { per: 15, cap: 45 },
  medium: { per: 8,  cap: 25 },
  low:    { per: 4,  cap: 15 },
}

function computeRiskScore(findings: ServerlessFaasDriftFinding[]): number {
  let score = 0
  for (const f of findings) {
    const { per, cap } = SEVERITY_PENALTIES[f.severity]
    score += Math.min(f.matchCount * per, cap)
  }
  return Math.min(score, 100)
}

function computeRiskLevel(score: number): ServerlessFaasRiskLevel {
  if (score === 0) return 'none'
  if (score < 20)  return 'low'
  if (score < 45)  return 'medium'
  if (score < 70)  return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Main scanner
// ---------------------------------------------------------------------------

export function scanServerlessFaasDrift(changedFiles: string[]): ServerlessFaasDriftResult {
  const normalise = (p: string) => p.replace(/\\/g, '/').toLowerCase()

  const findings: ServerlessFaasDriftFinding[] = []

  for (const rule of SERVERLESS_FAAS_RULES) {
    let firstPath = ''
    let matchCount = 0

    for (const raw of changedFiles) {
      const p    = normalise(raw)
      const base = p.split('/').pop() ?? p

      if (isVendor(p)) continue
      if (!rule.match(p, base)) continue

      matchCount++
      if (!firstPath) firstPath = raw
    }

    if (matchCount > 0) {
      findings.push({
        ruleId:         rule.id,
        severity:       rule.severity,
        matchedPath:    firstPath,
        matchCount,
        description:    rule.description,
        recommendation: rule.recommendation,
      })
    }
  }

  // Sort: high → medium → low
  const ORDER: Record<ServerlessFaasSeverity, number> = { high: 0, medium: 1, low: 2 }
  findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity])

  const riskScore = computeRiskScore(findings)
  const riskLevel = computeRiskLevel(riskScore)
  const highCount   = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount    = findings.filter((f) => f.severity === 'low').length

  const summary =
    findings.length === 0
      ? 'No serverless or FaaS security configuration changes detected.'
      : `${findings.length} serverless security rule${findings.length === 1 ? '' : 's'} triggered ` +
        `(${[
          highCount   ? `${highCount} high`     : '',
          mediumCount ? `${mediumCount} medium`  : '',
          lowCount    ? `${lowCount} low`        : '',
        ].filter(Boolean).join(', ')}); risk score ${riskScore}/100.`

  return {
    riskScore,
    riskLevel,
    totalFindings: findings.length,
    highCount,
    mediumCount,
    lowCount,
    findings,
    summary,
  }
}
