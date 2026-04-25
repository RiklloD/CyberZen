// WS-77 — Serverless & FaaS Security Configuration Drift Detector: test suite.
import { describe, expect, it } from 'vitest'
import {
  SERVERLESS_FAAS_RULES,
  isFunctionIamPermissionFile,
  scanServerlessFaasDrift,
} from './serverlessFaasDrift'

// ---------------------------------------------------------------------------
// Rule 1: SERVERLESS_FRAMEWORK_DRIFT
// ---------------------------------------------------------------------------

describe('SERVERLESS_FRAMEWORK_DRIFT', () => {
  it('flags serverless.yml (canonical Serverless Framework config)', () => {
    const r = scanServerlessFaasDrift(['serverless.yml'])
    expect(r.findings.some((f) => f.ruleId === 'SERVERLESS_FRAMEWORK_DRIFT')).toBe(true)
  })

  it('flags serverless.yaml (alternate extension)', () => {
    const r = scanServerlessFaasDrift(['serverless.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SERVERLESS_FRAMEWORK_DRIFT')).toBe(true)
  })

  it('flags serverless.ts (TypeScript Serverless Framework config)', () => {
    const r = scanServerlessFaasDrift(['serverless.ts'])
    expect(r.findings.some((f) => f.ruleId === 'SERVERLESS_FRAMEWORK_DRIFT')).toBe(true)
  })

  it('flags serverless.json (JSON Serverless Framework config)', () => {
    const r = scanServerlessFaasDrift(['serverless.json'])
    expect(r.findings.some((f) => f.ruleId === 'SERVERLESS_FRAMEWORK_DRIFT')).toBe(true)
  })

  it('flags serverless.prod.yml (stage-specific config)', () => {
    const r = scanServerlessFaasDrift(['serverless.prod.yml'])
    expect(r.findings.some((f) => f.ruleId === 'SERVERLESS_FRAMEWORK_DRIFT')).toBe(true)
  })

  it('flags serverless.staging.yaml (staging stage config)', () => {
    const r = scanServerlessFaasDrift(['serverless.staging.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'SERVERLESS_FRAMEWORK_DRIFT')).toBe(true)
  })

  it('flags serverless.dev.yml (dev stage config)', () => {
    const r = scanServerlessFaasDrift(['serverless.dev.yml'])
    expect(r.findings.some((f) => f.ruleId === 'SERVERLESS_FRAMEWORK_DRIFT')).toBe(true)
  })

  it('flags nested serverless.yml (inside project subdir)', () => {
    const r = scanServerlessFaasDrift(['services/auth/serverless.yml'])
    expect(r.findings.some((f) => f.ruleId === 'SERVERLESS_FRAMEWORK_DRIFT')).toBe(true)
  })

  it('does NOT flag serverless.js (not a config format)', () => {
    const r = scanServerlessFaasDrift(['serverless.js'])
    expect(r.findings.some((f) => f.ruleId === 'SERVERLESS_FRAMEWORK_DRIFT')).toBe(false)
  })

  it('does NOT flag not-serverless.yml (different prefix)', () => {
    const r = scanServerlessFaasDrift(['not-serverless.yml'])
    expect(r.findings.some((f) => f.ruleId === 'SERVERLESS_FRAMEWORK_DRIFT')).toBe(false)
  })

  it('does NOT flag config.yml (generic YAML, no serverless prefix)', () => {
    const r = scanServerlessFaasDrift(['config.yml'])
    expect(r.findings.some((f) => f.ruleId === 'SERVERLESS_FRAMEWORK_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 2: AWS_LAMBDA_SAM_DRIFT
// ---------------------------------------------------------------------------

describe('AWS_LAMBDA_SAM_DRIFT', () => {
  it('flags samconfig.toml (ungated AWS SAM CLI config)', () => {
    const r = scanServerlessFaasDrift(['samconfig.toml'])
    expect(r.findings.some((f) => f.ruleId === 'AWS_LAMBDA_SAM_DRIFT')).toBe(true)
  })

  it('flags samconfig.yaml (YAML SAM config)', () => {
    const r = scanServerlessFaasDrift(['samconfig.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'AWS_LAMBDA_SAM_DRIFT')).toBe(true)
  })

  it('flags samconfig.yml (short YAML SAM config)', () => {
    const r = scanServerlessFaasDrift(['samconfig.yml'])
    expect(r.findings.some((f) => f.ruleId === 'AWS_LAMBDA_SAM_DRIFT')).toBe(true)
  })

  it('flags lambda/template.yaml (SAM template gated in lambda/ dir)', () => {
    const r = scanServerlessFaasDrift(['lambda/template.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'AWS_LAMBDA_SAM_DRIFT')).toBe(true)
  })

  it('flags sam-app/template.yml (SAM template in sam-app/ dir)', () => {
    const r = scanServerlessFaasDrift(['sam-app/template.yml'])
    expect(r.findings.some((f) => f.ruleId === 'AWS_LAMBDA_SAM_DRIFT')).toBe(true)
  })

  it('flags functions/template.json (CloudFormation template in functions/ dir)', () => {
    const r = scanServerlessFaasDrift(['functions/template.json'])
    expect(r.findings.some((f) => f.ruleId === 'AWS_LAMBDA_SAM_DRIFT')).toBe(true)
  })

  it('flags lambda/lambda.json (Lambda function config)', () => {
    const r = scanServerlessFaasDrift(['lambda/lambda.json'])
    expect(r.findings.some((f) => f.ruleId === 'AWS_LAMBDA_SAM_DRIFT')).toBe(true)
  })

  it('flags lambda/lambda-function.json (Lambda function definition)', () => {
    const r = scanServerlessFaasDrift(['lambda/lambda-function.json'])
    expect(r.findings.some((f) => f.ruleId === 'AWS_LAMBDA_SAM_DRIFT')).toBe(true)
  })

  it('flags lambda/lambda-auth.json (lambda- prefixed JSON)', () => {
    const r = scanServerlessFaasDrift(['lambda/lambda-auth.json'])
    expect(r.findings.some((f) => f.ruleId === 'AWS_LAMBDA_SAM_DRIFT')).toBe(true)
  })

  it('flags lambda/function-definition.json (function definition file)', () => {
    const r = scanServerlessFaasDrift(['lambda/function-definition.json'])
    expect(r.findings.some((f) => f.ruleId === 'AWS_LAMBDA_SAM_DRIFT')).toBe(true)
  })

  it('does NOT flag template.yaml outside sam/lambda dirs (too generic)', () => {
    const r = scanServerlessFaasDrift(['config/template.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'AWS_LAMBDA_SAM_DRIFT')).toBe(false)
  })

  it('does NOT flag template.yml at repo root (no sam/lambda dir)', () => {
    const r = scanServerlessFaasDrift(['template.yml'])
    expect(r.findings.some((f) => f.ruleId === 'AWS_LAMBDA_SAM_DRIFT')).toBe(false)
  })

  it('does NOT flag lambda.json outside lambda dirs', () => {
    const r = scanServerlessFaasDrift(['config/lambda.json'])
    expect(r.findings.some((f) => f.ruleId === 'AWS_LAMBDA_SAM_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 3: AZURE_FUNCTION_SECURITY_DRIFT
// ---------------------------------------------------------------------------

describe('AZURE_FUNCTION_SECURITY_DRIFT', () => {
  it('flags local.settings.json (ungated Azure Functions secrets file)', () => {
    const r = scanServerlessFaasDrift(['local.settings.json'])
    expect(r.findings.some((f) => f.ruleId === 'AZURE_FUNCTION_SECURITY_DRIFT')).toBe(true)
  })

  it('flags azure-functions/host.json (host config gated in azure-functions/ dir)', () => {
    const r = scanServerlessFaasDrift(['azure-functions/host.json'])
    expect(r.findings.some((f) => f.ruleId === 'AZURE_FUNCTION_SECURITY_DRIFT')).toBe(true)
  })

  it('flags api/function.json (function binding in api/ dir)', () => {
    const r = scanServerlessFaasDrift(['api/function.json'])
    expect(r.findings.some((f) => f.ruleId === 'AZURE_FUNCTION_SECURITY_DRIFT')).toBe(true)
  })

  it('flags HttpTrigger/function.json (Azure trigger-named dir)', () => {
    const r = scanServerlessFaasDrift(['HttpTrigger/function.json'])
    expect(r.findings.some((f) => f.ruleId === 'AZURE_FUNCTION_SECURITY_DRIFT')).toBe(true)
  })

  it('flags azure-functions/extensions.json (extension bundle config)', () => {
    const r = scanServerlessFaasDrift(['azure-functions/extensions.json'])
    expect(r.findings.some((f) => f.ruleId === 'AZURE_FUNCTION_SECURITY_DRIFT')).toBe(true)
  })

  it('flags azure/azure-functions.json (Azure Functions app config)', () => {
    const r = scanServerlessFaasDrift(['azure/azure-functions.json'])
    expect(r.findings.some((f) => f.ruleId === 'AZURE_FUNCTION_SECURITY_DRIFT')).toBe(true)
  })

  it('flags TimerTrigger/host.json (timer trigger Azure dir)', () => {
    const r = scanServerlessFaasDrift(['TimerTrigger/host.json'])
    expect(r.findings.some((f) => f.ruleId === 'AZURE_FUNCTION_SECURITY_DRIFT')).toBe(true)
  })

  it('does NOT flag host.json outside azure dirs', () => {
    const r = scanServerlessFaasDrift(['config/host.json'])
    expect(r.findings.some((f) => f.ruleId === 'AZURE_FUNCTION_SECURITY_DRIFT')).toBe(false)
  })

  it('does NOT flag function.json outside azure dirs', () => {
    const r = scanServerlessFaasDrift(['src/function.json'])
    expect(r.findings.some((f) => f.ruleId === 'AZURE_FUNCTION_SECURITY_DRIFT')).toBe(false)
  })

  it('does NOT flag host.json at repo root', () => {
    const r = scanServerlessFaasDrift(['host.json'])
    expect(r.findings.some((f) => f.ruleId === 'AZURE_FUNCTION_SECURITY_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 4: CLOUDFLARE_WORKER_DRIFT
// ---------------------------------------------------------------------------

describe('CLOUDFLARE_WORKER_DRIFT', () => {
  it('flags wrangler.toml (canonical Cloudflare Workers config)', () => {
    const r = scanServerlessFaasDrift(['wrangler.toml'])
    expect(r.findings.some((f) => f.ruleId === 'CLOUDFLARE_WORKER_DRIFT')).toBe(true)
  })

  it('flags wrangler.json (JSON Wrangler config)', () => {
    const r = scanServerlessFaasDrift(['wrangler.json'])
    expect(r.findings.some((f) => f.ruleId === 'CLOUDFLARE_WORKER_DRIFT')).toBe(true)
  })

  it('flags wrangler.jsonc (JSONC Wrangler config)', () => {
    const r = scanServerlessFaasDrift(['wrangler.jsonc'])
    expect(r.findings.some((f) => f.ruleId === 'CLOUDFLARE_WORKER_DRIFT')).toBe(true)
  })

  it('flags wrangler.yaml (YAML Wrangler config)', () => {
    const r = scanServerlessFaasDrift(['wrangler.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'CLOUDFLARE_WORKER_DRIFT')).toBe(true)
  })

  it('flags wrangler.prod.toml (production environment config)', () => {
    const r = scanServerlessFaasDrift(['wrangler.prod.toml'])
    expect(r.findings.some((f) => f.ruleId === 'CLOUDFLARE_WORKER_DRIFT')).toBe(true)
  })

  it('flags wrangler-staging.json (staging environment config via wrangler- prefix)', () => {
    const r = scanServerlessFaasDrift(['wrangler-staging.json'])
    expect(r.findings.some((f) => f.ruleId === 'CLOUDFLARE_WORKER_DRIFT')).toBe(true)
  })

  it('flags wrangler-dev.yaml (dev environment config via wrangler- prefix)', () => {
    const r = scanServerlessFaasDrift(['wrangler-dev.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'CLOUDFLARE_WORKER_DRIFT')).toBe(true)
  })

  it('does NOT flag wrangler.js (not a config format)', () => {
    const r = scanServerlessFaasDrift(['wrangler.js'])
    expect(r.findings.some((f) => f.ruleId === 'CLOUDFLARE_WORKER_DRIFT')).toBe(false)
  })

  it('does NOT flag not-wrangler.toml (different prefix)', () => {
    const r = scanServerlessFaasDrift(['not-wrangler.toml'])
    expect(r.findings.some((f) => f.ruleId === 'CLOUDFLARE_WORKER_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 5: GCP_CLOUD_RUN_DRIFT
// ---------------------------------------------------------------------------

describe('GCP_CLOUD_RUN_DRIFT', () => {
  it('flags cloud-run-service.yaml (ungated Cloud Run service config)', () => {
    const r = scanServerlessFaasDrift(['cloud-run-service.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'GCP_CLOUD_RUN_DRIFT')).toBe(true)
  })

  it('flags cloud-run-service.yml (short extension variant)', () => {
    const r = scanServerlessFaasDrift(['cloud-run-service.yml'])
    expect(r.findings.some((f) => f.ruleId === 'GCP_CLOUD_RUN_DRIFT')).toBe(true)
  })

  it('flags cloud-run-job.yaml (ungated Cloud Run job config)', () => {
    const r = scanServerlessFaasDrift(['cloud-run-job.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'GCP_CLOUD_RUN_DRIFT')).toBe(true)
  })

  it('flags cloudfunctions.yaml (ungated Cloud Functions deploy config)', () => {
    const r = scanServerlessFaasDrift(['cloudfunctions.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'GCP_CLOUD_RUN_DRIFT')).toBe(true)
  })

  it('flags gcp/app.yaml (App Engine config gated in gcp/ dir)', () => {
    const r = scanServerlessFaasDrift(['gcp/app.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'GCP_CLOUD_RUN_DRIFT')).toBe(true)
  })

  it('flags cloud-run/service.yaml (service config gated in cloud-run/ dir)', () => {
    const r = scanServerlessFaasDrift(['cloud-run/service.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'GCP_CLOUD_RUN_DRIFT')).toBe(true)
  })

  it('flags gcp/cloudbuild.yaml (Cloud Build config in gcp/ dir)', () => {
    const r = scanServerlessFaasDrift(['gcp/cloudbuild.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'GCP_CLOUD_RUN_DRIFT')).toBe(true)
  })

  it('flags cloud-functions/cloud-deploy.yaml (cloud- prefix YAML in gcp dir)', () => {
    const r = scanServerlessFaasDrift(['cloud-functions/cloud-deploy.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'GCP_CLOUD_RUN_DRIFT')).toBe(true)
  })

  it('does NOT flag app.yaml outside gcp dirs (too generic ungated)', () => {
    const r = scanServerlessFaasDrift(['app.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'GCP_CLOUD_RUN_DRIFT')).toBe(false)
  })

  it('does NOT flag service.yaml outside gcp dirs', () => {
    const r = scanServerlessFaasDrift(['k8s/service.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'GCP_CLOUD_RUN_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 6: EDGE_DEPLOY_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('EDGE_DEPLOY_CONFIG_DRIFT', () => {
  it('flags netlify.toml (ungated Netlify deploy config)', () => {
    const r = scanServerlessFaasDrift(['netlify.toml'])
    expect(r.findings.some((f) => f.ruleId === 'EDGE_DEPLOY_CONFIG_DRIFT')).toBe(true)
  })

  it('flags fly.toml (ungated Fly.io config)', () => {
    const r = scanServerlessFaasDrift(['fly.toml'])
    expect(r.findings.some((f) => f.ruleId === 'EDGE_DEPLOY_CONFIG_DRIFT')).toBe(true)
  })

  it('flags vercel.json (ungated Vercel config)', () => {
    const r = scanServerlessFaasDrift(['vercel.json'])
    expect(r.findings.some((f) => f.ruleId === 'EDGE_DEPLOY_CONFIG_DRIFT')).toBe(true)
  })

  it('flags vercel.yaml (YAML Vercel config)', () => {
    const r = scanServerlessFaasDrift(['vercel.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'EDGE_DEPLOY_CONFIG_DRIFT')).toBe(true)
  })

  it('flags render.yaml (ungated Render config)', () => {
    const r = scanServerlessFaasDrift(['render.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'EDGE_DEPLOY_CONFIG_DRIFT')).toBe(true)
  })

  it('flags render.yml (short YAML Render config)', () => {
    const r = scanServerlessFaasDrift(['render.yml'])
    expect(r.findings.some((f) => f.ruleId === 'EDGE_DEPLOY_CONFIG_DRIFT')).toBe(true)
  })

  it('flags netlify.staging.toml (Netlify staging variant via netlify. prefix)', () => {
    const r = scanServerlessFaasDrift(['netlify.staging.toml'])
    expect(r.findings.some((f) => f.ruleId === 'EDGE_DEPLOY_CONFIG_DRIFT')).toBe(true)
  })

  it('does NOT flag random.toml (non-edge platform config)', () => {
    const r = scanServerlessFaasDrift(['random.toml'])
    expect(r.findings.some((f) => f.ruleId === 'EDGE_DEPLOY_CONFIG_DRIFT')).toBe(false)
  })

  it('does NOT flag vercel.js (JavaScript, not a config format)', () => {
    const r = scanServerlessFaasDrift(['vercel.js'])
    expect(r.findings.some((f) => f.ruleId === 'EDGE_DEPLOY_CONFIG_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 7: FUNCTION_IAM_PERMISSION_DRIFT — integration tests
// ---------------------------------------------------------------------------

describe('FUNCTION_IAM_PERMISSION_DRIFT', () => {
  it('flags lambda/execution-role.json (execution role definition)', () => {
    const r = scanServerlessFaasDrift(['lambda/execution-role.json'])
    expect(r.findings.some((f) => f.ruleId === 'FUNCTION_IAM_PERMISSION_DRIFT')).toBe(true)
  })

  it('flags lambda/trust-policy.json (STS trust policy)', () => {
    const r = scanServerlessFaasDrift(['lambda/trust-policy.json'])
    expect(r.findings.some((f) => f.ruleId === 'FUNCTION_IAM_PERMISSION_DRIFT')).toBe(true)
  })

  it('flags functions/iam-role.yaml (IAM role in functions/ dir)', () => {
    const r = scanServerlessFaasDrift(['functions/iam-role.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'FUNCTION_IAM_PERMISSION_DRIFT')).toBe(true)
  })

  it('flags lambda/function-policy.json (function inline policy)', () => {
    const r = scanServerlessFaasDrift(['lambda/function-policy.json'])
    expect(r.findings.some((f) => f.ruleId === 'FUNCTION_IAM_PERMISSION_DRIFT')).toBe(true)
  })

  it('flags serverless/assume-role.yml (assume-role policy in serverless/ dir)', () => {
    const r = scanServerlessFaasDrift(['serverless/assume-role.yml'])
    expect(r.findings.some((f) => f.ruleId === 'FUNCTION_IAM_PERMISSION_DRIFT')).toBe(true)
  })

  it('does NOT flag lambda/config.json (no IAM keyword in filename)', () => {
    const r = scanServerlessFaasDrift(['lambda/config.json'])
    expect(r.findings.some((f) => f.ruleId === 'FUNCTION_IAM_PERMISSION_DRIFT')).toBe(false)
  })

  it('does NOT flag config/execution-role.json (not in lambda/ dir)', () => {
    const r = scanServerlessFaasDrift(['config/execution-role.json'])
    expect(r.findings.some((f) => f.ruleId === 'FUNCTION_IAM_PERMISSION_DRIFT')).toBe(false)
  })

  it('does NOT flag lambda/execution-role.ts (wrong extension)', () => {
    const r = scanServerlessFaasDrift(['lambda/execution-role.ts'])
    expect(r.findings.some((f) => f.ruleId === 'FUNCTION_IAM_PERMISSION_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// isFunctionIamPermissionFile — unit tests for the exported user contribution
// ---------------------------------------------------------------------------

describe('isFunctionIamPermissionFile (unit)', () => {
  const check = (path: string) => {
    const p    = path.toLowerCase()
    const base = p.split('/').pop() ?? p
    return isFunctionIamPermissionFile(p, base)
  }

  it('returns true for lambda/execution-role.json', () => {
    expect(check('lambda/execution-role.json')).toBe(true)
  })

  it('returns true for lambda/iam-role.json (iam keyword)', () => {
    expect(check('lambda/iam-role.json')).toBe(true)
  })

  it('returns true for functions/permissions.yaml (permission keyword)', () => {
    expect(check('functions/permissions.yaml')).toBe(true)
  })

  it('returns true for lambda/trust-policy.json (trust + policy keywords)', () => {
    expect(check('lambda/trust-policy.json')).toBe(true)
  })

  it('returns true for src/lambda/assume-role.yml (nested lambda dir)', () => {
    expect(check('src/lambda/assume-role.yml')).toBe(true)
  })

  it('returns false for lambda/config.json (no IAM keyword)', () => {
    expect(check('lambda/config.json')).toBe(false)
  })

  it('returns false for config/execution-role.json (not in lambda dir)', () => {
    expect(check('config/execution-role.json')).toBe(false)
  })

  it('returns false for lambda/execution-role.tf (wrong extension)', () => {
    expect(check('lambda/execution-role.tf')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 8: KNATIVE_OPENWHISK_DRIFT
// ---------------------------------------------------------------------------

describe('KNATIVE_OPENWHISK_DRIFT', () => {
  it('flags wskprops (ungated OpenWhisk CLI config)', () => {
    const r = scanServerlessFaasDrift(['wskprops'])
    expect(r.findings.some((f) => f.ruleId === 'KNATIVE_OPENWHISK_DRIFT')).toBe(true)
  })

  it('flags .wskprops (hidden OpenWhisk CLI config variant)', () => {
    const r = scanServerlessFaasDrift(['.wskprops'])
    expect(r.findings.some((f) => f.ruleId === 'KNATIVE_OPENWHISK_DRIFT')).toBe(true)
  })

  it('flags knative/kservice.yaml (Knative Service CRD)', () => {
    const r = scanServerlessFaasDrift(['knative/kservice.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'KNATIVE_OPENWHISK_DRIFT')).toBe(true)
  })

  it('flags knative/trigger.yaml (Knative eventing trigger)', () => {
    const r = scanServerlessFaasDrift(['knative/trigger.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'KNATIVE_OPENWHISK_DRIFT')).toBe(true)
  })

  it('flags knative-serving/serving.yml (Knative serving config)', () => {
    const r = scanServerlessFaasDrift(['knative-serving/serving.yml'])
    expect(r.findings.some((f) => f.ruleId === 'KNATIVE_OPENWHISK_DRIFT')).toBe(true)
  })

  it('flags openwhisk/manifest.yaml (OpenWhisk deployment manifest)', () => {
    const r = scanServerlessFaasDrift(['openwhisk/manifest.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'KNATIVE_OPENWHISK_DRIFT')).toBe(true)
  })

  it('flags knative-config.yaml (knative- prefixed config)', () => {
    const r = scanServerlessFaasDrift(['knative-config.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'KNATIVE_OPENWHISK_DRIFT')).toBe(true)
  })

  it('flags kn-serving.yml (kn- prefixed config)', () => {
    const r = scanServerlessFaasDrift(['kn-serving.yml'])
    expect(r.findings.some((f) => f.ruleId === 'KNATIVE_OPENWHISK_DRIFT')).toBe(true)
  })

  it('does NOT flag trigger.yaml outside knative dirs (too generic)', () => {
    const r = scanServerlessFaasDrift(['k8s/trigger.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'KNATIVE_OPENWHISK_DRIFT')).toBe(false)
  })

  it('does NOT flag manifest.yaml outside openwhisk dirs', () => {
    const r = scanServerlessFaasDrift(['deploy/manifest.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'KNATIVE_OPENWHISK_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Vendor directory exclusion
// ---------------------------------------------------------------------------

describe('vendor directory exclusion', () => {
  it('does not flag serverless.yml in node_modules/', () => {
    const r = scanServerlessFaasDrift(['node_modules/serverless/serverless.yml'])
    expect(r.findings).toHaveLength(0)
  })

  it('does not flag wrangler.toml in vendor/', () => {
    const r = scanServerlessFaasDrift(['vendor/cf-workers/wrangler.toml'])
    expect(r.findings).toHaveLength(0)
  })

  it('does not flag samconfig.toml in .git/', () => {
    const r = scanServerlessFaasDrift(['.git/hooks/samconfig.toml'])
    expect(r.findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Windows path normalisation
// ---------------------------------------------------------------------------

describe('Windows path normalisation', () => {
  it('normalises backslashes before matching (lambda\\template.yaml)', () => {
    const r = scanServerlessFaasDrift(['lambda\\template.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'AWS_LAMBDA_SAM_DRIFT')).toBe(true)
  })

  it('normalises nested Windows paths (azure-functions\\host.json)', () => {
    const r = scanServerlessFaasDrift(['azure-functions\\host.json'])
    expect(r.findings.some((f) => f.ruleId === 'AZURE_FUNCTION_SECURITY_DRIFT')).toBe(true)
  })

  it('normalises knative paths (knative\\kservice.yaml)', () => {
    const r = scanServerlessFaasDrift(['knative\\kservice.yaml'])
    expect(r.findings.some((f) => f.ruleId === 'KNATIVE_OPENWHISK_DRIFT')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Deduplication — one finding per rule regardless of matched-file count
// ---------------------------------------------------------------------------

describe('deduplication per rule', () => {
  it('produces one finding for multiple CF worker config files', () => {
    const r = scanServerlessFaasDrift([
      'wrangler.toml',
      'wrangler.prod.toml',
      'wrangler-staging.json',
    ])
    const cfFindings = r.findings.filter((f) => f.ruleId === 'CLOUDFLARE_WORKER_DRIFT')
    expect(cfFindings).toHaveLength(1)
    expect(cfFindings[0].matchCount).toBe(3)
  })

  it('records the first matched path', () => {
    const r = scanServerlessFaasDrift([
      'serverless.yml',
      'serverless.prod.yml',
      'serverless.staging.yaml',
    ])
    const f = r.findings.find((f) => f.ruleId === 'SERVERLESS_FRAMEWORK_DRIFT')!
    expect(f.matchedPath).toBe('serverless.yml')
    expect(f.matchCount).toBe(3)
  })

  it('does not double-count a file across two different rules', () => {
    // serverless.yml triggers SERVERLESS_FRAMEWORK only; wrangler.toml triggers CLOUDFLARE only.
    const r = scanServerlessFaasDrift(['serverless.yml', 'wrangler.toml'])
    const sfFindings = r.findings.filter((f) => f.ruleId === 'SERVERLESS_FRAMEWORK_DRIFT')
    const cfFindings = r.findings.filter((f) => f.ruleId === 'CLOUDFLARE_WORKER_DRIFT')
    expect(sfFindings).toHaveLength(1)
    expect(cfFindings).toHaveLength(1)
    expect(sfFindings[0].matchCount).toBe(1)
    expect(cfFindings[0].matchCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scoring model', () => {
  it('returns score 0 and level none for empty input', () => {
    const r = scanServerlessFaasDrift([])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })

  it('returns score 0 and level none when no files match', () => {
    const r = scanServerlessFaasDrift(['src/app.ts', 'README.md', 'package.json'])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })

  it('HIGH × 1 match → score 15 → level low', () => {
    const r = scanServerlessFaasDrift(['serverless.yml'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('low')
  })

  it('HIGH × 3 matches → score 45 → level high (cap=45 applied)', () => {
    const r = scanServerlessFaasDrift([
      'serverless.yml',
      'serverless.prod.yml',
      'serverless.staging.yaml',
    ])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('MEDIUM × 1 match → score 8 → level low', () => {
    const r = scanServerlessFaasDrift(['netlify.toml'])
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('MEDIUM × 4 matches → score 25 (capped at MEDIUM cap=25) → level medium', () => {
    const r = scanServerlessFaasDrift([
      'cloud-run-service.yaml',
      'cloud-run-service.yml',
      'cloud-run-job.yaml',
      'cloud-run-job.yml',
    ])
    expect(r.riskScore).toBe(25)
    expect(r.riskLevel).toBe('medium')
  })

  it('LOW × 1 match → score 4 → level low', () => {
    const r = scanServerlessFaasDrift(['wskprops'])
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('HIGH cap (45) + MEDIUM cap (25) = 70 → level critical', () => {
    const r = scanServerlessFaasDrift([
      // 3 HIGH matches → SERVERLESS cap 45
      'serverless.yml',
      'serverless.prod.yml',
      'serverless.staging.yaml',
      // 4 MEDIUM matches → GCP cap 25
      'cloud-run-service.yaml',
      'cloud-run-service.yml',
      'cloud-run-job.yaml',
      'cloud-run-job.yml',
    ])
    expect(r.riskScore).toBe(70)
    expect(r.riskLevel).toBe('critical')
  })

  it('total clamped at 100 even when sum exceeds 100', () => {
    const r = scanServerlessFaasDrift([
      // SERVERLESS (HIGH): 3 matches → 45
      'serverless.yml', 'serverless.prod.yml', 'serverless.staging.yaml',
      // AWS_LAMBDA_SAM (HIGH): 3 matches → 45
      'samconfig.toml', 'lambda/template.yaml', 'sam-app/template.yml',
      // AZURE_FUNCTION (HIGH): 3 matches → 45
      'local.settings.json', 'azure-functions/host.json', 'api/function.json',
      // CLOUDFLARE_WORKER (HIGH): 3 matches → 45
      'wrangler.toml', 'wrangler.prod.toml', 'wrangler-staging.json',
    ])
    expect(r.riskScore).toBe(100)
    expect(r.riskLevel).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// Risk levels (boundary checks)
// ---------------------------------------------------------------------------

describe('risk level boundaries', () => {
  it('score 16 → low', () => {
    // GCP MEDIUM (8) + EDGE MEDIUM (8) = 16
    const r = scanServerlessFaasDrift(['cloud-run-service.yaml', 'netlify.toml'])
    expect(r.riskScore).toBe(16)
    expect(r.riskLevel).toBe('low')
  })

  it('score 42 → medium', () => {
    // HIGH (15) + HIGH (15) + MEDIUM (8) + LOW (4) = 42
    const r = scanServerlessFaasDrift([
      'serverless.yml',  // SERVERLESS HIGH → 15
      'samconfig.toml',  // AWS_LAMBDA HIGH → 15
      'netlify.toml',    // EDGE MEDIUM → 8
      'wskprops',        // KNATIVE LOW → 4
    ])
    expect(r.riskScore).toBe(42)
    expect(r.riskLevel).toBe('medium')
  })

  it('score 45 → high (3 × HIGH serverless configs, capped)', () => {
    const r = scanServerlessFaasDrift([
      'serverless.yml',
      'serverless.prod.yml',
      'serverless.staging.yaml',
    ])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('score 69 → high', () => {
    // 3 HIGH serverless (45) + GCP (8) + EDGE (8) + IAM (8) = 69
    const r = scanServerlessFaasDrift([
      'serverless.yml', 'serverless.prod.yml', 'serverless.staging.yaml', // SERVERLESS × 3 → 45
      'cloud-run-service.yaml',  // GCP MEDIUM → 8
      'netlify.toml',            // EDGE MEDIUM → 8
      'lambda/execution-role.json', // IAM MEDIUM → 8
    ])
    expect(r.riskScore).toBe(69)
    expect(r.riskLevel).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// Severity ordering — high first
// ---------------------------------------------------------------------------

describe('severity ordering', () => {
  it('orders findings high → medium → low', () => {
    const r = scanServerlessFaasDrift([
      'wskprops',            // LOW
      'netlify.toml',        // MEDIUM
      'serverless.yml',      // HIGH
    ])
    const severities = r.findings.map((f) => f.severity)
    expect(severities[0]).toBe('high')
    const lastMediumIndex = severities.lastIndexOf('medium')
    const firstLowIndex   = severities.indexOf('low')
    if (lastMediumIndex !== -1 && firstLowIndex !== -1) {
      expect(lastMediumIndex).toBeLessThan(firstLowIndex)
    }
  })
})

// ---------------------------------------------------------------------------
// Summary and result shape
// ---------------------------------------------------------------------------

describe('result shape and summary', () => {
  it('clean push: correct shape with empty findings', () => {
    const r = scanServerlessFaasDrift(['src/index.ts'])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
    expect(r.totalFindings).toBe(0)
    expect(r.highCount).toBe(0)
    expect(r.mediumCount).toBe(0)
    expect(r.lowCount).toBe(0)
    expect(r.findings).toHaveLength(0)
    expect(r.summary).toBe('No serverless or FaaS security configuration changes detected.')
  })

  it('summary contains rule count, severity breakdown, and score', () => {
    const r = scanServerlessFaasDrift(['serverless.yml', 'netlify.toml'])
    expect(r.summary).toContain('2 serverless security rules triggered')
    expect(r.summary).toContain('1 high')
    expect(r.summary).toContain('1 medium')
    expect(r.summary).toContain(`${r.riskScore}/100`)
  })

  it('summary uses singular "rule" when exactly 1 finding', () => {
    const r = scanServerlessFaasDrift(['wrangler.toml'])
    expect(r.summary).toContain('1 serverless security rule triggered')
  })

  it('totalFindings equals findings array length', () => {
    const r = scanServerlessFaasDrift(['serverless.yml', 'samconfig.toml', 'netlify.toml'])
    expect(r.totalFindings).toBe(r.findings.length)
  })

  it('highCount, mediumCount, lowCount sum to totalFindings', () => {
    const r = scanServerlessFaasDrift([
      'serverless.yml',
      'netlify.toml',
      'wskprops',
    ])
    expect(r.highCount + r.mediumCount + r.lowCount).toBe(r.totalFindings)
  })

  it('each finding has all required fields', () => {
    const r = scanServerlessFaasDrift(['serverless.yml'])
    const f = r.findings[0]
    expect(f).toHaveProperty('ruleId')
    expect(f).toHaveProperty('severity')
    expect(f).toHaveProperty('matchedPath')
    expect(f).toHaveProperty('matchCount')
    expect(f).toHaveProperty('description')
    expect(f).toHaveProperty('recommendation')
  })
})

// ---------------------------------------------------------------------------
// Multi-rule push scenario
// ---------------------------------------------------------------------------

describe('multi-rule push scenario', () => {
  it('Serverless Framework + AWS SAM + Azure Functions → 3 distinct HIGH findings', () => {
    const r = scanServerlessFaasDrift([
      'serverless.yml',     // SERVERLESS_FRAMEWORK_DRIFT (HIGH)
      'samconfig.toml',     // AWS_LAMBDA_SAM_DRIFT (HIGH)
      'local.settings.json', // AZURE_FUNCTION_SECURITY_DRIFT (HIGH)
    ])
    expect(r.findings).toHaveLength(3)
    const ids = r.findings.map((f) => f.ruleId)
    expect(ids).toContain('SERVERLESS_FRAMEWORK_DRIFT')
    expect(ids).toContain('AWS_LAMBDA_SAM_DRIFT')
    expect(ids).toContain('AZURE_FUNCTION_SECURITY_DRIFT')
  })

  it('multiple CF configs → CLOUDFLARE_WORKER_DRIFT fired once (dedup)', () => {
    const r = scanServerlessFaasDrift([
      'wrangler.toml',
      'wrangler.prod.toml',
      'wrangler-dev.yaml',
    ])
    const cfFindings = r.findings.filter((f) => f.ruleId === 'CLOUDFLARE_WORKER_DRIFT')
    expect(cfFindings).toHaveLength(1)
    expect(cfFindings[0].matchCount).toBe(3)
  })

  it('GCP + Edge + IAM push → all three MEDIUM rules fire, HIGH first in sort', () => {
    const r = scanServerlessFaasDrift([
      'serverless.yml',              // HIGH
      'cloud-run-service.yaml',      // MEDIUM
      'netlify.toml',                // MEDIUM
      'lambda/execution-role.json',  // MEDIUM
      'wskprops',                    // LOW
    ])
    expect(r.findings.some((f) => f.ruleId === 'GCP_CLOUD_RUN_DRIFT')).toBe(true)
    expect(r.findings.some((f) => f.ruleId === 'EDGE_DEPLOY_CONFIG_DRIFT')).toBe(true)
    expect(r.findings.some((f) => f.ruleId === 'FUNCTION_IAM_PERMISSION_DRIFT')).toBe(true)
    // HIGH finding must come before LOW
    const severities = r.findings.map((f) => f.severity)
    expect(severities[0]).toBe('high')
    expect(severities[severities.length - 1]).toBe('low')
  })
})

// ---------------------------------------------------------------------------
// Rule registry completeness
// ---------------------------------------------------------------------------

describe('rule registry completeness', () => {
  const ALL_RULE_IDS = [
    'SERVERLESS_FRAMEWORK_DRIFT',
    'AWS_LAMBDA_SAM_DRIFT',
    'AZURE_FUNCTION_SECURITY_DRIFT',
    'CLOUDFLARE_WORKER_DRIFT',
    'GCP_CLOUD_RUN_DRIFT',
    'EDGE_DEPLOY_CONFIG_DRIFT',
    'FUNCTION_IAM_PERMISSION_DRIFT',
    'KNATIVE_OPENWHISK_DRIFT',
  ]

  it('registry contains exactly 8 rules', () => {
    expect(SERVERLESS_FAAS_RULES).toHaveLength(8)
  })

  it('every rule ID appears in the registry', () => {
    const registryIds = SERVERLESS_FAAS_RULES.map((r) => r.id)
    for (const id of ALL_RULE_IDS) {
      expect(registryIds).toContain(id)
    }
  })

  it('every rule has a non-empty description and recommendation', () => {
    for (const rule of SERVERLESS_FAAS_RULES) {
      expect(rule.description.length).toBeGreaterThan(10)
      expect(rule.recommendation.length).toBeGreaterThan(10)
    }
  })

  it('severity distribution: 4 high, 3 medium, 1 low', () => {
    const high   = SERVERLESS_FAAS_RULES.filter((r) => r.severity === 'high').length
    const medium = SERVERLESS_FAAS_RULES.filter((r) => r.severity === 'medium').length
    const low    = SERVERLESS_FAAS_RULES.filter((r) => r.severity === 'low').length
    expect(high).toBe(4)
    expect(medium).toBe(3)
    expect(low).toBe(1)
  })
})
