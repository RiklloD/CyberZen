// WS-81 — ML/AI Platform Security Configuration Drift Detector:
// pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to machine learning and AI platform security configuration files. This scanner
// focuses on the *ML infrastructure layer* — configurations that govern how ML
// workloads authenticate to compute clusters, experiment tracking servers,
// feature stores, and model serving endpoints.
//
// DISTINCT from:
//   WS-62  cloudSecurityDrift       — cloud-wide IAM/KMS resource policies;
//                                     WS-81 covers ML platform-specific access
//                                     configs (SageMaker domains, Vertex AI
//                                     workbenches, Azure ML workspaces)
//   WS-63  containerHardeningDrift  — generic k8s RBAC/NetworkPolicy; WS-81
//                                     covers ML-operator CRDs (KFDef, InferenceService)
//   WS-70  identityAccessDrift      — server-side PAM/Vault/LDAP; WS-81 covers
//                                     ML platform authentication settings
//   WS-80  dataPipelineDrift        — data pipeline ETL configs; WS-81 covers
//                                     the ML training and serving infrastructure
//
// Covered rule groups (8 rules):
//
//   MLFLOW_TRACKING_DRIFT        — MLflow tracking server, model registry,
//                                  and artifact store configuration
//   KUBEFLOW_PIPELINE_DRIFT      — Kubeflow Pipelines, KServe/KFServing, and
//                                  Katib hyperparameter tuning configuration
//   RAY_CLUSTER_DRIFT            — Ray distributed compute cluster and
//                                  Anyscale platform security configuration
//   AI_PLATFORM_ACCESS_DRIFT     — SageMaker, Vertex AI, and Azure ML platform
//                                  IAM and access configuration
//   FEATURE_STORE_DRIFT          — Feast, Tecton, and Hopsworks feature store
//                                  security configuration
//   MODEL_SERVING_DRIFT          — TorchServe, TF Serving, BentoML, Seldon
//                                  Core, and Triton model serving configuration
//   MLOPS_PIPELINE_DRIFT         — DVC, ClearML, Comet, and W&B experiment
//                                  tracking and MLOps pipeline security
//   MODEL_CARD_AUDIT_DRIFT       — Model governance artifacts, model cards,
//                                  and model registry metadata configuration
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Vendor directory exclusion applied to all paths.
//   • Same penalty/cap scoring model as WS-60–80 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (firstPath + matchCount).
//   • kfctl.yaml / kfdef.yaml are globally unambiguous KFCtl manifests.
//   • feature_store.yaml is Feast's canonical file — globally unambiguous.
//   • dvc.yaml / dvc.yml are DVC pipeline definitions — globally unambiguous.
//   • bentofile.yaml is BentoML's build spec — globally unambiguous.
//   • isAiPlatformAccessFile is the trickiest classification (user contribution):
//     generic config filenames in cloud AI platform dirs require keyword gating
//     to distinguish ML-platform access configs from experiment boilerplate.
//
// Exports:
//   isAiPlatformAccessFile    — user contribution point (see JSDoc below)
//   ML_AI_PLATFORM_RULES      — readonly rule registry
//   scanMlAiPlatformDrift     — main scanner, returns MlAiPlatformDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type MlAiPlatformRuleId =
  | 'MLFLOW_TRACKING_DRIFT'
  | 'KUBEFLOW_PIPELINE_DRIFT'
  | 'RAY_CLUSTER_DRIFT'
  | 'AI_PLATFORM_ACCESS_DRIFT'
  | 'FEATURE_STORE_DRIFT'
  | 'MODEL_SERVING_DRIFT'
  | 'MLOPS_PIPELINE_DRIFT'
  | 'MODEL_CARD_AUDIT_DRIFT'

export type MlAiPlatformSeverity = 'high' | 'medium' | 'low'
export type MlAiPlatformRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type MlAiPlatformDriftFinding = {
  ruleId: MlAiPlatformRuleId
  severity: MlAiPlatformSeverity
  matchedPath: string
  matchCount: number
  description: string
  recommendation: string
}

export type MlAiPlatformDriftResult = {
  riskScore: number
  riskLevel: MlAiPlatformRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: MlAiPlatformDriftFinding[]
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
  '__pycache__/',
  '.tox/',
  '.venv/',
  'venv/',
]

function isVendor(p: string): boolean {
  return VENDOR_DIRS.some((v) => p.includes(v))
}

// ---------------------------------------------------------------------------
// Directory sets used for gating ambiguous filenames
// ---------------------------------------------------------------------------

const MLFLOW_DIRS   = ['mlflow/', '.mlflow/', 'ml-platform/', 'mlflow-config/', 'mlflow-server/']
const KUBEFLOW_DIRS = ['kubeflow/', 'kfserving/', 'kserve/', 'kfp/', '.kubeflow/', 'kubeflow-pipelines/']
const RAY_DIRS      = ['ray/', '.ray/', 'ray-config/', 'anyscale/', 'ray-cluster/']
const AI_PLATFORM_DIRS = [
  'sagemaker/', '.sagemaker/', 'vertexai/', 'vertex-ai/',
  'azureml/', '.azureml/', 'azure-ml/', 'aml/',
]
const FEAST_DIRS   = ['feast/', 'feature-store/', 'feature_store/', 'tecton/', 'hopsworks/']
const SERVING_DIRS = [
  'torchserve/', 'tf-serving/', 'tensorflow-serving/',
  'triton/', 'bentoml/', 'seldon/', 'model-serving/', 'kserve/',
]
const MLOPS_DIRS   = ['.dvc/', 'dvc/', 'clearml/', 'wandb/', '.wandb/', 'comet/', 'mlops/', 'ml-pipeline/']
const MODEL_DIRS   = ['models/', 'model-registry/', 'model-cards/', 'model_cards/', '.huggingface/', 'huggingface/']

function inAnyDir(pathLower: string, dirs: readonly string[]): boolean {
  return dirs.some((d) => pathLower.includes(d))
}

// ---------------------------------------------------------------------------
// Rule 1: MLFLOW_TRACKING_DRIFT (high)
// MLflow tracking server, model registry, and artifact store configuration
// ---------------------------------------------------------------------------

const MLFLOW_UNGATED = new Set([
  'mlflow.yaml',              // MLflow server config — globally unambiguous
  'mlflow.yml',
  'mlflow-config.yaml',       // Named-config variant
  'mlflow-config.yml',
  'mlflow-tracking.yaml',     // Tracking URI and artifact root config
  'mlflow-tracking.yml',
])

function isMlflowTrackingConfig(pathLower: string, base: string): boolean {
  if (MLFLOW_UNGATED.has(base)) return true

  // mlflow-* / mlflow_* prefix — filename names its own tool
  if (base.startsWith('mlflow-') || base.startsWith('mlflow_')) {
    if (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.cfg') ||
        base.endsWith('.json') || base.endsWith('.ini')) return true
  }

  if (!inAnyDir(pathLower, MLFLOW_DIRS)) return false

  if (
    base === 'logging.yaml'        ||
    base === 'logging.yml'         ||
    base === 'artifacts.yaml'      ||
    base === 'server.yaml'         ||
    base === 'server.yml'          ||
    base === 'config.yaml'         ||
    base === 'config.yml'          ||
    base === 'config.ini'          ||
    base === '.env'                ||
    base === 'docker-compose.yaml' ||
    base === 'docker-compose.yml'
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 2: KUBEFLOW_PIPELINE_DRIFT (high)
// Kubeflow Pipelines, KServe/KFServing, and Katib configuration
// ---------------------------------------------------------------------------

const KUBEFLOW_UNGATED = new Set([
  'kfctl.yaml',                      // KFCtl deployment manifest — globally unambiguous
  'kfctl.yml',
  'kfdef.yaml',                      // KFDef CRD — globally unambiguous Kubeflow
  'kfdef.yml',
  'kubeflow-config.yaml',
  'kubeflow-config.yml',
])

function isKubeflowPipelineConfig(pathLower: string, base: string): boolean {
  if (KUBEFLOW_UNGATED.has(base)) return true

  // kfserving-*, kserve-*, kubeflow-* prefix
  if (
    base.startsWith('kfserving-') ||
    base.startsWith('kserve-')    ||
    base.startsWith('kubeflow-')  ||
    base.startsWith('katib-')
  ) {
    if (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json')) return true
  }

  if (!inAnyDir(pathLower, KUBEFLOW_DIRS)) return false

  if (
    base === 'pipeline.yaml'            ||
    base === 'pipeline.yml'             ||
    base === 'application.yaml'         ||
    base === 'config.yaml'              ||
    base === 'config.yml'               ||
    base === 'inference-service.yaml'   ||
    base === 'inference-service.yml'    ||
    base === 'inferenceservice.yaml'    ||
    base === 'serving-runtime.yaml'     ||
    base === 'resources.yaml'           ||
    base === 'values.yaml'
  ) return true

  // Any YAML/JSON in Kubeflow directories
  if (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 3: RAY_CLUSTER_DRIFT (high)
// Ray distributed compute cluster and Anyscale platform security configuration
// ---------------------------------------------------------------------------

const RAY_UNGATED = new Set([
  'ray-cluster.yaml',       // Ray cluster manifest — globally unambiguous
  'ray-cluster.yml',
  'ray-config.yaml',
  'ray-config.yml',
  'anyscale-config.yaml',   // Anyscale cloud platform config
  'anyscale-config.yml',
])

function isRayClusterConfig(pathLower: string, base: string): boolean {
  if (RAY_UNGATED.has(base)) return true

  // ray-cluster-*, ray-worker-*, ray-head-* prefix
  if (
    base.startsWith('ray-cluster-') ||
    base.startsWith('ray-worker-')  ||
    base.startsWith('ray-head-')    ||
    base.startsWith('ray-service-')
  ) {
    if (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json')) return true
  }

  if (!inAnyDir(pathLower, RAY_DIRS)) return false

  if (
    base === 'config.yaml'             ||
    base === 'config.yml'              ||
    base === 'autoscaler-config.yaml'  ||
    base === 'head-config.yaml'        ||
    base === 'worker-config.yaml'      ||
    base === 'values.yaml'             ||
    base === '.env'
  ) return true

  if (base.endsWith('.yaml') || base.endsWith('.yml')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 4: AI_PLATFORM_ACCESS_DRIFT (high) — user contribution
// SageMaker, Vertex AI, and Azure ML platform IAM and access configuration
// ---------------------------------------------------------------------------

const AI_PLATFORM_UNGATED = new Set([
  'sagemaker-config.yaml',
  'sagemaker-config.yml',
  '.sagemaker.yaml',
  '.sagemaker.json',
  'sagemaker.yaml',
  'sagemaker.yml',
])

// Keywords in a basename that indicate the file configures platform-level access
const AI_ACCESS_KEYWORDS = [
  'role', 'permission', 'access', 'auth', 'credential', 'apikey', 'api-key',
  'endpoint', 'domain', 'iam', 'execution', 'trust', 'policy', 'network',
  'service-account', 'service_account', 'workspace', 'compute', 'studio',
]

/**
 * WS-81 user contribution — determines whether a config file in a cloud AI
 * platform directory is a security-relevant access configuration rather than
 * generic experiment or hyperparameter boilerplate.
 *
 * The challenge: cloud ML platform directories (sagemaker/, vertexai/,
 * azureml/) contain many files — experiment hyperparameters, notebook
 * parameters, dataset definitions — only a subset of which configure platform
 * access, execution roles, or network security. We want to surface IAM role
 * configs, endpoint ACLs, workspace network settings, and studio domain
 * configs, but not tuning params or model metrics files.
 *
 * Two disambiguation signals:
 *
 *   1. The file has a platform-tool prefix (sagemaker-X/vertexai-X/azureml-X)
 *      with a config extension — the filename names its own platform.
 *
 *   2. The file lives in a recognised platform directory AND its basename
 *      contains an access-relevant keyword (role/permission/access/auth/
 *      credential/endpoint/domain/iam/execution/trust/policy/workspace/
 *      compute/studio). Standard IaC-style names (config.yaml / values.yaml /
 *      settings.yaml) in platform dirs are also included since they commonly
 *      hold access and networking settings.
 *
 * Exclusions applied first:
 *   - k8s, Terraform, Pulumi, CDK, and CloudFormation directories are excluded
 *     (those are WS-62/WS-63 scope for cloud infrastructure policies).
 *   - Non-config extensions (Python source, notebooks, metrics) are excluded.
 *
 * @param pathLower  Lowercased, forward-slash-normalised file path.
 * @param base       Lowercased filename component of `pathLower`.
 */
export function isAiPlatformAccessFile(pathLower: string, base: string): boolean {
  // IaC / k8s dirs — handled by WS-62/WS-63, not WS-81
  const INFRA_DIRS = [
    'terraform/', 'pulumi/', 'cdk/', 'cloudformation/', 'bicep/',
    'k8s/', 'kubernetes/', 'kustomize/', 'helm/', 'charts/',
  ]
  if (INFRA_DIRS.some((d) => pathLower.includes(d))) return false

  const CONFIG_EXTS = ['.yaml', '.yml', '.json', '.cfg', '.ini', '.toml', '.conf']

  // Platform-named prefix — unambiguous regardless of directory
  if (
    base.startsWith('sagemaker-')  || base.startsWith('sagemaker_')  ||
    base.startsWith('vertexai-')   || base.startsWith('vertex-ai-')  ||
    base.startsWith('azureml-')    || base.startsWith('aml-')
  ) {
    if (CONFIG_EXTS.some((ext) => base.endsWith(ext))) return true
  }

  // Must be in a recognised AI platform directory
  if (!inAnyDir(pathLower, AI_PLATFORM_DIRS)) return false
  if (!CONFIG_EXTS.some((ext) => base.endsWith(ext))) return false

  // Access keyword in basename
  if (AI_ACCESS_KEYWORDS.some((kw) => base.includes(kw))) return true

  // Standard IaC / config filenames that commonly hold access settings
  if (
    base === 'config.yaml'   || base === 'config.yml'    ||
    base === 'values.yaml'   || base === 'settings.yaml' ||
    base === 'settings.json' || base === 'config.json'   ||
    base === '.env'
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 5: FEATURE_STORE_DRIFT (medium)
// Feast, Tecton, and Hopsworks feature store security configuration
// ---------------------------------------------------------------------------

const FEAST_UNGATED = new Set([
  'feature_store.yaml',      // Feast canonical configuration — globally unambiguous
  'feature_store.yml',
  'feast.yaml',              // Feast CLI configuration
  'feast.yml',
])

function isFeatureStoreConfig(pathLower: string, base: string): boolean {
  if (FEAST_UNGATED.has(base)) return true

  // feature-store-*, feast-* prefix
  if (base.startsWith('feature-store-') || base.startsWith('feast-')) {
    if (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json')) return true
  }

  if (!inAnyDir(pathLower, FEAST_DIRS)) return false

  if (
    base === 'registry.yaml'        ||
    base === 'registry.yml'         ||
    base === 'data_sources.yaml'    ||
    base === 'entities.yaml'        ||
    base === 'feature_views.yaml'   ||
    base === 'feature-service.yaml' ||
    base === 'config.yaml'          ||
    base === 'config.yml'           ||
    base === '.env'
  ) return true

  if (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 6: MODEL_SERVING_DRIFT (medium)
// TorchServe, TF Serving, BentoML, Seldon Core, and Triton configuration
// ---------------------------------------------------------------------------

const SERVING_UNGATED = new Set([
  'bentofile.yaml',                    // BentoML build spec — globally unambiguous
  'bentofile.yml',
  'torchserve.config',                 // TorchServe startup config
  'triton-config.pbtxt',               // Triton model repository config
  'triton.pbtxt',
  'seldon-deployment.yaml',            // Seldon Core deployment — globally unambiguous
  'seldon-deployment.yml',
  'kfserving-inferenceservice.yaml',   // KFServing/KServe InferenceService
  'inferenceservice.yaml',
  'inferenceservice.yml',
])

function isModelServingConfig(pathLower: string, base: string): boolean {
  if (SERVING_UNGATED.has(base)) return true

  // torchserve-*, bentoml-*, seldon-*, triton-* prefix
  if (
    base.startsWith('torchserve-') ||
    base.startsWith('bentoml-')    ||
    base.startsWith('seldon-')     ||
    base.startsWith('triton-')     ||
    base.startsWith('tfserving-')
  ) {
    if (
      base.endsWith('.yaml') || base.endsWith('.yml')   || base.endsWith('.json') ||
      base.endsWith('.config') || base.endsWith('.pbtxt') || base.endsWith('.conf')
    ) return true
  }

  if (!inAnyDir(pathLower, SERVING_DIRS)) return false

  if (
    base === 'config.properties'  ||  // TorchServe management API config
    base === 'config.yaml'        ||
    base === 'config.yml'         ||
    base === 'serving.yaml'       ||
    base === 'serving.yml'        ||
    base === 'model-config.yaml'  ||
    base === 'model_config.yaml'  ||
    base === 'values.yaml'        ||
    base === '.env'
  ) return true

  if (
    base.endsWith('.yaml')       || base.endsWith('.yml')   ||
    base.endsWith('.json')       || base.endsWith('.config') ||
    base.endsWith('.pbtxt')      || base.endsWith('.properties')
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 7: MLOPS_PIPELINE_DRIFT (medium)
// DVC, ClearML, Comet, and W&B experiment tracking and MLOps configuration
// ---------------------------------------------------------------------------

const MLOPS_UNGATED = new Set([
  'dvc.yaml',       // DVC pipeline definition — globally unambiguous
  'dvc.yml',
  'clearml.conf',   // ClearML (formerly Trains) config — globally unambiguous
  '.clearml.conf',
])

function isMlopsPipelineConfig(pathLower: string, base: string): boolean {
  if (MLOPS_UNGATED.has(base)) return true

  // dvc-*, comet-*, wandb-*, clearml-* prefix
  if (
    base.startsWith('dvc-')     ||
    base.startsWith('comet-')   ||
    base.startsWith('wandb-')   ||
    base.startsWith('clearml-')
  ) {
    if (
      base.endsWith('.yaml') || base.endsWith('.yml')  ||
      base.endsWith('.json') || base.endsWith('.cfg')  ||
      base.endsWith('.conf')
    ) return true
  }

  if (!inAnyDir(pathLower, MLOPS_DIRS)) return false

  if (
    base === 'params.yaml'   ||
    base === 'params.yml'    ||
    base === 'config.yaml'   ||
    base === 'config.yml'    ||
    base === 'settings.yaml' ||
    base === 'dagshub.yaml'  ||
    base === 'comet.yaml'    ||
    base === '.env'
  ) return true

  if (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.cfg') || base.endsWith('.conf')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 8: MODEL_CARD_AUDIT_DRIFT (low)
// Model governance artifacts, model cards, and model registry metadata
// ---------------------------------------------------------------------------

const MODEL_CARD_UNGATED = new Set([
  'model-card.json',    // Model governance artifact — globally unambiguous term
  'model-card.yaml',
  'model-card.yml',
  'modelcard.json',
  'modelcard.yaml',
  'modelcard.yml',
  'model_card.json',
  'model_card.yaml',
  'model_card.yml',
])

function isModelCardAuditConfig(pathLower: string, base: string): boolean {
  if (MODEL_CARD_UNGATED.has(base)) return true

  // model-card-*, model_card_* prefix
  if (base.startsWith('model-card-') || base.startsWith('model_card_')) {
    if (base.endsWith('.json') || base.endsWith('.yaml') || base.endsWith('.yml')) return true
  }

  if (!inAnyDir(pathLower, MODEL_DIRS)) return false

  if (
    base === 'model-registry.yaml'  ||
    base === 'model-registry.yml'   ||
    base === 'metadata.yaml'        ||
    base === 'model-metadata.json'  ||
    base === 'model-info.yaml'      ||
    base === 'model-info.json'      ||
    base === 'registry.yaml'        ||
    base === 'registry.yml'
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

export const ML_AI_PLATFORM_RULES: ReadonlyArray<{
  id: MlAiPlatformRuleId
  severity: MlAiPlatformSeverity
  description: string
  recommendation: string
  match: (pathLower: string, base: string) => boolean
}> = [
  {
    id: 'MLFLOW_TRACKING_DRIFT',
    severity: 'high',
    description: 'MLflow tracking server, model registry, or artifact store configuration changed.',
    recommendation:
      'Review MLflow authentication settings (HTTP basic auth, token auth), ensure the artifact store access credentials are rotated, audit model registry permission changes, and confirm that the tracking URI does not expose a publicly accessible endpoint without authentication.',
    match: (p, b) => isMlflowTrackingConfig(p, b),
  },
  {
    id: 'KUBEFLOW_PIPELINE_DRIFT',
    severity: 'high',
    description: 'Kubeflow Pipelines, KServe/KFServing, or Katib configuration changed.',
    recommendation:
      'Validate pipeline RBAC bindings in the KFDef manifest, review InferenceService IAM policy changes, confirm that Kubeflow Pipelines auth is configured (OIDC or basic), and ensure that serving runtime resource limits have not been weakened.',
    match: (p, b) => isKubeflowPipelineConfig(p, b),
  },
  {
    id: 'RAY_CLUSTER_DRIFT',
    severity: 'high',
    description: 'Ray distributed compute cluster or Anyscale platform configuration changed.',
    recommendation:
      'Review cluster autoscaler IAM permissions, confirm that the Ray Dashboard is not publicly exposed, audit runtime environment changes for dependency injection risks, and verify that worker node security groups have not been relaxed.',
    match: (p, b) => isRayClusterConfig(p, b),
  },
  {
    id: 'AI_PLATFORM_ACCESS_DRIFT',
    severity: 'high',
    description: 'Cloud AI platform (SageMaker, Vertex AI, Azure ML) access or IAM configuration changed.',
    recommendation:
      'Verify SageMaker execution role changes follow least-privilege, review Vertex AI workbench service account bindings, confirm Azure ML workspace network isolation settings, and audit endpoint IAM policy changes to ensure inference endpoints are not publicly accessible.',
    match: (p, b) => AI_PLATFORM_UNGATED.has(b) || isAiPlatformAccessFile(p, b),
  },
  {
    id: 'FEATURE_STORE_DRIFT',
    severity: 'medium',
    description: 'Feature store (Feast, Tecton, Hopsworks) security configuration changed.',
    recommendation:
      'Check Feast registry access controls and confirm the online store connection credentials are rotated, review data source authentication changes, validate that the feature store offline store IAM permissions follow least-privilege, and verify that feature serving endpoints enforce authentication.',
    match: (p, b) => isFeatureStoreConfig(p, b),
  },
  {
    id: 'MODEL_SERVING_DRIFT',
    severity: 'medium',
    description: 'Model serving configuration (TorchServe, TF Serving, BentoML, Seldon, Triton) changed.',
    recommendation:
      'Review TorchServe management API authentication settings, verify that the inference endpoint is not bound to 0.0.0.0 without TLS, audit BentoML runner config for credential leaks, and confirm Seldon Deployment resource limits have not been weakened.',
    match: (p, b) => isModelServingConfig(p, b),
  },
  {
    id: 'MLOPS_PIPELINE_DRIFT',
    severity: 'medium',
    description: 'MLOps pipeline or experiment tracking configuration (DVC, ClearML, W&B, Comet) changed.',
    recommendation:
      'Validate DVC remote storage credentials (ensure environment variable references, not plaintext), review ClearML API key rotation status, confirm that W&B API keys are not committed to version control, and verify that pipeline artifact stores enforce access controls.',
    match: (p, b) => isMlopsPipelineConfig(p, b),
  },
  {
    id: 'MODEL_CARD_AUDIT_DRIFT',
    severity: 'low',
    description: 'Model governance artifact or model registry metadata changed.',
    recommendation:
      'Verify that model card accuracy reflects the current model version, review bias and fairness disclosure changes, confirm that model registry access controls allow only authorised principals to promote models, and ensure model metadata includes intended use and out-of-scope usage documentation.',
    match: (p, b) => isModelCardAuditConfig(p, b),
  },
]

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

const SEVERITY_PENALTIES: Record<MlAiPlatformSeverity, { per: number; cap: number }> = {
  high:   { per: 15, cap: 45 },
  medium: { per: 8,  cap: 25 },
  low:    { per: 4,  cap: 15 },
}

function computeRiskScore(findings: MlAiPlatformDriftFinding[]): number {
  let score = 0
  for (const f of findings) {
    const { per, cap } = SEVERITY_PENALTIES[f.severity]
    score += Math.min(f.matchCount * per, cap)
  }
  return Math.min(score, 100)
}

function computeRiskLevel(score: number): MlAiPlatformRiskLevel {
  if (score === 0) return 'none'
  if (score < 20)  return 'low'
  if (score < 45)  return 'medium'
  if (score < 70)  return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Main scanner
// ---------------------------------------------------------------------------

const MAX_PATHS_PER_SCAN = 500

export function scanMlAiPlatformDrift(changedFiles: string[]): MlAiPlatformDriftResult {
  const normalise = (p: string) => p.replace(/\\/g, '/').toLowerCase()

  const findings: MlAiPlatformDriftFinding[] = []

  for (const rule of ML_AI_PLATFORM_RULES) {
    let firstPath  = ''
    let matchCount = 0

    for (const raw of changedFiles.slice(0, MAX_PATHS_PER_SCAN)) {
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
  const ORDER: Record<MlAiPlatformSeverity, number> = { high: 0, medium: 1, low: 2 }
  findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity])

  const riskScore   = computeRiskScore(findings)
  const riskLevel   = computeRiskLevel(riskScore)
  const highCount   = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount    = findings.filter((f) => f.severity === 'low').length

  const summary =
    findings.length === 0
      ? 'No ML/AI platform security configuration drift detected.'
      : `${findings.length} ML/AI platform rule${findings.length === 1 ? '' : 's'} triggered ` +
        `(${[
          highCount   ? `${highCount} high`    : '',
          mediumCount ? `${mediumCount} medium` : '',
          lowCount    ? `${lowCount} low`       : '',
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
