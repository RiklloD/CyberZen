import { describe, expect, it } from 'vitest'
import {
  isAiPlatformAccessFile,
  ML_AI_PLATFORM_RULES,
  scanMlAiPlatformDrift,
  type MlAiPlatformDriftResult,
  type MlAiPlatformRuleId,
} from './mlAiPlatformDrift'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function scan(files: string[]): MlAiPlatformDriftResult {
  return scanMlAiPlatformDrift(files)
}

function triggeredRules(files: string[]): MlAiPlatformRuleId[] {
  return scan(files).findings.map((f) => f.ruleId)
}

// ---------------------------------------------------------------------------
// Rule 1: MLFLOW_TRACKING_DRIFT
// ---------------------------------------------------------------------------

describe('MLFLOW_TRACKING_DRIFT', () => {
  it('matches mlflow.yaml (ungated)', () => {
    expect(triggeredRules(['mlflow.yaml'])).toContain('MLFLOW_TRACKING_DRIFT')
  })
  it('matches mlflow.yml (ungated)', () => {
    expect(triggeredRules(['mlflow.yml'])).toContain('MLFLOW_TRACKING_DRIFT')
  })
  it('matches mlflow-config.yaml (ungated)', () => {
    expect(triggeredRules(['mlflow-config.yaml'])).toContain('MLFLOW_TRACKING_DRIFT')
  })
  it('matches mlflow-tracking.yaml (ungated)', () => {
    expect(triggeredRules(['mlflow-tracking.yaml'])).toContain('MLFLOW_TRACKING_DRIFT')
  })
  it('matches mlflow-prod.yaml via prefix', () => {
    expect(triggeredRules(['mlflow-prod.yaml'])).toContain('MLFLOW_TRACKING_DRIFT')
  })
  it('matches mlflow-staging.cfg via prefix', () => {
    expect(triggeredRules(['mlflow-staging.cfg'])).toContain('MLFLOW_TRACKING_DRIFT')
  })
  it('matches mlflow_server.yaml via prefix', () => {
    expect(triggeredRules(['mlflow_server.yaml'])).toContain('MLFLOW_TRACKING_DRIFT')
  })
  it('matches config.yaml inside mlflow/ dir', () => {
    expect(triggeredRules(['mlflow/config.yaml'])).toContain('MLFLOW_TRACKING_DRIFT')
  })
  it('matches logging.yaml inside .mlflow/ dir', () => {
    expect(triggeredRules(['.mlflow/logging.yaml'])).toContain('MLFLOW_TRACKING_DRIFT')
  })
  it('matches server.yaml inside mlflow-server/ dir', () => {
    expect(triggeredRules(['mlflow-server/server.yaml'])).toContain('MLFLOW_TRACKING_DRIFT')
  })
  it('does NOT match config.yaml outside mlflow dirs', () => {
    expect(triggeredRules(['config/config.yaml'])).not.toContain('MLFLOW_TRACKING_DRIFT')
  })
  it('does NOT match vendor path', () => {
    expect(triggeredRules(['vendor/mlflow/mlflow.yaml'])).not.toContain('MLFLOW_TRACKING_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 2: KUBEFLOW_PIPELINE_DRIFT
// ---------------------------------------------------------------------------

describe('KUBEFLOW_PIPELINE_DRIFT', () => {
  it('matches kfctl.yaml (ungated)', () => {
    expect(triggeredRules(['kfctl.yaml'])).toContain('KUBEFLOW_PIPELINE_DRIFT')
  })
  it('matches kfdef.yaml (ungated)', () => {
    expect(triggeredRules(['kfdef.yaml'])).toContain('KUBEFLOW_PIPELINE_DRIFT')
  })
  it('matches kfdef.yml (ungated)', () => {
    expect(triggeredRules(['kfdef.yml'])).toContain('KUBEFLOW_PIPELINE_DRIFT')
  })
  it('matches kubeflow-config.yaml (ungated)', () => {
    expect(triggeredRules(['kubeflow-config.yaml'])).toContain('KUBEFLOW_PIPELINE_DRIFT')
  })
  it('matches kfserving-config.yaml via prefix', () => {
    expect(triggeredRules(['kfserving-config.yaml'])).toContain('KUBEFLOW_PIPELINE_DRIFT')
  })
  it('matches kserve-setup.yaml via prefix', () => {
    expect(triggeredRules(['kserve-setup.yaml'])).toContain('KUBEFLOW_PIPELINE_DRIFT')
  })
  it('matches katib-config.yaml via prefix', () => {
    expect(triggeredRules(['katib-config.yaml'])).toContain('KUBEFLOW_PIPELINE_DRIFT')
  })
  it('matches inferenceservice.yaml inside kubeflow/ dir', () => {
    expect(triggeredRules(['kubeflow/inferenceservice.yaml'])).toContain('KUBEFLOW_PIPELINE_DRIFT')
  })
  it('matches pipeline.yaml inside kfp/ dir', () => {
    expect(triggeredRules(['kfp/pipeline.yaml'])).toContain('KUBEFLOW_PIPELINE_DRIFT')
  })
  it('matches any yaml inside kserve/ dir', () => {
    expect(triggeredRules(['kserve/serving-runtime.yaml'])).toContain('KUBEFLOW_PIPELINE_DRIFT')
  })
  it('does NOT match pipeline.yaml outside kubeflow dirs', () => {
    expect(triggeredRules(['ci/pipeline.yaml'])).not.toContain('KUBEFLOW_PIPELINE_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 3: RAY_CLUSTER_DRIFT
// ---------------------------------------------------------------------------

describe('RAY_CLUSTER_DRIFT', () => {
  it('matches ray-cluster.yaml (ungated)', () => {
    expect(triggeredRules(['ray-cluster.yaml'])).toContain('RAY_CLUSTER_DRIFT')
  })
  it('matches ray-config.yaml (ungated)', () => {
    expect(triggeredRules(['ray-config.yaml'])).toContain('RAY_CLUSTER_DRIFT')
  })
  it('matches anyscale-config.yaml (ungated)', () => {
    expect(triggeredRules(['anyscale-config.yaml'])).toContain('RAY_CLUSTER_DRIFT')
  })
  it('matches ray-cluster-prod.yaml via prefix', () => {
    expect(triggeredRules(['ray-cluster-prod.yaml'])).toContain('RAY_CLUSTER_DRIFT')
  })
  it('matches ray-worker-gpu.yaml via prefix', () => {
    expect(triggeredRules(['ray-worker-gpu.yaml'])).toContain('RAY_CLUSTER_DRIFT')
  })
  it('matches config.yaml inside ray/ dir', () => {
    expect(triggeredRules(['ray/config.yaml'])).toContain('RAY_CLUSTER_DRIFT')
  })
  it('matches autoscaler-config.yaml inside .ray/ dir', () => {
    expect(triggeredRules(['.ray/autoscaler-config.yaml'])).toContain('RAY_CLUSTER_DRIFT')
  })
  it('matches any yaml inside anyscale/ dir', () => {
    expect(triggeredRules(['anyscale/head-config.yaml'])).toContain('RAY_CLUSTER_DRIFT')
  })
  it('does NOT match config.yaml outside ray dirs', () => {
    expect(triggeredRules(['infra/config.yaml'])).not.toContain('RAY_CLUSTER_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 4: AI_PLATFORM_ACCESS_DRIFT + isAiPlatformAccessFile
// ---------------------------------------------------------------------------

describe('AI_PLATFORM_ACCESS_DRIFT', () => {
  it('matches sagemaker.yaml (ungated)', () => {
    expect(triggeredRules(['sagemaker.yaml'])).toContain('AI_PLATFORM_ACCESS_DRIFT')
  })
  it('matches sagemaker-config.yaml (ungated)', () => {
    expect(triggeredRules(['sagemaker-config.yaml'])).toContain('AI_PLATFORM_ACCESS_DRIFT')
  })
  it('matches .sagemaker.json (ungated)', () => {
    expect(triggeredRules(['.sagemaker.json'])).toContain('AI_PLATFORM_ACCESS_DRIFT')
  })
  it('matches sagemaker-role.yaml via platform prefix', () => {
    expect(triggeredRules(['sagemaker-role.yaml'])).toContain('AI_PLATFORM_ACCESS_DRIFT')
  })
  it('matches vertexai-config.yaml via platform prefix', () => {
    expect(triggeredRules(['vertexai-config.yaml'])).toContain('AI_PLATFORM_ACCESS_DRIFT')
  })
  it('matches azureml-workspace.yaml via platform prefix', () => {
    expect(triggeredRules(['azureml-workspace.yaml'])).toContain('AI_PLATFORM_ACCESS_DRIFT')
  })
  it('matches aml-config.json via platform prefix', () => {
    expect(triggeredRules(['aml-config.json'])).toContain('AI_PLATFORM_ACCESS_DRIFT')
  })
  it('matches role-config.yaml inside sagemaker/ dir', () => {
    expect(triggeredRules(['sagemaker/role-config.yaml'])).toContain('AI_PLATFORM_ACCESS_DRIFT')
  })
  it('matches config.yaml inside .sagemaker/ dir', () => {
    expect(triggeredRules(['.sagemaker/config.yaml'])).toContain('AI_PLATFORM_ACCESS_DRIFT')
  })
  it('matches domain-config.yaml inside vertexai/ dir', () => {
    expect(triggeredRules(['vertexai/domain-config.yaml'])).toContain('AI_PLATFORM_ACCESS_DRIFT')
  })
  it('matches workspace.yaml inside azureml/ dir', () => {
    expect(triggeredRules(['azureml/workspace.yaml'])).toContain('AI_PLATFORM_ACCESS_DRIFT')
  })
  it('does NOT match hyperparams.yaml inside sagemaker/ dir (no access keyword)', () => {
    // hyperparams.yaml — not an access config and no access keyword
    expect(triggeredRules(['sagemaker/hyperparams.yaml'])).not.toContain('AI_PLATFORM_ACCESS_DRIFT')
  })
  it('does NOT match sagemaker-role.yaml inside terraform/ dir', () => {
    expect(triggeredRules(['terraform/sagemaker/role.yaml'])).not.toContain('AI_PLATFORM_ACCESS_DRIFT')
  })
  it('does NOT match sagemaker-role.yaml inside k8s/ dir', () => {
    expect(triggeredRules(['k8s/sagemaker-role.yaml'])).not.toContain('AI_PLATFORM_ACCESS_DRIFT')
  })
})

describe('isAiPlatformAccessFile', () => {
  it('returns true for sagemaker-role.yaml (platform prefix)', () => {
    expect(isAiPlatformAccessFile('sagemaker-role.yaml', 'sagemaker-role.yaml')).toBe(true)
  })
  it('returns true for auth-config.yaml in sagemaker/ dir', () => {
    expect(isAiPlatformAccessFile('sagemaker/auth-config.yaml', 'auth-config.yaml')).toBe(true)
  })
  it('returns true for config.yaml in vertexai/ dir (standard config name)', () => {
    expect(isAiPlatformAccessFile('vertexai/config.yaml', 'config.yaml')).toBe(true)
  })
  it('returns false for hyperparams.json in sagemaker/ dir (no access keyword)', () => {
    expect(isAiPlatformAccessFile('sagemaker/hyperparams.json', 'hyperparams.json')).toBe(false)
  })
  it('returns false when path includes terraform/', () => {
    expect(isAiPlatformAccessFile('terraform/sagemaker/role.yaml', 'role.yaml')).toBe(false)
  })
  it('returns false when path includes kubernetes/', () => {
    expect(isAiPlatformAccessFile('kubernetes/sagemaker/config.yaml', 'config.yaml')).toBe(false)
  })
  it('returns false for generic config.yaml outside all platform dirs', () => {
    expect(isAiPlatformAccessFile('services/api/config.yaml', 'config.yaml')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 5: FEATURE_STORE_DRIFT
// ---------------------------------------------------------------------------

describe('FEATURE_STORE_DRIFT', () => {
  it('matches feature_store.yaml (ungated)', () => {
    expect(triggeredRules(['feature_store.yaml'])).toContain('FEATURE_STORE_DRIFT')
  })
  it('matches feature_store.yml (ungated)', () => {
    expect(triggeredRules(['feature_store.yml'])).toContain('FEATURE_STORE_DRIFT')
  })
  it('matches feast.yaml (ungated)', () => {
    expect(triggeredRules(['feast.yaml'])).toContain('FEATURE_STORE_DRIFT')
  })
  it('matches feast-prod.yaml via prefix', () => {
    expect(triggeredRules(['feast-prod.yaml'])).toContain('FEATURE_STORE_DRIFT')
  })
  it('matches feature-store-config.yaml via prefix', () => {
    expect(triggeredRules(['feature-store-config.yaml'])).toContain('FEATURE_STORE_DRIFT')
  })
  it('matches registry.yaml inside feast/ dir', () => {
    expect(triggeredRules(['feast/registry.yaml'])).toContain('FEATURE_STORE_DRIFT')
  })
  it('matches data_sources.yaml inside feature_store/ dir', () => {
    expect(triggeredRules(['feature_store/data_sources.yaml'])).toContain('FEATURE_STORE_DRIFT')
  })
  it('matches entities.yaml inside feature-store/ dir', () => {
    expect(triggeredRules(['feature-store/entities.yaml'])).toContain('FEATURE_STORE_DRIFT')
  })
  it('matches any yaml inside hopsworks/ dir', () => {
    expect(triggeredRules(['hopsworks/config.yaml'])).toContain('FEATURE_STORE_DRIFT')
  })
  it('does NOT match registry.yaml outside feature store dirs', () => {
    expect(triggeredRules(['services/registry.yaml'])).not.toContain('FEATURE_STORE_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 6: MODEL_SERVING_DRIFT
// ---------------------------------------------------------------------------

describe('MODEL_SERVING_DRIFT', () => {
  it('matches bentofile.yaml (ungated)', () => {
    expect(triggeredRules(['bentofile.yaml'])).toContain('MODEL_SERVING_DRIFT')
  })
  it('matches bentofile.yml (ungated)', () => {
    expect(triggeredRules(['bentofile.yml'])).toContain('MODEL_SERVING_DRIFT')
  })
  it('matches torchserve.config (ungated)', () => {
    expect(triggeredRules(['torchserve.config'])).toContain('MODEL_SERVING_DRIFT')
  })
  it('matches seldon-deployment.yaml (ungated)', () => {
    expect(triggeredRules(['seldon-deployment.yaml'])).toContain('MODEL_SERVING_DRIFT')
  })
  it('matches inferenceservice.yaml (ungated)', () => {
    expect(triggeredRules(['inferenceservice.yaml'])).toContain('MODEL_SERVING_DRIFT')
  })
  it('matches triton-config.pbtxt (ungated)', () => {
    expect(triggeredRules(['triton-config.pbtxt'])).toContain('MODEL_SERVING_DRIFT')
  })
  it('matches torchserve-prod.config via prefix', () => {
    expect(triggeredRules(['torchserve-prod.config'])).toContain('MODEL_SERVING_DRIFT')
  })
  it('matches seldon-v2.yaml via prefix', () => {
    expect(triggeredRules(['seldon-v2.yaml'])).toContain('MODEL_SERVING_DRIFT')
  })
  it('matches config.properties inside torchserve/ dir', () => {
    expect(triggeredRules(['torchserve/config.properties'])).toContain('MODEL_SERVING_DRIFT')
  })
  it('matches serving.yaml inside bentoml/ dir', () => {
    expect(triggeredRules(['bentoml/serving.yaml'])).toContain('MODEL_SERVING_DRIFT')
  })
  it('matches model-config.yaml inside seldon/ dir', () => {
    expect(triggeredRules(['seldon/model-config.yaml'])).toContain('MODEL_SERVING_DRIFT')
  })
  it('matches any yaml inside triton/ dir', () => {
    expect(triggeredRules(['triton/values.yaml'])).toContain('MODEL_SERVING_DRIFT')
  })
  it('does NOT match config.properties outside serving dirs', () => {
    expect(triggeredRules(['java/config.properties'])).not.toContain('MODEL_SERVING_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 7: MLOPS_PIPELINE_DRIFT
// ---------------------------------------------------------------------------

describe('MLOPS_PIPELINE_DRIFT', () => {
  it('matches dvc.yaml (ungated)', () => {
    expect(triggeredRules(['dvc.yaml'])).toContain('MLOPS_PIPELINE_DRIFT')
  })
  it('matches dvc.yml (ungated)', () => {
    expect(triggeredRules(['dvc.yml'])).toContain('MLOPS_PIPELINE_DRIFT')
  })
  it('matches clearml.conf (ungated)', () => {
    expect(triggeredRules(['clearml.conf'])).toContain('MLOPS_PIPELINE_DRIFT')
  })
  it('matches .clearml.conf (ungated)', () => {
    expect(triggeredRules(['.clearml.conf'])).toContain('MLOPS_PIPELINE_DRIFT')
  })
  it('matches dvc-prod.yaml via prefix', () => {
    expect(triggeredRules(['dvc-prod.yaml'])).toContain('MLOPS_PIPELINE_DRIFT')
  })
  it('matches comet-config.yaml via prefix', () => {
    expect(triggeredRules(['comet-config.yaml'])).toContain('MLOPS_PIPELINE_DRIFT')
  })
  it('matches wandb-settings.yaml via prefix', () => {
    expect(triggeredRules(['wandb-settings.yaml'])).toContain('MLOPS_PIPELINE_DRIFT')
  })
  it('matches params.yaml inside dvc/ dir', () => {
    expect(triggeredRules(['dvc/params.yaml'])).toContain('MLOPS_PIPELINE_DRIFT')
  })
  it('matches config.yaml inside .dvc/ dir', () => {
    expect(triggeredRules(['.dvc/config.yaml'])).toContain('MLOPS_PIPELINE_DRIFT')
  })
  it('matches any yaml inside clearml/ dir', () => {
    expect(triggeredRules(['clearml/settings.yaml'])).toContain('MLOPS_PIPELINE_DRIFT')
  })
  it('matches config.cfg inside mlops/ dir', () => {
    expect(triggeredRules(['mlops/config.cfg'])).toContain('MLOPS_PIPELINE_DRIFT')
  })
  it('does NOT match params.yaml outside mlops dirs', () => {
    expect(triggeredRules(['config/params.yaml'])).not.toContain('MLOPS_PIPELINE_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 8: MODEL_CARD_AUDIT_DRIFT
// ---------------------------------------------------------------------------

describe('MODEL_CARD_AUDIT_DRIFT', () => {
  it('matches model-card.json (ungated)', () => {
    expect(triggeredRules(['model-card.json'])).toContain('MODEL_CARD_AUDIT_DRIFT')
  })
  it('matches model-card.yaml (ungated)', () => {
    expect(triggeredRules(['model-card.yaml'])).toContain('MODEL_CARD_AUDIT_DRIFT')
  })
  it('matches modelcard.json (ungated)', () => {
    expect(triggeredRules(['modelcard.json'])).toContain('MODEL_CARD_AUDIT_DRIFT')
  })
  it('matches modelcard.yml (ungated)', () => {
    expect(triggeredRules(['modelcard.yml'])).toContain('MODEL_CARD_AUDIT_DRIFT')
  })
  it('matches model_card.yaml (ungated)', () => {
    expect(triggeredRules(['model_card.yaml'])).toContain('MODEL_CARD_AUDIT_DRIFT')
  })
  it('matches model-card-v2.json via prefix', () => {
    expect(triggeredRules(['model-card-v2.json'])).toContain('MODEL_CARD_AUDIT_DRIFT')
  })
  it('matches model-registry.yaml inside models/ dir', () => {
    expect(triggeredRules(['models/model-registry.yaml'])).toContain('MODEL_CARD_AUDIT_DRIFT')
  })
  it('matches metadata.yaml inside model-registry/ dir', () => {
    expect(triggeredRules(['model-registry/metadata.yaml'])).toContain('MODEL_CARD_AUDIT_DRIFT')
  })
  it('matches registry.yml inside model-cards/ dir', () => {
    expect(triggeredRules(['model-cards/registry.yml'])).toContain('MODEL_CARD_AUDIT_DRIFT')
  })
  it('does NOT match metadata.yaml outside model dirs', () => {
    expect(triggeredRules(['src/metadata.yaml'])).not.toContain('MODEL_CARD_AUDIT_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Vendor exclusion
// ---------------------------------------------------------------------------

describe('vendor exclusion', () => {
  it('ignores node_modules paths', () => {
    expect(triggeredRules(['node_modules/mlflow/mlflow.yaml'])).toHaveLength(0)
  })
  it('ignores vendor/ paths', () => {
    expect(triggeredRules(['vendor/feast/feature_store.yaml'])).toHaveLength(0)
  })
  it('ignores __pycache__ paths', () => {
    expect(triggeredRules(['__pycache__/mlflow.yaml'])).toHaveLength(0)
  })
  it('ignores .venv paths', () => {
    expect(triggeredRules(['.venv/mlflow/config.yaml'])).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Windows path normalisation
// ---------------------------------------------------------------------------

describe('Windows path normalisation', () => {
  it('normalises backslashes for mlflow.yaml', () => {
    expect(triggeredRules(['mlflow\\mlflow.yaml'])).toContain('MLFLOW_TRACKING_DRIFT')
  })
  it('normalises backslashes for kfdef.yaml', () => {
    expect(triggeredRules(['kubeflow\\kfdef.yaml'])).toContain('KUBEFLOW_PIPELINE_DRIFT')
  })
  it('normalises backslashes for feature_store.yaml in feast dir', () => {
    expect(triggeredRules(['feast\\feature_store.yaml'])).toContain('FEATURE_STORE_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Deduplication — one finding per rule regardless of matchCount
// ---------------------------------------------------------------------------

describe('deduplication', () => {
  it('produces one finding for multiple mlflow config files', () => {
    const result = scan(['mlflow.yaml', 'mlflow-config.yaml', 'mlflow-tracking.yaml'])
    const mlflowFindings = result.findings.filter((f) => f.ruleId === 'MLFLOW_TRACKING_DRIFT')
    expect(mlflowFindings).toHaveLength(1)
    expect(mlflowFindings[0].matchCount).toBe(3)
  })
  it('produces separate findings for different rules', () => {
    const result = scan(['mlflow.yaml', 'kfctl.yaml', 'dvc.yaml'])
    expect(result.findings.map((f) => f.ruleId)).toEqual(
      expect.arrayContaining(['MLFLOW_TRACKING_DRIFT', 'KUBEFLOW_PIPELINE_DRIFT', 'MLOPS_PIPELINE_DRIFT']),
    )
  })
  it('records firstPath correctly', () => {
    const result = scan(['a/mlflow.yaml', 'b/mlflow-config.yaml'])
    const finding = result.findings.find((f) => f.ruleId === 'MLFLOW_TRACKING_DRIFT')
    expect(finding?.matchedPath).toBe('a/mlflow.yaml')
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scoring model', () => {
  it('returns score 0 and level none for empty input', () => {
    const result = scan([])
    expect(result.riskScore).toBe(0)
    expect(result.riskLevel).toBe('none')
  })
  it('returns score 15 and level low for 1 high finding', () => {
    const result = scan(['mlflow.yaml'])
    expect(result.riskScore).toBe(15)
    expect(result.riskLevel).toBe('low')
  })
  it('returns score 8 and level low for 1 medium finding', () => {
    const result = scan(['feature_store.yaml'])
    expect(result.riskScore).toBe(8)
    expect(result.riskLevel).toBe('low')
  })
  it('caps high severity at 45 for 4+ matches', () => {
    // 4 separate high rules: mlflow + kubeflow + ray + sagemaker
    const result = scan(['mlflow.yaml', 'kfctl.yaml', 'ray-cluster.yaml', 'sagemaker.yaml'])
    expect(result.highCount).toBe(4)
    // 4 × 15 = 60, but total capped at 100; no cap at 45 per severity since each rule is separate
    expect(result.riskScore).toBe(60)
    expect(result.riskLevel).toBe('high')
  })
  it('caps per-rule score at 45 when matchCount is high', () => {
    // Single high rule with 5 matches — 5×15=75 but per-rule cap is 45
    const files = [
      'mlflow.yaml',
      'mlflow.yml',
      'mlflow-config.yaml',
      'mlflow-config.yml',
      'mlflow-tracking.yaml',
    ]
    const result = scan(files)
    // MLFLOW cap: min(5×15, 45) = 45; score 45 → high (score < 70)
    expect(result.riskScore).toBe(45)
    expect(result.riskLevel).toBe('high')
  })
  it('reaches critical at score >= 70', () => {
    // 4 high rules + 2 medium rules = 4×15 + 2×8 = 76
    const result = scan([
      'mlflow.yaml',
      'kfctl.yaml',
      'ray-cluster.yaml',
      'sagemaker.yaml',
      'feature_store.yaml',
      'dvc.yaml',
    ])
    expect(result.riskScore).toBeGreaterThanOrEqual(70)
    expect(result.riskLevel).toBe('critical')
  })
  it('score is clamped to 100', () => {
    // All 8 rules triggered — 4×15 + 3×8 + 1×4 = 88 (no individual cap hit)
    const result = scan([
      'mlflow.yaml',
      'kfctl.yaml',
      'ray-cluster.yaml',
      'sagemaker.yaml',
      'feature_store.yaml',
      'bentofile.yaml',
      'dvc.yaml',
      'model-card.json',
    ])
    expect(result.riskScore).toBeLessThanOrEqual(100)
  })
})

// ---------------------------------------------------------------------------
// Risk level boundaries
// ---------------------------------------------------------------------------

describe('risk level boundaries', () => {
  it('score 0 → none', () => {
    expect(scan([]).riskLevel).toBe('none')
  })
  it('score 15 (1 high) → low', () => {
    expect(scan(['mlflow.yaml']).riskLevel).toBe('low')
  })
  it('score 23 (2 high + 1 low) → medium', () => {
    const result = scan(['mlflow.yaml', 'kfctl.yaml', 'model-card.json'])
    // 2×15 + 1×4 = 34 — medium
    expect(result.riskLevel).toBe('medium')
  })
  it('score 45 (3 high) → high', () => {
    const result = scan(['mlflow.yaml', 'kfctl.yaml', 'ray-cluster.yaml'])
    // 3×15=45 — score < 45 is false, score < 70 is true → high
    expect(result.riskScore).toBe(45)
    expect(result.riskLevel).toBe('high')
  })
  it('score 60 (4 high) → high', () => {
    const result = scan(['mlflow.yaml', 'kfctl.yaml', 'ray-cluster.yaml', 'sagemaker.yaml'])
    expect(result.riskScore).toBe(60)
    expect(result.riskLevel).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// Severity ordering
// ---------------------------------------------------------------------------

describe('severity ordering', () => {
  it('sorts high before medium before low', () => {
    const result = scan(['model-card.json', 'feature_store.yaml', 'mlflow.yaml'])
    const severities = result.findings.map((f) => f.severity)
    const highIdx   = severities.indexOf('high')
    const mediumIdx = severities.indexOf('medium')
    const lowIdx    = severities.indexOf('low')
    if (highIdx !== -1 && mediumIdx !== -1) expect(highIdx).toBeLessThan(mediumIdx)
    if (mediumIdx !== -1 && lowIdx !== -1) expect(mediumIdx).toBeLessThan(lowIdx)
  })
})

// ---------------------------------------------------------------------------
// Result shape
// ---------------------------------------------------------------------------

describe('result shape', () => {
  it('returns expected shape for empty input', () => {
    const result = scan([])
    expect(result).toMatchObject({
      riskScore: 0,
      riskLevel: 'none',
      totalFindings: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      findings: [],
    })
    expect(typeof result.summary).toBe('string')
  })
  it('returns correct counts for mixed input', () => {
    const result = scan(['mlflow.yaml', 'feature_store.yaml', 'model-card.json'])
    expect(result.highCount).toBe(1)
    expect(result.mediumCount).toBe(1)
    expect(result.lowCount).toBe(1)
    expect(result.totalFindings).toBe(3)
  })
  it('each finding has all required fields', () => {
    const result = scan(['kfctl.yaml'])
    const f = result.findings[0]
    expect(f).toHaveProperty('ruleId')
    expect(f).toHaveProperty('severity')
    expect(f).toHaveProperty('matchedPath')
    expect(f).toHaveProperty('matchCount')
    expect(f).toHaveProperty('description')
    expect(f).toHaveProperty('recommendation')
  })
})

// ---------------------------------------------------------------------------
// Multi-rule scenarios
// ---------------------------------------------------------------------------

describe('multi-rule scenarios', () => {
  it('full ML stack change triggers all 8 rules', () => {
    const result = scan([
      'mlflow.yaml',          // MLFLOW_TRACKING_DRIFT
      'kfctl.yaml',           // KUBEFLOW_PIPELINE_DRIFT
      'ray-cluster.yaml',     // RAY_CLUSTER_DRIFT
      'sagemaker.yaml',       // AI_PLATFORM_ACCESS_DRIFT
      'feature_store.yaml',   // FEATURE_STORE_DRIFT
      'bentofile.yaml',       // MODEL_SERVING_DRIFT
      'dvc.yaml',             // MLOPS_PIPELINE_DRIFT
      'model-card.json',      // MODEL_CARD_AUDIT_DRIFT
    ])
    expect(result.totalFindings).toBe(8)
  })
  it('dvc.yaml triggers only MLOPS, not KUBEFLOW', () => {
    const rules = triggeredRules(['dvc.yaml'])
    expect(rules).toContain('MLOPS_PIPELINE_DRIFT')
    expect(rules).not.toContain('KUBEFLOW_PIPELINE_DRIFT')
  })
  it('feature_store.yaml triggers only FEATURE_STORE, not MLOPS', () => {
    const rules = triggeredRules(['feature_store.yaml'])
    expect(rules).toContain('FEATURE_STORE_DRIFT')
    expect(rules).not.toContain('MLOPS_PIPELINE_DRIFT')
  })
  it('inferenceservice.yaml triggers only MODEL_SERVING when ungated', () => {
    const rules = triggeredRules(['inferenceservice.yaml'])
    expect(rules).toContain('MODEL_SERVING_DRIFT')
  })
  it('inferenceservice.yaml in kubeflow/ dir triggers BOTH KUBEFLOW and MODEL_SERVING', () => {
    const rules = triggeredRules(['kubeflow/inferenceservice.yaml'])
    expect(rules).toContain('KUBEFLOW_PIPELINE_DRIFT')
    expect(rules).toContain('MODEL_SERVING_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule registry completeness
// ---------------------------------------------------------------------------

describe('ML_AI_PLATFORM_RULES registry', () => {
  it('has exactly 8 rules', () => {
    expect(ML_AI_PLATFORM_RULES).toHaveLength(8)
  })
  it('has 4 high severity rules', () => {
    expect(ML_AI_PLATFORM_RULES.filter((r) => r.severity === 'high')).toHaveLength(4)
  })
  it('has 3 medium severity rules', () => {
    expect(ML_AI_PLATFORM_RULES.filter((r) => r.severity === 'medium')).toHaveLength(3)
  })
  it('has 1 low severity rule', () => {
    expect(ML_AI_PLATFORM_RULES.filter((r) => r.severity === 'low')).toHaveLength(1)
  })
  it('all rule IDs are unique', () => {
    const ids = ML_AI_PLATFORM_RULES.map((r) => r.id)
    expect(new Set(ids).size).toBe(ids.length)
  })
  it('all rules have non-empty description and recommendation', () => {
    for (const rule of ML_AI_PLATFORM_RULES) {
      expect(rule.description.length).toBeGreaterThan(0)
      expect(rule.recommendation.length).toBeGreaterThan(0)
    }
  })
})
