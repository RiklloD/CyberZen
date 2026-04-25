import { describe, expect, it } from 'vitest'
import {
  CICD_PIPELINE_SECURITY_RULES,
  isTektonPipelineConfig,
  scanCicdPipelineSecurityDrift,
  type CicdPipelineSecurityRuleId,
} from './cicdPipelineSecurityDrift'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hasRule(paths: string[], ruleId: CicdPipelineSecurityRuleId): boolean {
  return scanCicdPipelineSecurityDrift(paths).findings.some((f) => f.ruleId === ruleId)
}

function getResult(paths: string[]) {
  return scanCicdPipelineSecurityDrift(paths)
}

// ---------------------------------------------------------------------------
// Trivial inputs
// ---------------------------------------------------------------------------

describe('trivial inputs', () => {
  it('empty array → no findings, riskScore 0, riskLevel none', () => {
    const r = getResult([])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
    expect(r.findings).toHaveLength(0)
  })

  it('single unrelated file → no findings', () => {
    expect(getResult(['src/auth.ts']).findings).toHaveLength(0)
  })

  it('vendor dir excluded', () => {
    const r = getResult(['node_modules/.github/workflows/ci.yml'])
    expect(r.findings).toHaveLength(0)
  })

  it('.git dir excluded', () => {
    expect(getResult(['.git/COMMIT_EDITMSG']).findings).toHaveLength(0)
  })

  it('dist/ dir excluded', () => {
    expect(getResult(['dist/.buildkite/pipeline.yml']).findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// GITHUB_ACTIONS_WORKFLOW_DRIFT
// ---------------------------------------------------------------------------

describe('GITHUB_ACTIONS_WORKFLOW_DRIFT', () => {
  const RULE: CicdPipelineSecurityRuleId = 'GITHUB_ACTIONS_WORKFLOW_DRIFT'

  it('.github/workflows/ci.yml → flagged', () =>
    expect(hasRule(['.github/workflows/ci.yml'], RULE)).toBe(true))

  it('.github/workflows/deploy.yaml → flagged', () =>
    expect(hasRule(['.github/workflows/deploy.yaml'], RULE)).toBe(true))

  it('.github/workflows/security-audit.yml → flagged', () =>
    expect(hasRule(['.github/workflows/security-audit.yml'], RULE)).toBe(true))

  it('.github/workflows/release.yml → flagged', () =>
    expect(hasRule(['.github/workflows/release.yml'], RULE)).toBe(true))

  it('.github/actions/composite/action.yml → flagged', () =>
    expect(hasRule(['.github/actions/composite/action.yml'], RULE)).toBe(true))

  it('.github/actions/setup/action.yaml → flagged', () =>
    expect(hasRule(['.github/actions/setup/action.yaml'], RULE)).toBe(true))

  it('root action.yml (standalone action repo) → flagged', () =>
    expect(hasRule(['action.yml'], RULE)).toBe(true))

  it('root action.yaml → flagged', () =>
    expect(hasRule(['action.yaml'], RULE)).toBe(true))

  it('github/workflows/ci.yml (missing dot prefix) NOT flagged', () =>
    expect(hasRule(['github/workflows/ci.yml'], RULE)).toBe(false))

  it('workflows/ci.yml (missing .github/) NOT flagged', () =>
    expect(hasRule(['workflows/ci.yml'], RULE)).toBe(false))

  it('src/action.yml (not root-level) NOT flagged', () =>
    expect(hasRule(['src/action.yml'], RULE)).toBe(false))

  it('github-actions-result.json NOT flagged', () =>
    expect(hasRule(['github-actions-result.json'], RULE)).toBe(false))

  it('dedup: 3 workflow files → 1 finding, matchCount=3', () => {
    const r = getResult([
      '.github/workflows/ci.yml',
      '.github/workflows/deploy.yaml',
      '.github/workflows/security.yml',
    ])
    const f = r.findings.find((x) => x.ruleId === RULE)
    expect(f).toBeDefined()
    expect(f!.matchCount).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// JENKINS_PIPELINE_SECURITY_DRIFT
// ---------------------------------------------------------------------------

describe('JENKINS_PIPELINE_SECURITY_DRIFT', () => {
  const RULE: CicdPipelineSecurityRuleId = 'JENKINS_PIPELINE_SECURITY_DRIFT'

  it('Jenkinsfile (no extension) → flagged', () =>
    expect(hasRule(['Jenkinsfile'], RULE)).toBe(true))

  it('Jenkinsfile.prod → flagged', () =>
    expect(hasRule(['Jenkinsfile.prod'], RULE)).toBe(true))

  it('Jenkinsfile.deploy → flagged', () =>
    expect(hasRule(['Jenkinsfile.deploy'], RULE)).toBe(true))

  it('Jenkinsfile.groovy → flagged', () =>
    expect(hasRule(['Jenkinsfile.groovy'], RULE)).toBe(true))

  it('jenkins.yaml → flagged', () =>
    expect(hasRule(['jenkins.yaml'], RULE)).toBe(true))

  it('jenkins.yml → flagged', () =>
    expect(hasRule(['jenkins.yml'], RULE)).toBe(true))

  it('ci/jenkins/pipeline.groovy → flagged', () =>
    expect(hasRule(['ci/jenkins/pipeline.groovy'], RULE)).toBe(true))

  it('jenkins/agent.yml → flagged', () =>
    expect(hasRule(['jenkins/agent.yml'], RULE)).toBe(true))

  it('.jenkins/Jenkinsfile → flagged', () =>
    expect(hasRule(['.jenkins/Jenkinsfile'], RULE)).toBe(true))

  it('.jenkins/config.yaml → flagged', () =>
    expect(hasRule(['.jenkins/config.yaml'], RULE)).toBe(true))

  it('jenkins-agent.yaml → flagged (jenkins- prefix)', () =>
    expect(hasRule(['jenkins-agent.yaml'], RULE)).toBe(true))

  it('jenkins-config.yml → flagged (jenkins- prefix)', () =>
    expect(hasRule(['jenkins-config.yml'], RULE)).toBe(true))

  it('generic Makefile NOT flagged', () =>
    expect(hasRule(['Makefile'], RULE)).toBe(false))

  it('pipeline.yaml (no jenkins/ dir) NOT flagged', () =>
    expect(hasRule(['pipeline.yaml'], RULE)).toBe(false))
})

// ---------------------------------------------------------------------------
// GITLAB_CI_SECURITY_DRIFT
// ---------------------------------------------------------------------------

describe('GITLAB_CI_SECURITY_DRIFT', () => {
  const RULE: CicdPipelineSecurityRuleId = 'GITLAB_CI_SECURITY_DRIFT'

  it('.gitlab-ci.yml → flagged (globally unambiguous)', () =>
    expect(hasRule(['.gitlab-ci.yml'], RULE)).toBe(true))

  it('.gitlab-ci.yaml → flagged', () =>
    expect(hasRule(['.gitlab-ci.yaml'], RULE)).toBe(true))

  it('.gitlab/ci/deploy.yml → flagged', () =>
    expect(hasRule(['.gitlab/ci/deploy.yml'], RULE)).toBe(true))

  it('.gitlab/ci/security-scan.yaml → flagged', () =>
    expect(hasRule(['.gitlab/ci/security-scan.yaml'], RULE)).toBe(true))

  it('gitlab/ci/templates.yml → flagged', () =>
    expect(hasRule(['gitlab/ci/templates.yml'], RULE)).toBe(true))

  it('gitlab-ci-templates.yml → flagged (gitlab-ci- prefix)', () =>
    expect(hasRule(['gitlab-ci-templates.yml'], RULE)).toBe(true))

  it('gitlab-ci-security.yaml → flagged (gitlab-ci- prefix)', () =>
    expect(hasRule(['gitlab-ci-security.yaml'], RULE)).toBe(true))

  it('gitlab-report.json NOT flagged', () =>
    expect(hasRule(['gitlab-report.json'], RULE)).toBe(false))

  it('git-config.yml NOT flagged', () =>
    expect(hasRule(['git-config.yml'], RULE)).toBe(false))
})

// ---------------------------------------------------------------------------
// ARGOCD_APP_SECURITY_DRIFT
// ---------------------------------------------------------------------------

describe('ARGOCD_APP_SECURITY_DRIFT', () => {
  const RULE: CicdPipelineSecurityRuleId = 'ARGOCD_APP_SECURITY_DRIFT'

  it('appproject.yaml → flagged (globally unambiguous)', () =>
    expect(hasRule(['appproject.yaml'], RULE)).toBe(true))

  it('appproject.yml → flagged', () =>
    expect(hasRule(['appproject.yml'], RULE)).toBe(true))

  it('applicationset.yaml → flagged (globally unambiguous)', () =>
    expect(hasRule(['applicationset.yaml'], RULE)).toBe(true))

  it('applicationset.yml → flagged', () =>
    expect(hasRule(['applicationset.yml'], RULE)).toBe(true))

  it('argocd-application.yaml → flagged', () =>
    expect(hasRule(['argocd-application.yaml'], RULE)).toBe(true))

  it('application.yaml in argocd/ dir → flagged (gated)', () =>
    expect(hasRule(['argocd/application.yaml'], RULE)).toBe(true))

  it('application.yaml in argo/ dir → flagged (gated)', () =>
    expect(hasRule(['argo/apps/application.yaml'], RULE)).toBe(true))

  it('application.yaml (no dir context) NOT flagged', () =>
    expect(hasRule(['application.yaml'], RULE)).toBe(false))

  it('argocd/prod.yaml → flagged (argocd/ dir)', () =>
    expect(hasRule(['argocd/prod.yaml'], RULE)).toBe(true))

  it('argocd-apps/staging.yaml → flagged (argocd-apps/ dir)', () =>
    expect(hasRule(['argocd-apps/staging.yaml'], RULE)).toBe(true))

  it('argocd-config.yaml → flagged (argocd- prefix)', () =>
    expect(hasRule(['argocd-config.yaml'], RULE)).toBe(true))

  it('generic apps/myapp.yaml NOT flagged', () =>
    expect(hasRule(['apps/myapp.yaml'], RULE)).toBe(false))
})

// ---------------------------------------------------------------------------
// FLUX_GITOPS_SECURITY_DRIFT
// ---------------------------------------------------------------------------

describe('FLUX_GITOPS_SECURITY_DRIFT', () => {
  const RULE: CicdPipelineSecurityRuleId = 'FLUX_GITOPS_SECURITY_DRIFT'

  it('helmrelease.yaml → flagged (globally unambiguous)', () =>
    expect(hasRule(['helmrelease.yaml'], RULE)).toBe(true))

  it('helmrelease.yml → flagged', () =>
    expect(hasRule(['helmrelease.yml'], RULE)).toBe(true))

  it('gitrepository.yaml → flagged', () =>
    expect(hasRule(['gitrepository.yaml'], RULE)).toBe(true))

  it('imagepolicy.yaml → flagged', () =>
    expect(hasRule(['imagepolicy.yaml'], RULE)).toBe(true))

  it('imagerepository.yaml → flagged', () =>
    expect(hasRule(['imagerepository.yaml'], RULE)).toBe(true))

  it('imageupdateautomation.yaml → flagged', () =>
    expect(hasRule(['imageupdateautomation.yaml'], RULE)).toBe(true))

  it('ocirepository.yaml → flagged', () =>
    expect(hasRule(['ocirepository.yaml'], RULE)).toBe(true))

  it('helmrepository.yaml → flagged', () =>
    expect(hasRule(['helmrepository.yaml'], RULE)).toBe(true))

  it('helmchart.yaml → flagged', () =>
    expect(hasRule(['helmchart.yaml'], RULE)).toBe(true))

  it('kustomization.yaml in flux/ dir → flagged (gated)', () =>
    expect(hasRule(['flux/kustomization.yaml'], RULE)).toBe(true))

  it('kustomization.yaml in flux-system/ dir → flagged (gated)', () =>
    expect(hasRule(['flux-system/kustomization.yaml'], RULE)).toBe(true))

  it('kustomization.yaml (no flux/ dir) NOT flagged', () =>
    expect(hasRule(['kustomization.yaml'], RULE)).toBe(false))

  it('kustomization.yaml in k8s/ dir NOT flagged', () =>
    expect(hasRule(['k8s/kustomization.yaml'], RULE)).toBe(false))

  it('flux-system/gotk-sync.yaml → flagged (flux-system/ dir)', () =>
    expect(hasRule(['flux-system/gotk-sync.yaml'], RULE)).toBe(true))

  it('fluxcd/config.yaml → flagged', () =>
    expect(hasRule(['fluxcd/config.yaml'], RULE)).toBe(true))

  it('flux-config.yaml → flagged (flux- prefix)', () =>
    expect(hasRule(['flux-config.yaml'], RULE)).toBe(true))

  it('flux-apps/prod.yaml → flagged', () =>
    expect(hasRule(['flux-apps/prod.yaml'], RULE)).toBe(true))
})

// ---------------------------------------------------------------------------
// BUILDKITE_CIRCLECI_DRIFT
// ---------------------------------------------------------------------------

describe('BUILDKITE_CIRCLECI_DRIFT', () => {
  const RULE: CicdPipelineSecurityRuleId = 'BUILDKITE_CIRCLECI_DRIFT'

  it('.buildkite/pipeline.yml → flagged', () =>
    expect(hasRule(['.buildkite/pipeline.yml'], RULE)).toBe(true))

  it('.buildkite/deploy.yaml → flagged', () =>
    expect(hasRule(['.buildkite/deploy.yaml'], RULE)).toBe(true))

  it('.buildkite/notify.json → flagged', () =>
    expect(hasRule(['.buildkite/notify.json'], RULE)).toBe(true))

  it('.circleci/config.yml → flagged', () =>
    expect(hasRule(['.circleci/config.yml'], RULE)).toBe(true))

  it('.circleci/continue_config.yml → flagged', () =>
    expect(hasRule(['.circleci/continue_config.yml'], RULE)).toBe(true))

  it('buildkite-config.yaml → flagged (buildkite- prefix)', () =>
    expect(hasRule(['buildkite-config.yaml'], RULE)).toBe(true))

  it('pipeline.yml (no .buildkite/) NOT flagged', () =>
    expect(hasRule(['pipeline.yml'], RULE)).toBe(false))

  it('circleci-config.yml (no .circleci/) NOT flagged', () =>
    expect(hasRule(['circleci-config.yml'], RULE)).toBe(false))

  it('config.yml (no CI dir) NOT flagged', () =>
    expect(hasRule(['config.yml'], RULE)).toBe(false))
})

// ---------------------------------------------------------------------------
// TEKTON_PIPELINE_DRIFT — isTektonPipelineConfig dedicated tests
// ---------------------------------------------------------------------------

describe('TEKTON_PIPELINE_DRIFT (isTektonPipelineConfig)', () => {
  const RULE: CicdPipelineSecurityRuleId = 'TEKTON_PIPELINE_DRIFT'

  it('clustertask.yaml → flagged (globally unambiguous)', () =>
    expect(hasRule(['clustertask.yaml'], RULE)).toBe(true))

  it('clustertask.yml → flagged', () =>
    expect(hasRule(['clustertask.yml'], RULE)).toBe(true))

  it('taskrun.yaml → flagged (globally unambiguous)', () =>
    expect(hasRule(['taskrun.yaml'], RULE)).toBe(true))

  it('taskrun.yml → flagged', () =>
    expect(hasRule(['taskrun.yml'], RULE)).toBe(true))

  it('pipelinerun.yaml → flagged (globally unambiguous)', () =>
    expect(hasRule(['pipelinerun.yaml'], RULE)).toBe(true))

  it('pipelinerun.yml → flagged', () =>
    expect(hasRule(['pipelinerun.yml'], RULE)).toBe(true))

  it('stepaction.yaml → flagged (globally unambiguous)', () =>
    expect(hasRule(['stepaction.yaml'], RULE)).toBe(true))

  it('stepaction.yml → flagged', () =>
    expect(hasRule(['stepaction.yml'], RULE)).toBe(true))

  it('clustertaskrun.yaml → flagged', () =>
    expect(hasRule(['clustertaskrun.yaml'], RULE)).toBe(true))

  it('tekton/task.yaml → flagged (tekton/ dir context)', () =>
    expect(hasRule(['tekton/task.yaml'], RULE)).toBe(true))

  it('tekton/pipeline.yaml → flagged (tekton/ dir context)', () =>
    expect(hasRule(['tekton/pipeline.yaml'], RULE)).toBe(true))

  it('tekton/build-task.yaml → flagged (tekton/ dir)', () =>
    expect(hasRule(['tekton/build-task.yaml'], RULE)).toBe(true))

  it('.tekton/ci.yaml → flagged (.tekton/ dir)', () =>
    expect(hasRule(['.tekton/ci.yaml'], RULE)).toBe(true))

  it('tekton-pipelines/deploy.yaml → flagged (tekton-pipelines/ dir)', () =>
    expect(hasRule(['tekton-pipelines/deploy.yaml'], RULE)).toBe(true))

  it('tekton-tasks/build.yml → flagged', () =>
    expect(hasRule(['tekton-tasks/build.yml'], RULE)).toBe(true))

  it('ci/tekton/scan.yaml → flagged (ci/tekton/ dir)', () =>
    expect(hasRule(['ci/tekton/scan.yaml'], RULE)).toBe(true))

  it('tekton-task.yaml → flagged (tekton- prefix)', () =>
    expect(hasRule(['tekton-task.yaml'], RULE)).toBe(true))

  it('tekton-pipeline.yaml → flagged (tekton- prefix)', () =>
    expect(hasRule(['tekton-pipeline.yaml'], RULE)).toBe(true))

  it('task.yaml (no tekton dir) NOT flagged', () =>
    expect(hasRule(['task.yaml'], RULE)).toBe(false))

  it('pipeline.yaml (no tekton dir) NOT flagged', () =>
    expect(hasRule(['pipeline.yaml'], RULE)).toBe(false))

  it('task.json → NOT flagged (not yaml)', () =>
    expect(hasRule(['tekton/task.json'], RULE)).toBe(false))

  it('clustertask.yaml in k8s/ dir → NOT flagged (k8s exclusion)', () =>
    expect(hasRule(['k8s/clustertask.yaml'], RULE)).toBe(false))

  it('taskrun.yaml in manifests/ dir → NOT flagged (k8s exclusion)', () =>
    expect(hasRule(['manifests/taskrun.yaml'], RULE)).toBe(false))

  it('pipelinerun.yaml in helm/ dir → NOT flagged (k8s exclusion)', () =>
    expect(hasRule(['helm/charts/tekton/pipelinerun.yaml'], RULE)).toBe(false))

  it('clustertask.yaml in charts/ dir → NOT flagged', () =>
    expect(hasRule(['charts/clustertask.yaml'], RULE)).toBe(false))

  // Direct isTektonPipelineConfig function tests
  it('isTektonPipelineConfig("taskrun.yaml") → true', () =>
    expect(isTektonPipelineConfig('taskrun.yaml')).toBe(true))

  it('isTektonPipelineConfig("tekton/task.yaml") → true', () =>
    expect(isTektonPipelineConfig('tekton/task.yaml')).toBe(true))

  it('isTektonPipelineConfig("task.yaml") → false (ambiguous)', () =>
    expect(isTektonPipelineConfig('task.yaml')).toBe(false))

  it('isTektonPipelineConfig("k8s/taskrun.yaml") → false (k8s exclusion)', () =>
    expect(isTektonPipelineConfig('k8s/taskrun.yaml')).toBe(false))
})

// ---------------------------------------------------------------------------
// PIPELINE_ARTIFACT_SIGNING_DRIFT
// ---------------------------------------------------------------------------

describe('PIPELINE_ARTIFACT_SIGNING_DRIFT', () => {
  const RULE: CicdPipelineSecurityRuleId = 'PIPELINE_ARTIFACT_SIGNING_DRIFT'

  it('.slsa-goreleaser.yml → flagged', () =>
    expect(hasRule(['.slsa-goreleaser.yml'], RULE)).toBe(true))

  it('.slsa-goreleaser.yaml → flagged', () =>
    expect(hasRule(['.slsa-goreleaser.yaml'], RULE)).toBe(true))

  it('slsa-goreleaser.yml → flagged', () =>
    expect(hasRule(['slsa-goreleaser.yml'], RULE)).toBe(true))

  it('slsa-goreleaser.yaml → flagged', () =>
    expect(hasRule(['slsa-goreleaser.yaml'], RULE)).toBe(true))

  it('slsa-policy.yaml → flagged', () =>
    expect(hasRule(['slsa-policy.yaml'], RULE)).toBe(true))

  it('slsa-policy.json → flagged', () =>
    expect(hasRule(['slsa-policy.json'], RULE)).toBe(true))

  it('slsa-verifier.yaml → flagged', () =>
    expect(hasRule(['slsa-verifier.yaml'], RULE)).toBe(true))

  it('slsa-builder.yaml → flagged', () =>
    expect(hasRule(['slsa-builder.yaml'], RULE)).toBe(true))

  it('slsa-generator.yml → flagged', () =>
    expect(hasRule(['slsa-generator.yml'], RULE)).toBe(true))

  it('file in slsa/ dir → flagged', () =>
    expect(hasRule(['slsa/attestation.yaml'], RULE)).toBe(true))

  it('file in supply-chain/ dir → flagged', () =>
    expect(hasRule(['supply-chain/signing-policy.yaml'], RULE)).toBe(true))

  it('slsa-config.yaml → flagged (slsa- prefix)', () =>
    expect(hasRule(['slsa-config.yaml'], RULE)).toBe(true))

  it('provenance.yaml in slsa/ dir → flagged', () =>
    expect(hasRule(['slsa/provenance.yaml'], RULE)).toBe(true))

  it('provenance.yaml (no slsa/ dir) NOT flagged', () =>
    expect(hasRule(['provenance.yaml'], RULE)).toBe(false))

  it('signing.yaml (no slsa prefix/dir) NOT flagged', () =>
    expect(hasRule(['signing.yaml'], RULE)).toBe(false))

  it('goreleaser.yml (not slsa-prefixed) NOT flagged', () =>
    expect(hasRule(['goreleaser.yml'], RULE)).toBe(false))
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scoring model', () => {
  it('empty → riskScore 0, riskLevel none', () => {
    const r = getResult([])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })

  it('1 LOW finding (matchCount=1) → riskScore 4, riskLevel low', () => {
    const r = getResult(['slsa-policy.yaml'])
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('1 MEDIUM finding (matchCount=1) → riskScore 8, riskLevel low', () => {
    const r = getResult(['appproject.yaml'])
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('1 HIGH finding (matchCount=1) → riskScore 15, riskLevel low', () => {
    const r = getResult(['.github/workflows/ci.yml'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('low')
  })

  it('score 43 → medium (1 high + 3 medium + 1 low)', () => {
    const r = getResult([
      '.github/workflows/ci.yml',   // HIGH: 15
      'appproject.yaml',            // MEDIUM: 8
      'helmrelease.yaml',           // MEDIUM: 8
      '.buildkite/pipeline.yml',    // MEDIUM: 8
      'slsa-policy.yaml',           // LOW: 4
    ])
    expect(r.riskScore).toBe(43)
    expect(r.riskLevel).toBe('medium')
  })

  it('score 45 → high (all 3 HIGH rules triggered)', () => {
    const r = getResult([
      '.github/workflows/ci.yml',   // HIGH: 15
      'Jenkinsfile',                // HIGH: 15
      '.gitlab-ci.yml',             // HIGH: 15
    ])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('score ≥ 70 → critical (3 HIGH + 4 MEDIUM rules triggered)', () => {
    const r = getResult([
      '.github/workflows/ci.yml',   // HIGH: 15
      'Jenkinsfile',                // HIGH: 15
      '.gitlab-ci.yml',             // HIGH: 15
      'appproject.yaml',            // MEDIUM: 8
      'helmrelease.yaml',           // MEDIUM: 8
      '.buildkite/pipeline.yml',    // MEDIUM: 8
      'taskrun.yaml',               // MEDIUM: 8
    ])
    // 45 + 32 = 77
    expect(r.riskScore).toBe(77)
    expect(r.riskLevel).toBe('critical')
  })

  it('HIGH penalty cap: 4 workflow files → capped at 45, not 60', () => {
    const r = getResult([
      '.github/workflows/a.yml',
      '.github/workflows/b.yml',
      '.github/workflows/c.yml',
      '.github/workflows/d.yml',
    ])
    expect(r.findings[0]!.matchCount).toBe(4)
    expect(r.riskScore).toBe(45)  // min(4×15, 45)
  })

  it('MEDIUM penalty cap: 4 CircleCI files → capped at 25', () => {
    const r = getResult([
      '.circleci/config.yml',
      '.circleci/continue_config.yml',
      '.circleci/build.yml',
      '.circleci/deploy.yml',
    ])
    const f = r.findings.find((x) => x.ruleId === 'BUILDKITE_CIRCLECI_DRIFT')
    expect(f!.matchCount).toBe(4)
    expect(r.riskScore).toBe(25)  // min(4×8, 25)
  })

  it('LOW penalty cap: 5 SLSA files → capped at 15', () => {
    const r = getResult([
      'slsa-policy.yaml',
      'slsa-builder.yaml',
      'slsa-verifier.yaml',
      'slsa-generator.yml',
      'slsa-config.yaml',
    ])
    const f = r.findings.find((x) => x.ruleId === 'PIPELINE_ARTIFACT_SIGNING_DRIFT')
    expect(f!.matchCount).toBe(5)
    expect(r.riskScore).toBe(15)  // min(5×4, 15)
  })

  it('total riskScore clamped at 100', () => {
    // All 8 rules triggered at matchCount=10 each
    const r = getResult([
      '.github/workflows/ci.yml', '.github/workflows/deploy.yml',
      '.github/workflows/release.yml', '.github/workflows/security.yml',
      '.github/workflows/a.yml', '.github/workflows/b.yml',
      '.github/workflows/c.yml', '.github/workflows/d.yml',
      '.github/workflows/e.yml', '.github/workflows/f.yml',
      'Jenkinsfile', 'Jenkinsfile.prod',
      '.gitlab-ci.yml',
      'appproject.yaml',
      'helmrelease.yaml',
      '.buildkite/pipeline.yml',
      'taskrun.yaml',
      'slsa-policy.yaml',
    ])
    expect(r.riskScore).toBeLessThanOrEqual(100)
  })
})

// ---------------------------------------------------------------------------
// Deduplication and ordering
// ---------------------------------------------------------------------------

describe('deduplication and ordering', () => {
  it('same rule triggered by multiple paths → 1 finding, matchCount=N', () => {
    const r = getResult([
      'Jenkinsfile',
      'Jenkinsfile.prod',
      '.jenkins/config.yaml',
    ])
    const jenkins = r.findings.filter((f) => f.ruleId === 'JENKINS_PIPELINE_SECURITY_DRIFT')
    expect(jenkins).toHaveLength(1)
    expect(jenkins[0]!.matchCount).toBe(3)
  })

  it('findings ordered high → medium → low', () => {
    const r = getResult([
      'slsa-policy.yaml',           // LOW
      'helmrelease.yaml',           // MEDIUM
      '.github/workflows/ci.yml',   // HIGH
    ])
    const sevs = r.findings.map((f) => f.severity)
    const highIdx = sevs.indexOf('high')
    const medIdx  = sevs.indexOf('medium')
    const lowIdx  = sevs.indexOf('low')
    expect(highIdx).toBeLessThan(medIdx)
    expect(medIdx).toBeLessThan(lowIdx)
  })

  it('matchedPath = first file that triggered the rule', () => {
    const r = getResult([
      'Jenkinsfile',
      'Jenkinsfile.prod',
    ])
    const f = r.findings.find((x) => x.ruleId === 'JENKINS_PIPELINE_SECURITY_DRIFT')
    expect(f!.matchedPath).toBe('Jenkinsfile')
  })
})

// ---------------------------------------------------------------------------
// Summary text
// ---------------------------------------------------------------------------

describe('summary text', () => {
  it('none risk level → clean pipeline summary', () => {
    const r = getResult([])
    expect(r.summary).toContain('No CI/CD pipeline security configuration drift')
  })

  it('findings present → summary contains risk level and most prominent rule', () => {
    const r = getResult(['.github/workflows/ci.yml'])
    expect(r.summary).toMatch(/github actions workflow drift/i)
    expect(r.summary).toMatch(/high|medium|low|critical/i)
  })

  it('summary uses plural when multiple findings', () => {
    const r = getResult(['.github/workflows/ci.yml', 'Jenkinsfile'])
    expect(r.summary).toMatch(/findings/)
  })

  it('summary uses singular when single finding', () => {
    const r = getResult(['slsa-policy.yaml'])
    expect(r.summary).toMatch(/finding/)
    expect(r.summary).not.toMatch(/findings/)
  })
})

// ---------------------------------------------------------------------------
// Windows path normalization
// ---------------------------------------------------------------------------

describe('windows path normalization', () => {
  it('backslash paths are normalized and matched', () => {
    expect(hasRule(['.github\\workflows\\ci.yml'], 'GITHUB_ACTIONS_WORKFLOW_DRIFT')).toBe(true)
  })

  it('backslash Jenkinsfile path matched', () => {
    expect(hasRule(['jenkins\\agent.yml'], 'JENKINS_PIPELINE_SECURITY_DRIFT')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Multi-rule scenarios
// ---------------------------------------------------------------------------

describe('multi-rule scenarios', () => {
  it('GitHub Actions + ArgoCD change → 2 findings', () => {
    const r = getResult([
      '.github/workflows/deploy.yml',
      'appproject.yaml',
    ])
    expect(r.findings).toHaveLength(2)
    expect(r.findings.map((f) => f.ruleId)).toContain('GITHUB_ACTIONS_WORKFLOW_DRIFT')
    expect(r.findings.map((f) => f.ruleId)).toContain('ARGOCD_APP_SECURITY_DRIFT')
  })

  it('all 3 high rules triggered → highCount=3, totalFindings=3', () => {
    const r = getResult([
      '.github/workflows/ci.yml',
      'Jenkinsfile',
      '.gitlab-ci.yml',
    ])
    expect(r.highCount).toBe(3)
    expect(r.mediumCount).toBe(0)
    expect(r.lowCount).toBe(0)
    expect(r.totalFindings).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// Registry completeness
// ---------------------------------------------------------------------------

describe('registry completeness', () => {
  it('CICD_PIPELINE_SECURITY_RULES has exactly 8 rules', () => {
    expect(CICD_PIPELINE_SECURITY_RULES).toHaveLength(8)
  })

  it('rule IDs are unique', () => {
    const ids = CICD_PIPELINE_SECURITY_RULES.map((r) => r.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it('severity distribution: 3 high, 4 medium, 1 low', () => {
    const high   = CICD_PIPELINE_SECURITY_RULES.filter((r) => r.severity === 'high').length
    const medium = CICD_PIPELINE_SECURITY_RULES.filter((r) => r.severity === 'medium').length
    const low    = CICD_PIPELINE_SECURITY_RULES.filter((r) => r.severity === 'low').length
    expect(high).toBe(3)
    expect(medium).toBe(4)
    expect(low).toBe(1)
  })

  it('all rules have non-empty description and recommendation', () => {
    for (const rule of CICD_PIPELINE_SECURITY_RULES) {
      expect(rule.description.length).toBeGreaterThan(20)
      expect(rule.recommendation.length).toBeGreaterThan(20)
    }
  })
})
