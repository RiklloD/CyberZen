// WS-73 — CI/CD Pipeline Security Configuration Drift Detector:
// pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to CI/CD pipeline security configuration files. This scanner focuses on the
// *pipeline authorization and execution layer* — the configs that control what
// code runs in CI, what secrets it can access, what gets deployed where, and
// how build artifacts are signed. Drift here can expose all repository secrets,
// allow unauthorized deployments to production, or disable supply-chain signing.
//
// DISTINCT from:
//   WS-05  integration layer            — webhook delivery, CI/CD provider
//                                         connection setup (not pipeline security)
//   WS-57  highRiskChangeResults        — security-sensitive SOURCE CODE changes
//                                         (auth handlers, crypto utils), not the
//                                         CI/CD pipeline orchestration configs
//   WS-58  depLockVerifyResults         — dependency lock file consistency, not
//                                         pipeline job security configurations
//   WS-63  containerHardeningResults    — k8s RBAC/NetworkPolicy/PodSecurity
//                                         (control-plane security), not CI/CD job
//                                         configs that happen to deploy to k8s
//   WS-66  certPkiDriftResults          — cryptographic key material and certificate
//                                         configurations; WS-73 covers the pipeline
//                                         step configs that invoke signing tools,
//                                         not the signing keys themselves
//
// WS-73 vs WS-63: WS-63 covers base k8s security resources (Role, NetworkPolicy,
//   PodSecurityPolicy). WS-73 covers CI/CD orchestration security: ArgoCD
//   AppProject (deployment authorization), FluxCD Kustomization/HelmRelease
//   (GitOps sync authorization), and Tekton Task/Pipeline (CI job definitions).
//   The boundary: "k8s control-plane security" (WS-63) vs "deployment pipeline
//   authorization" (WS-73).
//
// Covered rule groups (8 rules):
//
//   GITHUB_ACTIONS_WORKFLOW_DRIFT   — GitHub Actions workflow and custom action configs
//   JENKINS_PIPELINE_SECURITY_DRIFT — Jenkinsfile and shared-library pipeline configs
//   GITLAB_CI_SECURITY_DRIFT        — GitLab CI/CD pipeline configuration files
//   ARGOCD_APP_SECURITY_DRIFT       — ArgoCD Application/AppProject/ApplicationSet CRDs
//   FLUX_GITOPS_SECURITY_DRIFT      — FluxCD Kustomization/HelmRelease/ImagePolicy CRDs
//   BUILDKITE_CIRCLECI_DRIFT        — Buildkite and CircleCI pipeline configs
//   TEKTON_PIPELINE_DRIFT           — Tekton Task/Pipeline security configs ← user contribution
//   PIPELINE_ARTIFACT_SIGNING_DRIFT — SLSA provenance and artifact signing pipeline configs
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Vendor directory exclusion applied to all paths.
//   • Same penalty/cap scoring model as WS-60–72 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (matchedPath + matchCount).
//   • .github/workflows/ path segment is globally unambiguous for GitHub Actions.
//   • .gitlab-ci.yml is globally unambiguous by exact name.
//   • .circleci/ and .buildkite/ directory prefixes are globally unambiguous.
//   • ArgoCD CRD names (appproject.yaml, applicationset.yaml) are globally
//     unambiguous; generic 'application.yaml' is gated on argocd/ / argo/ dir.
//   • FluxCD CRD names (helmrelease.yaml, gitrepository.yaml, imagepolicy.yaml)
//     are globally unambiguous; 'kustomization.yaml' is gated on flux/ dir
//     because Kustomize standalone also uses this filename.
//   • Tekton disambiguation is the user contribution — see isTektonPipelineConfig.
//   • SLSA detection focuses on provenance config files, not signing key material
//     (WS-66 owns the keys; WS-73 owns the signing step configs in pipelines).
//
// Exports:
//   isTektonPipelineConfig          — user contribution point (see JSDoc below)
//   CICD_PIPELINE_SECURITY_RULES    — readonly rule registry
//   scanCicdPipelineSecurityDrift   — main scanner, returns CicdPipelineSecurityDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type CicdPipelineSecurityRuleId =
  | 'GITHUB_ACTIONS_WORKFLOW_DRIFT'
  | 'JENKINS_PIPELINE_SECURITY_DRIFT'
  | 'GITLAB_CI_SECURITY_DRIFT'
  | 'ARGOCD_APP_SECURITY_DRIFT'
  | 'FLUX_GITOPS_SECURITY_DRIFT'
  | 'BUILDKITE_CIRCLECI_DRIFT'
  | 'TEKTON_PIPELINE_DRIFT'
  | 'PIPELINE_ARTIFACT_SIGNING_DRIFT'

export type CicdPipelineSecuritySeverity = 'high' | 'medium' | 'low'
export type CicdPipelineSecurityRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type CicdPipelineSecurityDriftFinding = {
  ruleId: CicdPipelineSecurityRuleId
  severity: CicdPipelineSecuritySeverity
  matchedPath: string
  matchCount: number
  description: string
  recommendation: string
}

export type CicdPipelineSecurityDriftResult = {
  riskScore: number
  riskLevel: CicdPipelineSecurityRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: CicdPipelineSecurityDriftFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VENDOR_DIRS = [
  'node_modules/', '.git/', 'dist/', 'build/', '.next/', '.nuxt/',
  'vendor/', 'bower_components/', 'coverage/', '__pycache__/',
  '.terraform/', 'cdk.out/', '.cdk/', '.gradle/', '.m2/',
  'target/', 'out/', '.idea/', '.vscode/', '.cache/',
]

const HIGH_PENALTY_PER = 15
const HIGH_PENALTY_CAP = 45
const MED_PENALTY_PER  = 8
const MED_PENALTY_CAP  = 25
const LOW_PENALTY_PER  = 4
const LOW_PENALTY_CAP  = 15

// ---------------------------------------------------------------------------
// Detection helpers — GITHUB_ACTIONS_WORKFLOW_DRIFT
// ---------------------------------------------------------------------------

function isGithubActionsFile(pathLower: string, base: string): boolean {
  // .github/workflows/ contains all GitHub Actions workflow definitions
  if (pathLower.includes('.github/workflows/') &&
      (base.endsWith('.yaml') || base.endsWith('.yml'))) {
    return true
  }
  // .github/actions/ contains composite action definitions
  if (pathLower.includes('.github/actions/') &&
      (base.endsWith('.yaml') || base.endsWith('.yml'))) {
    return true
  }
  // Root-level action.yml / action.yaml — repos that ARE a GitHub Action
  if (pathLower === 'action.yml' || pathLower === 'action.yaml') return true
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — JENKINS_PIPELINE_SECURITY_DRIFT
// ---------------------------------------------------------------------------

function isJenkinsPipelineFile(pathLower: string, base: string): boolean {
  // Jenkinsfile (no extension) and Jenkinsfile.* variants
  if (base === 'jenkinsfile' || base.startsWith('jenkinsfile.')) return true
  // jenkins.yaml / jenkins.yml — Jenkins Configuration as Code (JCasC)
  if (base === 'jenkins.yaml' || base === 'jenkins.yml') return true
  // Files in jenkins/ or .jenkins/ directories
  if (pathLower.includes('jenkins/') || pathLower.includes('.jenkins/')) {
    if (base.endsWith('.groovy') || base.endsWith('.yaml') || base.endsWith('.yml')) {
      return true
    }
  }
  // jenkins-*.yaml / jenkins-*.yml prefix (jenkins-agent.yaml, jenkins-config.yaml)
  if (base.startsWith('jenkins-') &&
      (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json'))) {
    return true
  }
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — GITLAB_CI_SECURITY_DRIFT
// ---------------------------------------------------------------------------

function isGitlabCiFile(pathLower: string, base: string): boolean {
  // .gitlab-ci.yml / .gitlab-ci.yaml — globally unambiguous
  if (base === '.gitlab-ci.yml' || base === '.gitlab-ci.yaml') return true
  // .gitlab/ci/ directory (included pipeline fragments)
  if (pathLower.includes('.gitlab/ci/') &&
      (base.endsWith('.yaml') || base.endsWith('.yml'))) {
    return true
  }
  // gitlab/ci/ (without leading dot, some orgs use this)
  if (pathLower.includes('gitlab/ci/') &&
      (base.endsWith('.yaml') || base.endsWith('.yml'))) {
    return true
  }
  // gitlab-ci- prefix (gitlab-ci-templates.yml, gitlab-ci-security.yaml)
  if (base.startsWith('gitlab-ci-') &&
      (base.endsWith('.yaml') || base.endsWith('.yml'))) {
    return true
  }
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — ARGOCD_APP_SECURITY_DRIFT
// ---------------------------------------------------------------------------

const ARGOCD_UNGATED = new Set([
  // Globally unambiguous ArgoCD CRD names
  'appproject.yaml', 'appproject.yml',
  'applicationset.yaml', 'applicationset.yml',
  'argocd-application.yaml', 'argocd-application.yml',
])

const ARGOCD_DIRS = [
  'argocd/', 'argo/', 'argocd-apps/', 'argo-apps/', 'argocd-config/',
  'argo-config/', 'gitops/', 'argo-cd/', 'argocd-resources/',
]

function isArgocdAppFile(pathLower: string, base: string): boolean {
  if (ARGOCD_UNGATED.has(base)) return true
  for (const dir of ARGOCD_DIRS) {
    if (pathLower.includes(dir) &&
        (base.endsWith('.yaml') || base.endsWith('.yml'))) {
      return true
    }
  }
  // 'application.yaml' is too generic — only flag inside argocd/argo dirs
  if ((base === 'application.yaml' || base === 'application.yml') &&
      (pathLower.includes('argocd/') || pathLower.includes('argo/'))) {
    return true
  }
  if (base.startsWith('argocd-') &&
      (base.endsWith('.yaml') || base.endsWith('.yml'))) {
    return true
  }
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — FLUX_GITOPS_SECURITY_DRIFT
// ---------------------------------------------------------------------------

const FLUX_UNGATED = new Set([
  // Globally unambiguous FluxCD CRD names
  'helmrelease.yaml', 'helmrelease.yml',
  'gitrepository.yaml', 'gitrepository.yml',
  'imagepolicy.yaml', 'imagepolicy.yml',
  'imagerepository.yaml', 'imagerepository.yml',
  'imageupdateautomation.yaml', 'imageupdateautomation.yml',
  'ocirepository.yaml', 'ocirepository.yml',
  'helmrepository.yaml', 'helmrepository.yml',
  'helmchart.yaml', 'helmchart.yml',
  'alert.yaml', 'alert.yml',       // gated on flux/ dir — but keeping ungated since rare
  'receiver.yaml', 'receiver.yml', // Flux alert receiver
])

const FLUX_DIRS = [
  'flux/', 'flux-system/', 'fluxcd/', 'flux-config/',
  'flux-apps/', 'flux-infra/', 'gitops/flux/',
]

function isFluxGitOpsFile(pathLower: string, base: string): boolean {
  // kustomization.yaml is ambiguous (also used by Kustomize standalone) — gate on flux/ dir
  if ((base === 'kustomization.yaml' || base === 'kustomization.yml') &&
      FLUX_DIRS.some((d) => pathLower.includes(d))) {
    return true
  }
  if (FLUX_UNGATED.has(base)) return true
  for (const dir of FLUX_DIRS) {
    if (pathLower.includes(dir) &&
        (base.endsWith('.yaml') || base.endsWith('.yml'))) {
      return true
    }
  }
  if (base.startsWith('flux-') &&
      (base.endsWith('.yaml') || base.endsWith('.yml'))) {
    return true
  }
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — BUILDKITE_CIRCLECI_DRIFT
// ---------------------------------------------------------------------------

function isBuildkiteCiFile(pathLower: string, base: string): boolean {
  // .buildkite/ directory is globally unambiguous
  if (pathLower.includes('.buildkite/') &&
      (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json'))) {
    return true
  }
  // .circleci/ directory is globally unambiguous
  if (pathLower.includes('.circleci/') &&
      (base.endsWith('.yaml') || base.endsWith('.yml'))) {
    return true
  }
  // buildkite- prefix
  if (base.startsWith('buildkite-') &&
      (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json'))) {
    return true
  }
  return false
}

// ---------------------------------------------------------------------------
// TEKTON_PIPELINE_DRIFT — user contribution point
// ---------------------------------------------------------------------------

/**
 * isTektonPipelineConfig — determines whether a file path is a Tekton CI/CD
 * pipeline security configuration that is NOT already covered by:
 *   - WS-63 (containerHardeningDrift): k8s RBAC, NetworkPolicy, PodSecurity —
 *     the k8s control-plane security layer. Files in k8s manifest directories
 *     (k8s/, manifests/, helm/) are treated as k8s resources regardless of their
 *     Tekton content, since WS-63 owns the k8s manifest security layer.
 *
 * Target files: Tekton Task (what CI steps run), Pipeline (how tasks chain),
 * TaskRun (CI job execution), PipelineRun, ClusterTask (cluster-scoped task),
 * and StepAction (reusable step) CRD files — when these live in dedicated Tekton
 * pipeline directories rather than bundled k8s manifest sets.
 *
 * Core ambiguity: "task.yaml" and "pipeline.yaml" can be:
 *   (a) A Tekton Task/Pipeline CRD — target for WS-73 if in tekton/ dir
 *   (b) A generic k8s resource or application config — not for WS-73
 *   (c) A task runner config (Taskfile) — not for WS-73
 *
 * Design trade-offs to consider:
 *
 *   (a) k8s/manifest directory exclusion: files inside k8s/, kubernetes/,
 *       manifests/, helm/, charts/ are considered part of the k8s manifest
 *       deployment bundle. Even Tekton CRDs committed there are treated as
 *       k8s deployment artifacts, not active CI job definitions.
 *
 *   (b) Globally unambiguous Tekton CRD names: clustertask.yaml, taskrun.yaml,
 *       pipelinerun.yaml, stepaction.yaml are Tekton-specific names that can be
 *       flagged outside tekton/ dirs (outside k8s manifest dirs). These are
 *       essentially never used for non-Tekton purposes.
 *
 *   (c) Ambiguous names gated on directory: task.yaml and pipeline.yaml are
 *       too generic to flag globally. These are only flagged when the file lives
 *       in a tekton/, .tekton/, or tekton-pipelines/ directory, which makes the
 *       Tekton context unambiguous.
 *
 *   (d) tekton- prefix: files like tekton-task.yaml, tekton-pipeline.yaml,
 *       tekton-ci.yaml are clearly Tekton-related outside any directory context.
 *
 * Implement to return true for Tekton pipeline security config files outside k8s
 * manifest directories and false for generic task/pipeline configs already covered
 * by WS-63 or unrelated to CI/CD pipeline security.
 */
export function isTektonPipelineConfig(pathLower: string): boolean {
  const base = pathLower.split('/').at(-1) ?? pathLower
  const isYaml = base.endsWith('.yaml') || base.endsWith('.yml')

  // k8s manifest dirs — files here are deployment artifacts (WS-63 territory)
  const K8S_DIRS = ['k8s/', 'kubernetes/', 'manifests/', 'helm/', 'charts/', 'kustomize/']
  for (const dir of K8S_DIRS) {
    if (pathLower.includes(dir)) return false
  }

  // Globally unambiguous Tekton CRD basenames (outside k8s dirs)
  const TEKTON_UNGATED = new Set([
    'clustertask.yaml', 'clustertask.yml',
    'taskrun.yaml', 'taskrun.yml',
    'pipelinerun.yaml', 'pipelinerun.yml',
    'clustertaskrun.yaml', 'clustertaskrun.yml',
    'stepaction.yaml', 'stepaction.yml',  // Tekton StepAction CRD (v0.54+)
    'clusterstepaction.yaml', 'clusterstepaction.yml',
  ])
  if (TEKTON_UNGATED.has(base)) return true

  // Tekton directory context — any YAML in dedicated Tekton dirs
  const TEKTON_DIRS = [
    'tekton/', '.tekton/', 'tekton-pipelines/', 'tekton-tasks/',
    'tekton-config/', 'tekton-resources/', 'ci/tekton/',
  ]
  for (const dir of TEKTON_DIRS) {
    if (pathLower.includes(dir) && isYaml) return true
  }

  // tekton- prefix: tekton-task.yaml, tekton-pipeline.yaml, etc.
  if (base.startsWith('tekton-') && isYaml) return true

  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — PIPELINE_ARTIFACT_SIGNING_DRIFT
// ---------------------------------------------------------------------------

const SLSA_UNGATED = new Set([
  '.slsa-goreleaser.yml', '.slsa-goreleaser.yaml',
  'slsa-goreleaser.yml', 'slsa-goreleaser.yaml',
  'slsa-policy.yaml', 'slsa-policy.yml', 'slsa-policy.json',
  'slsa-verifier.yaml', 'slsa-verifier.yml',
  'slsa-builder.yaml', 'slsa-builder.yml',
  'slsa-generator.yaml', 'slsa-generator.yml',
])

const SLSA_DIRS = ['slsa/', 'slsa-config/', 'supply-chain/', 'signing/', 'attestation/']

function isPipelineSigningConfig(pathLower: string, base: string): boolean {
  if (SLSA_UNGATED.has(base)) return true
  // 'provenance.*' requires a SLSA/signing directory to avoid generic false positives
  if ((base === 'provenance.yaml' || base === 'provenance.yml' || base === 'provenance.json') &&
      SLSA_DIRS.some((d) => pathLower.includes(d))) {
    return true
  }
  for (const dir of SLSA_DIRS) {
    if (pathLower.includes(dir) &&
        (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json'))) {
      return true
    }
  }
  if (base.startsWith('slsa-') &&
      (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json'))) {
    return true
  }
  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

type CicdPipelineSecurityRule = {
  id: CicdPipelineSecurityRuleId
  severity: CicdPipelineSecuritySeverity
  description: string
  recommendation: string
  matches: (pathLower: string, base: string, ext: string) => boolean
}

export const CICD_PIPELINE_SECURITY_RULES: readonly CicdPipelineSecurityRule[] = [
  {
    id: 'GITHUB_ACTIONS_WORKFLOW_DRIFT',
    severity: 'high',
    description: 'GitHub Actions workflow or custom action definition files were modified. Workflow files define job-level `permissions:` scopes, which secrets are exposed to steps, which runners execute jobs, and which third-party actions are invoked — changes can add `pull_request_target` triggers (write-permission on fork PRs), broaden `permissions: write-all`, or invoke unverified external actions that exfiltrate secrets.',
    recommendation: 'Verify that no `pull_request_target` triggers were added without explicit permission restriction, that `permissions:` were not broadened beyond the minimum required, and that any newly referenced third-party actions are pinned by full commit SHA (not a mutable tag like `@v3`). Workflow changes that add external action references should be reviewed by the security team before merging.',
    matches: (p, b) => isGithubActionsFile(p, b),
  },
  {
    id: 'JENKINS_PIPELINE_SECURITY_DRIFT',
    severity: 'high',
    description: 'Jenkinsfile or Jenkins shared-library pipeline configuration files were modified. Jenkinsfile changes control what code runs in the CI/CD environment, which credentials are accessed via `withCredentials()`, and which build steps execute — malicious or accidental changes can expose credentials to untrusted steps, disable security checks, or execute arbitrary commands with build agent permissions.',
    recommendation: 'Verify that no new `withCredentials()` blocks expose secrets beyond what is required, that `sh`/`bat` steps were not changed to run unsafe operations, and that shared library imports reference trusted versions. Jenkinsfile changes should be reviewed with the same rigour as security-critical source code changes.',
    matches: (p, b) => isJenkinsPipelineFile(p, b),
  },
  {
    id: 'GITLAB_CI_SECURITY_DRIFT',
    severity: 'high',
    description: 'GitLab CI/CD pipeline configuration files were modified. Pipeline config changes control which jobs run, what protected CI/CD variables and secrets they access, which runners execute them, and which environments they deploy to — changes can escalate job permissions or expose protected variables to jobs running on non-protected branches.',
    recommendation: 'Verify that `rules:` or `only:` conditions still restrict sensitive jobs to protected branches, that newly added `variables:` do not expose protected CI/CD variables to unsafe jobs, and that `image:` references are pinned to trusted images. Changes to environment-scoped deployments should be reviewed by the security team.',
    matches: (p, b) => isGitlabCiFile(p, b),
  },
  {
    id: 'ARGOCD_APP_SECURITY_DRIFT',
    severity: 'medium',
    description: 'ArgoCD Application, AppProject, or ApplicationSet configuration files were modified. AppProject changes control which Git repositories ArgoCD can sync from, which cluster namespaces it can deploy to, and which resource kinds it can create — changes can permit unauthorized repositories to deploy to production clusters or expand cluster-scoped resource creation privileges.',
    recommendation: 'Verify that AppProject `sourceRepos` was not broadened to allow any repository (`*`), that `destinations` still restrict deployment to the intended namespaces and clusters, and that `clusterResourceWhitelist` was not expanded to allow additional cluster-scoped resource kinds. ArgoCD project changes should be reviewed by the platform security team before merging.',
    matches: (p, b) => isArgocdAppFile(p, b),
  },
  {
    id: 'FLUX_GITOPS_SECURITY_DRIFT',
    severity: 'medium',
    description: 'FluxCD Kustomization, HelmRelease, GitRepository, or ImagePolicy configuration files were modified. FluxCD resources control which Git paths and Helm charts are reconciled to which clusters, which container image tags are approved for automatic promotion, and what service account the reconciler uses — changes can redirect GitOps sync to malicious sources or enable auto-deployment of unverified container images.',
    recommendation: 'Verify that GitRepository URLs still point to trusted sources, that Kustomization `spec.path` values were not redirected to untrusted directories, that ImagePolicy tag filters were not broadened to allow any tag (`*`), and that HelmRelease `chart.spec.sourceRef` still references a trusted repository. Flux resource changes affecting production clusters should be reviewed before merging.',
    matches: (p, b) => isFluxGitOpsFile(p, b),
  },
  {
    id: 'BUILDKITE_CIRCLECI_DRIFT',
    severity: 'medium',
    description: 'Buildkite or CircleCI pipeline configuration files were modified. Pipeline config changes control which CI contexts (secret sets) are accessible to jobs, required approval steps before deployment, job execution environments, and deployment targets — changes can expose secrets to additional jobs, bypass required approvals, or add unauthorized deployment steps.',
    recommendation: 'Confirm that context restrictions were not removed to allow broader access to secret sets, that no new deployment steps were added without corresponding approval gates, and that pipeline configuration changes follow the principle of least privilege for secret access. Pipeline config changes should be reviewed by the security team before merging.',
    matches: (p, b) => isBuildkiteCiFile(p, b),
  },
  {
    id: 'TEKTON_PIPELINE_DRIFT',
    severity: 'medium',
    description: 'Tekton Task, Pipeline, TaskRun, or ClusterTask configuration files were modified. Tekton resources define CI/CD job steps, which workspaces (and therefore secrets) they access, which container images they run, and what parameters they accept — changes can introduce malicious build steps, expand the scope of secrets accessible to CI jobs, or modify cluster-scoped tasks that affect all tenants.',
    recommendation: 'Verify that new Pipeline or Task steps do not access secrets beyond what is required, that image references are pinned to trusted registries and digests, and that ClusterTask changes (which are cluster-scoped) were reviewed by the platform security team. Tekton resource changes should be reviewed with the same care as source code changes that affect the build environment.',
    matches: (p) => isTektonPipelineConfig(p),
  },
  {
    id: 'PIPELINE_ARTIFACT_SIGNING_DRIFT',
    severity: 'low',
    description: 'SLSA provenance or artifact signing pipeline configuration files were modified. SLSA and supply-chain signing configs define how build artifacts are attested and signed before distribution — changes can disable provenance generation, weaken signing policies, lower the SLSA level of releases, or allow unsigned artifacts through the CI pipeline.',
    recommendation: 'Confirm that SLSA provenance generation steps were not removed from release workflows, that signing key references still point to approved keys, and that any changes to attestation policy files were reviewed by the security team. Supply-chain signing configuration should be treated as security-critical: changes require explicit approval from the release security owner.',
    matches: (p, b) => isPipelineSigningConfig(p, b),
  },
]

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

function penaltyFor(sev: CicdPipelineSecuritySeverity, count: number): number {
  switch (sev) {
    case 'high':   return Math.min(count * HIGH_PENALTY_PER, HIGH_PENALTY_CAP)
    case 'medium': return Math.min(count * MED_PENALTY_PER,  MED_PENALTY_CAP)
    case 'low':    return Math.min(count * LOW_PENALTY_PER,  LOW_PENALTY_CAP)
  }
}

function toRiskLevel(score: number): CicdPipelineSecurityRiskLevel {
  if (score === 0)  return 'none'
  if (score < 20)  return 'low'
  if (score < 45)  return 'medium'
  if (score < 70)  return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Main scanner
// ---------------------------------------------------------------------------

export function scanCicdPipelineSecurityDrift(filePaths: string[]): CicdPipelineSecurityDriftResult {
  if (filePaths.length === 0) return emptyResult()

  const paths = filePaths
    .map((p) => p.replace(/\\/g, '/'))
    .filter((p) => {
      const lower = p.toLowerCase()
      return !VENDOR_DIRS.some((d) => lower.includes(d))
    })

  if (paths.length === 0) return emptyResult()

  const accumulated = new Map<CicdPipelineSecurityRuleId, { firstPath: string; count: number }>()

  for (const path of paths) {
    const pathLower = path.toLowerCase()
    const base = pathLower.split('/').at(-1) ?? pathLower
    const ext  = base.includes('.') ? `.${base.split('.').at(-1)}` : ''

    for (const rule of CICD_PIPELINE_SECURITY_RULES) {
      if (rule.matches(pathLower, base, ext)) {
        const existing = accumulated.get(rule.id)
        if (existing) {
          existing.count += 1
        } else {
          accumulated.set(rule.id, { firstPath: path, count: 1 })
        }
      }
    }
  }

  if (accumulated.size === 0) return emptyResult()

  const SEVERITY_ORDER: Record<CicdPipelineSecuritySeverity, number> = { high: 0, medium: 1, low: 2 }
  const findings: CicdPipelineSecurityDriftFinding[] = []

  for (const rule of CICD_PIPELINE_SECURITY_RULES) {
    const match = accumulated.get(rule.id)
    if (!match) continue
    findings.push({
      ruleId:         rule.id,
      severity:       rule.severity,
      matchedPath:    match.firstPath,
      matchCount:     match.count,
      description:    rule.description,
      recommendation: rule.recommendation,
    })
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])

  const highCount   = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount    = findings.filter((f) => f.severity === 'low').length

  let rawScore = 0
  for (const finding of findings) {
    rawScore += penaltyFor(finding.severity, finding.matchCount)
  }
  const riskScore = Math.min(rawScore, 100)
  const riskLevel = toRiskLevel(riskScore)

  const summary = buildSummary(riskLevel, highCount, mediumCount, lowCount, findings)

  return { riskScore, riskLevel, totalFindings: findings.length, highCount, mediumCount, lowCount, findings, summary }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function emptyResult(): CicdPipelineSecurityDriftResult {
  return {
    riskScore: 0, riskLevel: 'none',
    totalFindings: 0, highCount: 0, mediumCount: 0, lowCount: 0,
    findings: [], summary: 'No CI/CD pipeline security configuration drift detected.',
  }
}

function buildSummary(
  level: CicdPipelineSecurityRiskLevel,
  high: number,
  medium: number,
  low: number,
  findings: CicdPipelineSecurityDriftFinding[],
): string {
  if (level === 'none') return 'No CI/CD pipeline security configuration drift detected.'

  const parts: string[] = []
  if (high > 0)   parts.push(`${high} high`)
  if (medium > 0) parts.push(`${medium} medium`)
  if (low > 0)    parts.push(`${low} low`)

  const topRule  = findings[0]
  const topLabel = topRule ? topRule.ruleId.replace(/_/g, ' ').toLowerCase() : 'pipeline security config'

  return `CI/CD pipeline security drift detected (${parts.join(', ')} finding${findings.length !== 1 ? 's' : ''}). Most prominent: ${topLabel}. Review changes to ensure pipeline authorization, secret access, and deployment controls remain intact.`
}
