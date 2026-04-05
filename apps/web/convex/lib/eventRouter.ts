type WorkflowPriority = 'critical' | 'high' | 'medium' | 'low'

export type WorkflowTaskTemplate = {
  agent: string
  stage: string
  title: string
  detail: string
  order: number
}

type RoutedWorkflow = {
  dedupeKey: string
  kind: string
  source: string
  workflowType: string
  priority: WorkflowPriority
  eventSummary: string
  workflowSummary: string
  currentStage: string
  tasks: WorkflowTaskTemplate[]
}

const dependencyMatchers = [
  /(^|\/)package\.json$/i,
  /(^|\/)package-lock\.json$/i,
  /(^|\/)bun\.lock$/i,
  /(^|\/)bun\.lockb$/i,
  /(^|\/)pnpm-lock\.yaml$/i,
  /(^|\/)yarn\.lock$/i,
  /(^|\/)requirements(\.txt|\/.+)?$/i,
  /(^|\/)poetry\.lock$/i,
  /(^|\/)pyproject\.toml$/i,
  /(^|\/)pdm\.lock$/i,
  /(^|\/)Pipfile(\.lock)?$/i,
  /(^|\/)go\.mod$/i,
  /(^|\/)go\.sum$/i,
  /(^|\/)Cargo\.(toml|lock)$/i,
  /(^|\/)pom\.xml$/i,
  /(^|\/)build\.gradle(\.kts)?$/i,
  /(^|\/)gradle\.lockfile$/i,
  /(^|\/)Gemfile(\.lock)?$/i,
  /(^|\/)composer\.(json|lock)$/i,
  /(^|\/)Dockerfile/i,
]

const ciMatchers = [
  /(^|\/)\.github\/workflows\/.+/i,
  /(^|\/)\.gitlab-ci\.yml$/i,
  /(^|\/)docker-compose\.(ya?ml)$/i,
  /(^|\/)k8s\/.+/i,
  /(^|\/)helm\/.+/i,
  /(^|\/)terraform\/.+/i,
  /(^|\/)infra\/.+/i,
]

const docsMatchers = [
  /\.mdx?$/i,
  /(^|\/)docs\/.+/i,
  /(^|\/)README/i,
  /(^|\/)CHANGELOG/i,
]

const securityMatchers = [
  /(^|\/)auth\//i,
  /(^|\/)security\//i,
  /(^|\/)polic(y|ies)\//i,
  /(^|\/)secrets?\//i,
  /(jwt|oauth|saml|rbac|permission|credential|token)/i,
]

function matchesAny(path: string, patterns: RegExp[]) {
  return patterns.some((pattern) => pattern.test(path))
}

function createTask(
  order: number,
  task: Omit<WorkflowTaskTemplate, 'order'>,
): WorkflowTaskTemplate {
  return {
    ...task,
    order,
  }
}

function classifyChangedFiles(changedFiles: string[]) {
  const uniqueFiles = [...new Set(changedFiles)]
  const dependencyFiles = uniqueFiles.filter((file) =>
    matchesAny(file, dependencyMatchers),
  )
  const ciFiles = uniqueFiles.filter((file) => matchesAny(file, ciMatchers))
  const securityFiles = uniqueFiles.filter((file) =>
    matchesAny(file, securityMatchers),
  )
  const docFiles = uniqueFiles.filter((file) => matchesAny(file, docsMatchers))
  const codeFiles = uniqueFiles.filter(
    (file) =>
      !dependencyFiles.includes(file) &&
      !ciFiles.includes(file) &&
      !docFiles.includes(file),
  )

  return {
    uniqueFiles,
    dependencyFiles,
    ciFiles,
    securityFiles,
    docFiles,
    codeFiles,
    docsOnly:
      uniqueFiles.length > 0 &&
      uniqueFiles.every((file) => docFiles.includes(file)),
  }
}

export function buildGithubPushWorkflow(args: {
  tenantSlug: string
  repositoryFullName: string
  branch: string
  commitSha: string
  changedFiles: string[]
}): RoutedWorkflow {
  const classification = classifyChangedFiles(args.changedFiles)
  const tasks: WorkflowTaskTemplate[] = []

  tasks.push(
    createTask(tasks.length, {
      agent: 'event_router_agent',
      stage: 'intake',
      title: 'Normalize GitHub push context',
      detail: `Map ${classification.uniqueFiles.length} changed files on ${args.branch} into the Sentinel workflow graph.`,
    }),
  )

  if (classification.dependencyFiles.length > 0) {
    tasks.push(
      createTask(tasks.length, {
        agent: 'sbom_registry_agent',
        stage: 'inventory',
        title: 'Reconcile dependency and image drift',
        detail: `Inspect ${classification.dependencyFiles.length} manifest, lockfile, or container changes for a fresh SBOM snapshot.`,
      }),
    )
  }

  if (classification.codeFiles.length > 0 || classification.securityFiles.length > 0) {
    tasks.push(
      createTask(tasks.length, {
        agent: 'semantic_fingerprint_agent',
        stage: 'analysis',
        title: 'Run semantic fingerprinting on changed code',
        detail: `Prepare behavioral matching across ${classification.codeFiles.length} code paths and ${classification.securityFiles.length} security-sensitive files.`,
      }),
    )
  }

  if (classification.ciFiles.length > 0 || classification.securityFiles.length > 0) {
    tasks.push(
      createTask(tasks.length, {
        agent: 'gate_policy_agent',
        stage: 'policy',
        title: 'Evaluate pipeline and policy impact',
        detail: `Review ${classification.ciFiles.length} CI or infrastructure changes and ${classification.securityFiles.length} sensitive paths for merge-gate implications.`,
      }),
    )
  }

  if (classification.docsOnly || tasks.length === 1) {
    tasks.push(
      createTask(tasks.length, {
        agent: 'change_observer_agent',
        stage: 'observation',
        title: 'Capture low-risk change summary',
        detail:
          'Persist a lightweight audit trail so documentation-only or shallow changes still produce an observable workflow run.',
      }),
    )
  }

  const priority: WorkflowPriority = classification.securityFiles.length > 0
    ? 'critical'
    : classification.dependencyFiles.length > 0 || classification.ciFiles.length > 0
      ? 'high'
      : classification.docsOnly
        ? 'low'
        : 'medium'

  return {
    dedupeKey: [
      'github',
      args.tenantSlug,
      args.repositoryFullName,
      args.branch,
      args.commitSha,
    ].join(':'),
    kind: 'push',
    source: 'github',
    workflowType: 'full_scan',
    priority,
    eventSummary: `GitHub push on ${args.branch} touched ${classification.uniqueFiles.length} files and routed ${tasks.length} workflow stages.`,
    workflowSummary: `Queued ${tasks.length}-stage full scan for commit ${args.commitSha}.`,
    currentStage: tasks[0]?.stage ?? 'intake',
    tasks,
  }
}

export function buildBreachDisclosureWorkflow(args: {
  packageName: string
  sourceName: string
  sourceRef: string
  severity: WorkflowPriority | 'informational'
}): RoutedWorkflow {
  const tasks: WorkflowTaskTemplate[] = [
    createTask(0, {
      agent: 'breach_intel_agent',
      stage: 'disclosure',
      title: 'Normalize external disclosure',
      detail: `Extract package metadata, version ranges, and exploit signals from ${args.sourceName}.`,
    }),
    createTask(1, {
      agent: 'sbom_registry_agent',
      stage: 'matching',
      title: 'Match disclosure against tracked inventory',
      detail: `Locate ${args.packageName} across direct, transitive, and container dependency layers.`,
    }),
    createTask(2, {
      agent: 'exploit_validation_agent',
      stage: 'validation',
      title: 'Prepare exploit-first validation',
      detail:
        'Queue sandbox-ready evidence collection before any blocking or remediation decision is finalized.',
    }),
    createTask(3, {
      agent: 'gate_policy_agent',
      stage: 'decision',
      title: 'Recompute gate posture',
      detail:
        'Update merge or deploy gates once validation evidence and dependency exposure are known.',
    }),
  ]

  const priority: WorkflowPriority =
    args.severity === 'critical'
      ? 'critical'
      : args.severity === 'high'
        ? 'high'
        : 'medium'

  return {
    dedupeKey: ['disclosure', args.packageName, args.sourceRef].join(':'),
    kind: 'breach_disclosure',
    source: args.sourceName,
    workflowType: 'breach_response',
    priority,
    eventSummary: `External disclosure for ${args.packageName} was normalized from ${args.sourceName} and queued for exposure matching.`,
    workflowSummary: `Queued breach response for ${args.packageName} with ${tasks.length} auditable stages.`,
    currentStage: tasks[0].stage,
    tasks,
  }
}
