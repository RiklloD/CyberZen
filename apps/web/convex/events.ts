import { ConvexError, v } from 'convex/values'
import {
  internalMutation,
  mutation,
  type MutationCtx,
} from './_generated/server'
import type { Doc, Id } from './_generated/dataModel'
import { internal } from './_generated/api'
import {
  buildBreachDisclosureWorkflow,
  buildGithubPushWorkflow,
  type WorkflowTaskTemplate,
} from './lib/eventRouter'
import {
  buildDisclosureMatchSummary,
  businessImpactScoreForSeverity,
  matchDisclosureToInventory,
  normalizeEcosystem,
  normalizePackageName,
  uniqueStrings,
  type BreachMatchStatus,
  type InventoryComponentForBreachMatch,
} from './lib/breachMatching'
import {
  normalizeGithubSecurityAdvisory,
  normalizeOsvAdvisory,
  type NormalizedDisclosure,
} from './lib/breachFeeds'
import { assessExploitValidation } from './lib/exploitValidation'
import { matchSemanticFingerprints } from './lib/semanticFingerprint'
import { runGateEvaluationForWorkflow } from './gateEnforcement'

const lifecycleStatus = v.union(
  v.literal('queued'),
  v.literal('running'),
  v.literal('completed'),
  v.literal('failed'),
)

const severity = v.union(
  v.literal('critical'),
  v.literal('high'),
  v.literal('medium'),
  v.literal('low'),
  v.literal('informational'),
)

const validationOutcome = v.union(
  v.literal('validated'),
  v.literal('likely_exploitable'),
  v.literal('unexploitable'),
)

type RepositoryContext = {
  tenant: Doc<'tenants'>
  repository: Doc<'repositories'>
}

type GithubPushIngestInput = {
  branch: string
  commitSha: string
  changedFiles: string[]
  /** Commit messages from the push payload (WS-55). Optional — callers may omit. */
  commitMessages?: string[]
}

type SnapshotInventory = {
  latestSnapshot: Doc<'sbomSnapshots'> | null
  latestComponents: Doc<'sbomComponents'>[]
}

type CanonicalDisclosureInput = NormalizedDisclosure

async function insertWorkflowTasks(
  ctx: MutationCtx,
  tenantId: Id<'tenants'>,
  workflowRunId: Id<'workflowRuns'>,
  tasks: WorkflowTaskTemplate[],
) {
  for (const task of tasks) {
    await ctx.db.insert('workflowTasks', {
      tenantId,
      workflowRunId,
      status: 'queued',
      startedAt: undefined,
      completedAt: undefined,
      ...task,
    })
  }
}

async function updateWorkflowTask(
  ctx: MutationCtx,
  workflowRunId: Id<'workflowRuns'>,
  taskOrder: number,
  status: Doc<'workflowTasks'>['status'],
  detail?: string,
) {
  const task = await ctx.db
    .query('workflowTasks')
    .withIndex('by_workflow_run_and_order', (q) =>
      q.eq('workflowRunId', workflowRunId).eq('order', taskOrder),
    )
    .unique()

  if (!task) {
    throw new ConvexError('Workflow task not found')
  }

  const now = Date.now()
  await ctx.db.patch('workflowTasks', task._id, {
    status,
    detail: detail ?? task.detail,
    startedAt:
      status === 'running' || status === 'completed'
        ? task.startedAt ?? now
        : undefined,
    completedAt: status === 'completed' || status === 'failed' ? now : undefined,
  })

  return task
}

function buildWorkflowSummary(
  workflowType: string,
  nextStatus: Doc<'workflowRuns'>['status'],
  nextTask: Doc<'workflowTasks'> | null,
  failedTask: Doc<'workflowTasks'> | null,
  completedTaskCount: number,
  totalTaskCount: number,
) {
  const workflowLabel = workflowType.replace(/_/g, ' ')

  if (failedTask) {
    return `${failedTask.title} failed during the ${workflowLabel} workflow.`
  }

  if (nextStatus === 'completed') {
    return `Completed ${workflowLabel} with ${completedTaskCount}/${totalTaskCount} stages finished.`
  }

  if (nextTask) {
    return `Stage ${completedTaskCount + 1}/${totalTaskCount}: ${nextTask.title}.`
  }

  return `Queued ${workflowLabel} with ${totalTaskCount} planned stages.`
}

async function getRepositoryContext(
  ctx: MutationCtx,
  tenantSlug: string,
  repositoryFullName: string,
): Promise<RepositoryContext> {
  const tenant = await ctx.db
    .query('tenants')
    .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
    .unique()

  if (!tenant) {
    throw new ConvexError('Tenant not found')
  }

  const repository = await ctx.db
    .query('repositories')
    .withIndex('by_tenant_and_full_name', (q) =>
      q.eq('tenantId', tenant._id).eq('fullName', repositoryFullName),
    )
    .unique()

  if (!repository) {
    throw new ConvexError('Repository not found')
  }

  return {
    tenant,
    repository,
  }
}

async function getRepositoryContextByProviderAndFullName(
  ctx: MutationCtx,
  provider: Doc<'repositories'>['provider'],
  repositoryFullName: string,
): Promise<RepositoryContext> {
  const repository = await ctx.db
    .query('repositories')
    .withIndex('by_provider_and_full_name', (q) =>
      q.eq('provider', provider).eq('fullName', repositoryFullName),
    )
    .unique()

  if (!repository) {
    throw new ConvexError('Repository not found')
  }

  const tenant = await ctx.db.get(repository.tenantId)

  if (!tenant) {
    throw new ConvexError('Tenant not found for repository')
  }

  return {
    tenant,
    repository,
  }
}

async function loadLatestSnapshotInventory(
  ctx: MutationCtx,
  repositoryId: Id<'repositories'>,
): Promise<SnapshotInventory> {
  const latestSnapshot = await ctx.db
    .query('sbomSnapshots')
    .withIndex('by_repository_and_captured_at', (q) =>
      q.eq('repositoryId', repositoryId),
    )
    .order('desc')
    .first()

  if (!latestSnapshot) {
    return {
      latestSnapshot: null,
      latestComponents: [],
    }
  }

  const latestComponents = await ctx.db
    .query('sbomComponents')
    .withIndex('by_snapshot', (q) => q.eq('snapshotId', latestSnapshot._id))
    .collect()

  return {
    latestSnapshot,
    latestComponents,
  }
}

async function ingestGithubPushForRepository(
  ctx: MutationCtx,
  repositoryContext: RepositoryContext,
  args: GithubPushIngestInput,
) {
  const { tenant, repository } = repositoryContext
  const routedWorkflow = buildGithubPushWorkflow({
    tenantSlug: tenant.slug,
    repositoryFullName: repository.fullName,
    branch: args.branch,
    commitSha: args.commitSha,
    changedFiles: args.changedFiles,
  })
  const existingEvent = await ctx.db
    .query('ingestionEvents')
    .withIndex('by_dedupe_key', (q) =>
      q.eq('dedupeKey', routedWorkflow.dedupeKey),
    )
    .unique()

  if (existingEvent) {
    const existingWorkflowRun = await ctx.db
      .query('workflowRuns')
      .withIndex('by_event', (q) => q.eq('eventId', existingEvent._id))
      .unique()

    if (!existingWorkflowRun) {
      throw new ConvexError('Existing workflow run missing for deduped event')
    }

    return {
      eventId: existingEvent._id,
      workflowRunId: existingWorkflowRun._id,
      deduped: true,
    }
  }

  const now = Date.now()
  const eventId = await ctx.db.insert('ingestionEvents', {
    tenantId: tenant._id,
    repositoryId: repository._id,
    dedupeKey: routedWorkflow.dedupeKey,
    kind: routedWorkflow.kind,
    source: routedWorkflow.source,
    workflowType: routedWorkflow.workflowType,
    status: 'queued',
    externalRef: `${repository.provider}:${args.commitSha}`,
    branch: args.branch,
    commitSha: args.commitSha,
    changedFiles: args.changedFiles,
    summary: routedWorkflow.eventSummary,
    receivedAt: now,
  })

  const workflowRunId = await ctx.db.insert('workflowRuns', {
    tenantId: tenant._id,
    repositoryId: repository._id,
    eventId,
    workflowType: routedWorkflow.workflowType,
    status: 'queued',
    priority: routedWorkflow.priority,
    currentStage: routedWorkflow.currentStage,
    summary: routedWorkflow.workflowSummary,
    totalTaskCount: routedWorkflow.tasks.length,
    completedTaskCount: 0,
    startedAt: now,
    completedAt: undefined,
  })

  await insertWorkflowTasks(
    ctx,
    tenant._id,
    workflowRunId,
    routedWorkflow.tasks,
  )

  await ctx.db.patch('repositories', repository._id, {
    latestCommitSha: args.commitSha,
    lastScannedAt: now,
  })

  // Fire-and-forget: secret detection scan — scan changed file paths and the
  // commit SHA as content items. Runs immediately on every new push. File
  // paths can expose secrets embedded in directory/file names, and are always
  // available in the webhook payload without an additional GitHub API call.
  try {
    const contentItems: Array<{ content: string; filename?: string }> = []
    if (args.changedFiles && args.changedFiles.length > 0) {
      // Scan as a combined string to catch cross-line patterns in paths
      contentItems.push({ content: args.changedFiles.join('\n') })
    }
    if (contentItems.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.secretDetectionIntel.recordSecretScan,
        {
          tenantId: tenant._id,
          repositoryId: repository._id,
          branch: args.branch,
          commitSha: args.commitSha,
          contentItems,
        },
      )
    }
  } catch (e) {
    console.error('[secret-detection] failed to schedule for repository', repository._id, e)
  }

  // ── WS-33: IaC Security Scanner ──────────────────────────────────────────
  // Filters changed files to those with IaC-recognisable names and triggers
  // a misconfiguration scan. File paths are passed as content for the MVP;
  // a future integration can fetch real file bytes via the GitHub Contents API.
  try {
    const IAC_EXTENSIONS = /\.tf$|\.ya?ml$|Dockerfile(?:\.\w+)?$|\.dockerfile$|docker-compose/i
    const iacFiles = args.changedFiles?.filter((f) => IAC_EXTENSIONS.test(f)) ?? []
    if (iacFiles.length > 0) {
      await ctx.scheduler.runAfter(0, internal.iacScanIntel.recordIacScan, {
        tenantId: tenant._id,
        repositoryId: repository._id,
        branch: args.branch,
        commitSha: args.commitSha,
        fileItems: iacFiles.slice(0, 10).map((f) => ({ filename: f, content: f })),
      })
    }
  } catch (e) {
    console.error('[iac-scan] failed to schedule for repository', repository._id, e)
  }

  // ── WS-35: CI/CD Pipeline Security Scanner ───────────────────────────────
  // Detects misconfigurations in GitHub Actions, GitLab CI, CircleCI, and
  // Bitbucket Pipelines YAML files. File paths are passed as content for the
  // MVP; a future integration can fetch real bytes via the GitHub Contents API.
  try {
    const CICD_PATHS =
      /\.github[/\\]workflows[/\\].+\.ya?ml$|\.gitlab-ci\.ya?ml$|\.circleci[/\\]config\.ya?ml$|bitbucket-pipelines\.ya?ml$/i
    const cicdFiles = args.changedFiles?.filter((f) => CICD_PATHS.test(f)) ?? []
    if (cicdFiles.length > 0) {
      await ctx.scheduler.runAfter(0, internal.cicdScanIntel.recordCicdScan, {
        tenantId: tenant._id,
        repositoryId: repository._id,
        branch: args.branch,
        commitSha: args.commitSha,
        fileItems: cicdFiles.slice(0, 10).map((f) => ({ filename: f, content: f })),
      })
    }
  } catch (e) {
    console.error('[cicd-scan] failed to schedule for repository', repository._id, e)
  }

  // ── WS-37: Cryptography Weakness Detector ────────────────────────────────
  // Detects use of broken/deprecated crypto algorithms in source code files.
  // Covers Python, JS/TS, Java, Go, Ruby, C#, PHP, and Rust. File paths are
  // passed as content for the MVP; real bytes via GitHub Contents API later.
  try {
    const SOURCE_EXTENSIONS =
      /\.(py|js|ts|jsx|tsx|mjs|cjs|java|go|rb|cs|php|rs)$/i
    const sourceFiles = args.changedFiles?.filter((f) => SOURCE_EXTENSIONS.test(f)) ?? []
    if (sourceFiles.length > 0) {
      await ctx.scheduler.runAfter(0, internal.cryptoWeaknessIntel.recordCryptoWeaknessScan, {
        tenantId: tenant._id,
        repositoryId: repository._id,
        branch: args.branch,
        commitSha: args.commitSha,
        fileItems: sourceFiles.slice(0, 10).map((f) => ({ filename: f, content: f })),
      })
    }
  } catch (e) {
    console.error('[crypto-weakness] failed to schedule for repository', repository._id, e)
  }

  // ── WS-54: Sensitive File Commit Detector ────────────────────────────────
  // Scans all changed file paths in the push for accidentally committed
  // sensitive files: private keys, certificates, credential configs, .env
  // files, and debug artifacts. Path-pattern analysis only — no content fetch.
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(0, internal.sensitiveFileIntel.recordSensitiveFileScan, {
        tenantId: tenant._id,
        repositoryId: repository._id,
        commitSha: args.commitSha,
        branch: args.branch,
        filePaths: allFiles.slice(0, 200),
      })
    }
  } catch (e) {
    console.error('[sensitive-file] failed to schedule for repository', repository._id, e)
  }

  // ── WS-55: Commit Message Security Analyzer ──────────────────────────────
  // Analyses commit messages from the push for behavioral security signals:
  // control bypasses, security-fix reverts, force-merge indicators, CVE refs,
  // security TODOs, debug-mode enables, emergency deployments, and sensitive
  // data references.
  try {
    const messages = args.commitMessages ?? []
    if (messages.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.commitMessageIntel.recordCommitMessageScan,
        {
          tenantId: tenant._id,
          repositoryId: repository._id,
          commitSha: args.commitSha,
          branch: args.branch,
          commitMessages: messages,
        },
      )
    }
  } catch (e) {
    console.error('[commit-message] failed to schedule for repository', repository._id, e)
  }

  // ── WS-56: Git Supply Chain Integrity Scanner ─────────────────────────
  // Analyses changed file paths for supply-chain attack patterns: system-binary
  // PATH hijacking, submodule manipulation, binary executable smuggling, git
  // hook tampering, dependency registry overrides, gitconfig modification,
  // large blind pushes, and archive file commits.
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.gitIntegrityIntel.recordGitIntegrityScan,
        {
          tenantId: tenant._id,
          repositoryId: repository._id,
          commitSha: args.commitSha,
          branch: args.branch,
          changedFiles: allFiles.slice(0, 500),
          totalFileCount: allFiles.length,
        },
      )
    }
  } catch (e) {
    console.error('[git-integrity] failed to schedule for repository', repository._id, e)
  }

  // ── WS-57: Security Hotspot Change Detector ───────────────────────────
  // Analyses changed file paths for modifications to security-critical code
  // areas: authentication handlers, cryptographic primitives, payment
  // processing, administration endpoints, PII handlers, and security
  // middleware. One finding per triggered rule (deduplicated by rule).
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.highRiskChangeIntel.recordHighRiskChangeScan,
        {
          tenantId: tenant._id,
          repositoryId: repository._id,
          commitSha: args.commitSha,
          branch: args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[high-risk-change] failed to schedule for repository', repository._id, e)
  }

  // ── WS-101: AI/ML Dependency Security Drift ─────────────────────────────────
  // Analyses changed file paths for modifications to AI/ML dependency security
  // configuration: LLM provider client configuration (openai.yaml, anthropic.json,
  // llm-config.yaml), vector database configuration (pinecone.yaml, weaviate.json,
  // chroma.yaml, qdrant.conf, milvus.yaml), AI orchestration framework configuration
  // (llamaindex.yaml, autogen.json, haystack.yaml, langgraph.yaml, crewai.yaml),
  // ML model training and registry configuration (model.yaml, mlflow.yaml,
  // bentoml.yaml, seldon.yaml, triton.yaml), AI gateway and proxy configuration
  // (litellm.yaml, portkey.yaml, openrouter.yaml, ai-gateway.json), embedding
  // pipeline configuration (embedding.yaml, faiss.json, embeddings.yaml), AI
  // evaluation framework configuration (ragas.yaml, trulens.json, evals.yaml),
  // and AI safety and guardrail configuration (lakera.yaml, rebuff.yaml,
  // nemo-guardrails.yaml, guardrails.yaml in ai-safety dirs).
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.secretMgmtDriftIntel.recordSecretMgmtDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
      await ctx.scheduler.runAfter(
        0,
        internal.depMgrSecurityDriftIntel.recordDepMgrSecurityDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
      await ctx.scheduler.runAfter(
        0,
        internal.aiMlSecurityDriftIntel.recordAiMlSecurityDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
      await ctx.scheduler.runAfter(
        0,
        internal.k8sAdmissionDriftIntel.recordK8sAdmissionDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
      await ctx.scheduler.runAfter(
        0,
        internal.supplyChainAttestationDriftIntel.recordSupplyChainAttestationDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[ai-ml-security-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-95: Endpoint Security & EDR Configuration Drift ────────────────────────
  // Analyses changed file paths for modifications to endpoint security and EDR
  // configuration: CrowdStrike Falcon EDR agent and prevention policy configuration
  // (falcon.cfg, crowdstrike-policy.json, falcon/ dirs), SentinelOne agent and
  // policy configuration (sentinelone.conf, s1-policy.json), Microsoft Defender for
  // Endpoint managed configuration (mdatp-managed.json, wdav-config.json,
  // defender/ dirs), EDR and antivirus exclusion lists (edr-exclusions.json,
  // av-exclusions.conf — adversary-targeted), MDM and UEM device enrollment and
  // compliance policy configuration (Jamf Pro, Microsoft Intune, SCCM —
  // .mobileconfig, intune-policy.json), Carbon Black and Sophos endpoint security
  // agent configuration (cbagent.cfg, sophos.conf), vulnerability scanner agent
  // configuration (nessus.conf, openvas.conf, qualys-cloud-agent.conf), and
  // Tanium and IBM BigFix endpoint management configuration (tanium.conf, bigfix.conf).
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.endpointSecurityDriftIntel.recordEndpointSecurityDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[endpoint-security-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-94: Network Monitoring & SNMP Security Configuration Drift ─────────────
  // Analyses changed file paths for modifications to network monitoring and SNMP
  // security configuration: SNMP daemon community strings and v3 auth (snmpd.conf,
  // snmp.conf), Nagios monitoring server and NRPE agent configuration (nagios.cfg,
  // nrpe.cfg, icinga2.conf), Zabbix server/proxy/agent configuration
  // (zabbix_server.conf, zabbix_agentd.conf), NetFlow/IPFIX/sFlow traffic analysis
  // (pmacct.conf, ntopng.conf, fastnetmon.conf), network management system and
  // device backup tool configuration (oxidized.conf, librenms/config.php), Netdata
  // streaming and health configuration (netdata.conf, stream.conf in netdata/ dirs),
  // SNMP trap daemon and translator configuration (snmptrapd.conf, snmptt.conf), and
  // network scanner/probe tool configuration (masscan.conf, nmap.conf).
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.networkMonitoringDriftIntel.recordNetworkMonitoringDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[network-monitoring-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-93: VoIP & Unified Communications Security Configuration Drift ─────────
  // Analyses changed file paths for modifications to VoIP and UC security
  // configuration: Asterisk PBX / FreePBX (sip.conf, pjsip.conf, extensions.conf,
  // manager.conf in asterisk/ dirs), Kamailio and OpenSIPS SIP proxy configuration
  // (kamailio.cfg, opensips.cfg), FreeSWITCH PBX (freeswitch.xml, switch.conf.xml,
  // vars.xml in freeswitch/ dirs), SIP trunk provider credential configuration
  // (sip-trunk.conf, sip-provider.conf, sip-credentials.conf), Jitsi Meet and
  // TURN/STUN server configuration (coturn.conf, turnserver.conf, jvb.conf), VoIP
  // gateway and ATA configuration (voip-gateway.conf, sangoma-*, audiocodes-*),
  // web conferencing server configuration (Matrix/Synapse, BigBlueButton,
  // Rocket.Chat, Mattermost), and VoIP CDR / SIP capture monitoring (Homer, SNGREP).
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.voipSecurityDriftIntel.recordVoipSecurityDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[voip-security-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-92: Virtualization & Hypervisor Security Configuration Drift ──────────
  // Analyses changed file paths for modifications to hypervisor-level and VM
  // management security configuration: VMware vSphere / ESXi / vCenter
  // configuration (vmware.conf, vsphere.conf, vcenter.conf, vpxa.cfg, vpxd.cfg),
  // KVM / QEMU / libvirt host security configuration (libvirtd.conf, libvirt.conf,
  // virtlogd.conf, qemu.conf in libvirt/ dirs), Docker daemon and containerd host
  // configuration (docker-daemon.json, daemon.json in docker/ dirs, config.toml in
  // containerd/ dirs), Proxmox VE cluster and node configuration (datacenter.cfg,
  // pve.conf, corosync.conf in proxmox/ dirs), Xen / XenServer / XCP-ng
  // configuration (xend.conf, xl.conf, xapi.conf), Hyper-V configuration
  // (hyperv-config.xml, hyperv.conf), VM remote console access configuration
  // (VNC / SPICE / QEMU display configs), and Open vSwitch / SDN configuration
  // (ovs-vswitchd.conf, ovsdb.conf).
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.virtualizationSecurityDriftIntel.recordVirtualizationSecurityDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[virtualization-security-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-91: IoT & Embedded Device Security Configuration Drift ────────────────
  // Analyses changed file paths for modifications to IoT and embedded device
  // security configuration: Balena IoT fleet configuration (balena.yml,
  // balena-compose.yml, fleet-config/), AWS IoT Greengrass configuration
  // (greengrass-config.json, gg-config.json, config.json in greengrass/ dirs),
  // firmware signing and secure-boot configuration (signing_config.json,
  // mcuboot.config.yaml, imgtool-signing.conf, esptool.cfg, bootloader-keys.json),
  // Mender OTA update configuration (mender.conf, mender-artifact.conf,
  // artifact_info), Zigbee/Z-Wave controller configuration
  // (zigbee2mqtt/configuration.yaml, zwavejs2mqtt/settings.json, zigbee-*.yaml),
  // Azure IoT Hub / DPS configuration (iothub-connection.json, dps-config.json,
  // iotedge-config.yaml), IoT device management platforms (thingsboard.yml,
  // hawkbit.yml, edgex-configuration.toml), and LoRaWAN / network gateway
  // configuration (chirpstack.toml, the-things-stack.yml, lorawan-server.toml).
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.iotEmbeddedSecurityDriftIntel.recordIotEmbeddedSecurityDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[iot-embedded-security-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-90: Wireless Network & RADIUS Authentication Security Configuration Drift ──
  // Analyses changed file paths for modifications to wireless network and
  // network-access-authentication configuration: Wi-Fi access-point daemon
  // configuration (hostapd.conf, hostapd.wpa_psk, hostapd.eap_user), WPA
  // supplicant configuration (wpa_supplicant.conf, per-interface variants),
  // FreeRADIUS server configuration (radiusd.conf, clients.conf, users,
  // huntgroups, dictionary, sites-enabled/, policy.d/, mods-enabled/), TACACS+
  // authentication server configuration (tac_plus.conf, tacacs.conf), wireless
  // controller configuration (UniFi, Aruba, WLC JSON/YAML config), RADIUS policy
  // files (proxy.conf, policy.conf, filter.conf, sql.conf, sites-available/),
  // 802.1X / EAP authentication profiles (eapol.conf, eap-* files), and
  // captive-portal configuration (nodogsplash.conf, chillispot.conf,
  // coova-chilli.conf).
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.wirelessRadiusDriftIntel.recordWirelessRadiusDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[wireless-radius-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-89: Operating System Security Hardening Configuration Drift ────────────
  // Analyses changed file paths for modifications to OS-level security hardening
  // configuration: Linux kernel security parameters (sysctl.conf, sysctl.d/),
  // OpenSSH daemon configuration (sshd_config, sshd_config.d/), sudo privilege
  // escalation policy (sudoers, sudoers.d/), GRUB2 bootloader security settings
  // (/etc/default/grub, grub.cfg), SELinux mandatory-access-control policy
  // (/etc/selinux/config, .te/.pp policy files), OS access control files
  // (hosts.allow/deny, cron.allow, at.allow, securetty), NTP/time-synchronisation
  // daemon configuration (chrony.conf, ntp.conf, timesyncd.conf — critical for
  // certificate validation and log forensics), and OS login banner/MOTD
  // (/etc/issue, /etc/issue.net, /etc/motd, motd.d/ fragments).
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.osSecurityHardeningDriftIntel.recordOsSecurityHardeningDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[os-security-hardening-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-88: DNS Security Configuration Drift ──────────────────────────────────
  // Analyses changed file paths for modifications to DNS server configuration,
  // DNS resolver settings, encrypted DNS proxy configuration, and RPKI validation
  // setup: ISC BIND named.conf authoritative/recursive DNS server configuration
  // (named.conf, named-local.conf, rndc.conf), Unbound validating DNS resolver
  // (unbound.conf), PowerDNS authoritative and Recursor (pdns.conf,
  // pdns-recursor.conf), CoreDNS Corefile and plugin config (common in
  // Kubernetes), dnsmasq DNS/DHCP forwarder (dnsmasq.conf), Pi-hole DNS-level
  // filtering (pihole.conf, ftl.conf, setupvars.conf), encrypted DNS proxy
  // configuration (dnscrypt-proxy.toml, stubby.yml), and RPKI route-origin
  // validation daemon configuration (routinator.conf, fort.conf).
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.dnsSecurityDriftIntel.recordDnsSecurityDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[dns-security-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-87: Storage & Data Security Configuration Drift ───────────────────────
  // Analyses changed file paths for modifications to storage daemon configs,
  // disk encryption settings, object storage client credentials, file integrity
  // monitoring tools, and data-loss prevention policies: NFS server exports
  // (nfs-ganesha.conf, /etc/exports-style), Samba/SMB config (smb.conf,
  // samba.conf), disk encryption (crypttab LUKS map, dm-crypt, eCryptfs),
  // object storage client credentials (AWS .aws/credentials, s3cmd .s3cfg,
  // MinIO client config.json), database backup encryption (pgbackrest.conf,
  // barman.conf, wal-g config), file integrity monitoring (AIDE aide.conf,
  // Tripwire tripwire.cfg, Samhain samhain.conf), DLP policy configuration
  // (dlp-config.yaml, data-classification.yaml), and storage audit config
  // (MinIO audit webhook config.env, storage-audit.yaml).
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.storageDataSecurityDriftIntel.recordStorageDataSecurityDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[storage-data-security-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-86: SIEM & Security Analytics Configuration Drift ─────────────────────
  // Analyses changed file paths for modifications to SIEM detection rules,
  // security analytics configurations, and threat intelligence feed settings:
  // Splunk detection configs (savedsearches.conf, alert_actions.conf,
  // correlationsearches.conf), Elastic SIEM detection rule .toml files and
  // exception lists, Microsoft Sentinel analytics rules and hunting queries
  // (analyticsrules.json/yaml), osquery configuration and fleet packs
  // (osquery.conf), SIEM detection suppression/exception rules, SOAR playbook
  // configs (xsoar-config.yaml, phantom-config.json), threat intelligence feed
  // configs (misp.conf, opencti.yaml, taxii-config.json), and SIEM log source
  // input/output configs in log-collector directories.
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.siemSecurityDriftIntel.recordSiemSecurityDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[siem-security-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-85: Backup & Disaster Recovery Security Configuration Drift ───────────
  // Analyses changed file paths for modifications to backup agent, cloud sync,
  // and disaster recovery security configuration files: rclone configuration
  // (rclone.conf stores credentials for every cloud provider), Restic backup
  // password files and repository configuration (restic-password,
  // restic-password-file), BorgBackup passphrase and borgmatic YAML configs
  // (borgpassphrase, borgmatic.yaml), generic backup-specific encryption keys
  // and passphrases in backup dirs, rsync daemon configuration and secrets file
  // (rsyncd.conf, rsyncd.secrets), Bacula Director/File/Storage daemon and
  // Amanda backup server configs, Velero/Duplicati/Duplicity cloud backup agent
  // configs (credentials-velero), and backup shell scripts in backup directories.
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.backupDrSecurityDriftIntel.recordBackupDrSecurityDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[backup-dr-security-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-84: VPN & Remote Access Security Configuration Drift ──────────────────
  // Analyses changed file paths for modifications to VPN and remote access
  // security configuration files: OpenVPN server/client configuration and TLS
  // auth key material (openvpn.conf, ta.key, .ovpn profiles), WireGuard
  // interface configs with embedded private keys (wg0.conf, wgN.conf),
  // IPsec/StrongSwan/Libreswan configuration and PSK secrets (ipsec.conf,
  // ipsec.secrets, strongswan.conf), VPN-context PKI credential material,
  // Apache Guacamole/Teleport/JumpServer remote access gateway configuration,
  // Cisco AnyConnect profiles and ASA VPN config, Pritunl/OpenConnect/pptpd/
  // xl2tpd SSL VPN servers and PPP auth secrets, and VPN client profiles
  // including NetworkManager .nmconnection files and OpenVPN CCD entries.
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.vpnRemoteAccessDriftIntel.recordVpnRemoteAccessDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[vpn-remote-access-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-83: Infrastructure Configuration Management Security Drift ────────────
  // Analyses changed file paths for modifications to configuration management
  // tool security files: Ansible configuration and vault password files
  // (ansible.cfg, vault-password-file, ansible-vault.yml), Chef workstation API
  // keys and encrypted data bag secrets (knife.rb, encrypted_data_bag_secret,
  // .chef/client.rb), Puppet master server configuration and r10k Puppetfiles
  // (puppet.conf, Puppetfile, hiera.yaml), SaltStack master/minion configuration
  // and SSH rosters (Saltfile, master.conf, roster), Ansible inventory and
  // group/host variable files, Chef Berkshelf and Policyfile cookbook dependency
  // manifests, Puppet Hiera data files (including eyaml-encrypted common/site
  // data), and Test Kitchen/Molecule CI framework configs.
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.cfgMgmtSecurityDriftIntel.recordCfgMgmtSecurityDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[cfg-mgmt-security-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-82: Package & Artifact Registry Security Configuration Drift ──────────
  // Analyses changed file paths for modifications to artifact registry and
  // package repository security configuration files: JFrog Artifactory and
  // JFrog Platform security (artifactory.system.yaml, artifactory.config.xml),
  // Sonatype Nexus Repository Manager security and storage (nexus.properties),
  // Harbor OCI container registry config (harbor.yml), Docker Distribution v2
  // auth and storage (registry-config.yaml, config.yml in registry dirs),
  // Verdaccio/Sinopia private npm registry (verdaccio.yaml), Bandersnatch/DevPI
  // Python package registry (bandersnatch.cfg, devpi-server.cfg), ChartMuseum
  // Helm chart repository (chartmuseum.yaml), and Athens Go module proxy
  // (athens.yaml, athens.toml).
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.artifactRegistryDriftIntel.recordArtifactRegistryDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[artifact-registry-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-81: ML/AI Platform Security Configuration Drift ───────────────────────
  // Analyses changed file paths for modifications to machine learning and AI
  // platform security configuration files: MLflow tracking server configs
  // (mlflow.yaml, mlflow-config.yaml), Kubeflow Pipelines and KServe manifests
  // (kfctl.yaml, kfdef.yaml, inferenceservice.yaml), Ray distributed compute
  // cluster configs (ray-cluster.yaml, anyscale-config.yaml), cloud AI platform
  // IAM configs (SageMaker, Vertex AI, Azure ML access and domain settings),
  // Feast/Tecton feature store configs (feature_store.yaml), model serving configs
  // (bentofile.yaml, torchserve.config, seldon-deployment.yaml), MLOps pipeline
  // configs (dvc.yaml, clearml.conf), and model governance artifacts (model-card.json).
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.mlAiPlatformDriftIntel.recordMlAiPlatformDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[ml-ai-platform-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-80: Data Pipeline & ETL Security Configuration Drift ──────────────────
  // Analyses changed file paths for modifications to data pipeline and ETL
  // security configuration files: Apache Airflow auth/RBAC configs (airflow.cfg,
  // webserver_config.py), Apache Spark encryption settings (spark-defaults.conf),
  // dbt database connection profiles (dbt_project.yml, profiles.yml), Apache
  // Hadoop/Hive/HBase/Flink security XMLs (hdfs-site.xml, hive-site.xml,
  // flink-conf.yaml), Trino/Presto query engine auth and TLS properties, pipeline
  // orchestration configs (Dagster, Prefect, Kedro), data quality configs (Great
  // Expectations, DataHub, Atlas), and Jupyter notebook server auth configs.
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.dataPipelineDriftIntel.recordDataPipelineDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[data-pipeline-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-79: SSO Provider & Authentication Configuration Drift ─────────────────
  // Analyses changed file paths for modifications to single-sign-on and
  // authentication provider configuration files: Keycloak realm exports and
  // client configs, SAML IdP/SP metadata, OAuth2/OIDC provider configs (Ory
  // Hydra), hosted IdP configs (Auth0, Okta, PingFederate, Azure AD), Dex /
  // Authelia / Authentik self-hosted SSO middleware, Duo/YubiKey MFA provider
  // integration configs, SCIM provisioning endpoint configs, and oauth2-proxy
  // reverse proxy authentication configurations.
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.ssoProviderDriftIntel.recordSsoProviderDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[sso-provider-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-78: Messaging & Event Streaming Security Configuration Drift ─────────
  // Analyses changed file paths for modifications to messaging broker and
  // event-streaming security configuration files: Apache Kafka security configs
  // (kafka-*.properties, JAAS, KRaft), RabbitMQ broker configs (rabbitmq.conf),
  // NATS server configs (nats-server.conf), MQTT broker configs (mosquitto.conf,
  // HiveMQ), messaging transport TLS configs (kafka-ssl, amqp-ssl), broker
  // auth/ACL policy files, Confluent Schema Registry configs, and ActiveMQ /
  // Apache Pulsar broker configs.
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.messagingSecurityDriftIntel.recordMessagingSecurityDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[messaging-security-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-77: Serverless & FaaS Security Configuration Drift ────────────────
  // Analyses changed file paths for modifications to serverless function and
  // FaaS security configuration files: Serverless Framework configs (serverless.
  // yml/yaml/ts), AWS SAM templates (samconfig.toml, template.yaml), Azure
  // Functions host and settings files (host.json, local.settings.json), Cloudflare
  // Workers Wrangler configs (wrangler.toml/json), Google Cloud Run and App Engine
  // configs (cloud-run-service.yaml, app.yaml in GCP dirs), edge deployment configs
  // (netlify.toml, fly.toml, vercel.json), serverless function IAM role/policy
  // files in lambda/ dirs, and Knative/OpenWhisk FaaS platform configs.
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.serverlessFaasDriftIntel.recordServerlessFaasDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[serverless-faas-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-76: Email Security Configuration Drift ────────────────────────────
  // Analyses changed file paths for modifications to email server and mail
  // transport security configuration files: MTA core configs (Postfix main.cf/
  // master.cf, sendmail.cf/mc, exim.conf, dovecot.conf), DKIM signing key
  // material and OpenDKIM/DMARC configs (opendkim.conf, opendmarc.conf,
  // dkim/*.private), SASL authentication for mail relay (saslauthd.conf,
  // sasl/smtpd.conf, cyrus.conf), SpamAssassin/Rspamd/Amavis anti-spam
  // configs (amavisd.conf, spamassassin/local.cf, rspamd/ overrides), SMTP/
  // IMAP/POP3 TLS configs (smtp-tls.conf, dovecot-ssl.conf), Postfix relay
  // routing and virtual domain maps (relay_domains, transport, virtual), and
  // Postfix access/header-filter maps (sender_access, header_checks).
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.emailSecurityDriftIntel.recordEmailSecurityDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[email-security-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-75: Web Server & Reverse Proxy Security Configuration Drift ───────
  // Analyses changed file paths for modifications to web server and reverse
  // proxy security configuration files: nginx.conf and virtualhost configs,
  // Apache .htaccess and httpd.conf, Traefik static config (traefik.yml/yaml/
  // toml), Caddy Caddyfile variants, Kubernetes ingress controller security
  // configs, ModSecurity/OWASP CRS WAF rules, SSL termination parameter files
  // (ssl-params.conf, dhparam.pem, options-ssl-nginx.conf), and web server
  // access control configs (.htpasswd, geo.conf, basic-auth.conf).
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.webServerSecurityDriftIntel.recordWebServerSecurityDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[web-server-security-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-74: Mobile Application Security Configuration Drift ──────────────
  // Analyses changed file paths for modifications to mobile application security
  // configuration files: iOS entitlement files and export options, Android
  // AndroidManifest.xml (excluding test source sets), signing keystores and
  // provisioning profiles, iOS Info.plist/PrivacyInfo.xcprivacy ATS and privacy
  // configs, Android ProGuard/R8 obfuscation rules, Firebase/Google services
  // configs, Universal Links and Android App Links deep link configs, and mobile
  // platform configs (Expo EAS, Ionic Capacitor, CocoaPods lockfile, xcconfig).
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.mobileAppSecurityDriftIntel.recordMobileAppSecurityDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[mobile-app-security-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-73: CI/CD Pipeline Security Configuration Drift ──────────────────
  // Analyses changed file paths for modifications to CI/CD pipeline security
  // configuration files: GitHub Actions workflow YAML files, Jenkinsfile and
  // shared-library pipeline configs, GitLab CI/CD pipeline configs, ArgoCD
  // Application/AppProject/ApplicationSet CRDs, FluxCD Kustomization/HelmRelease/
  // ImagePolicy CRDs, Buildkite/.circleci pipeline configs, Tekton Task/Pipeline
  // security configs, and SLSA provenance and artifact signing pipeline configs.
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.cicdPipelineSecurityDriftIntel.recordCicdPipelineSecurityDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[cicd-pipeline-security-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-96: Configuration Drift Aggregate Health Score ────────────────────
  // Synthesis layer: reads the latest result from all 36 drift detector tables
  // (WS-60 through WS-95) and produces a single weighted 0–100 drift posture
  // score with an A–F grade and per-category breakdown. Runs 3 s after push so
  // individual drift scans have a head start on persisting their results.
  try {
    await ctx.scheduler.runAfter(
      3000,
      internal.driftPostureIntel.recordDriftPostureScan,
      {
        tenantId:     tenant._id,
        repositoryId: repository._id,
      },
    )
  } catch (e) {
    console.error('[drift-posture] failed to schedule for repository', repository._id, e)
  }

  // ── WS-98: Zero-Day Anomaly Detection (spec §3.1.3) ──────────────────────
  // Runs alongside normal drift detection. When the semantic fingerprint scan
  // finds no strong known-vuln-class match, this heuristic detector flags
  // novel attack patterns via static file-path and code-pattern analysis.
  // addedLines are empty here (push events don't carry diff content) — signals
  // that rely on line content will be dormant until richer diff data is provided.
  try {
    const recentFindings = await ctx.db
      .query('findings')
      .withIndex('by_repository_and_status', (q) => q.eq('repositoryId', repository._id))
      .take(50)
    const recentBreachTypes = [...new Set(
      recentFindings.map((f) => f.vulnClass).filter(Boolean) as string[],
    )]
    const changedFilesForZeroDay = args.changedFiles ?? []
    const lockfileChanged = changedFilesForZeroDay.some((f) =>
      /package-lock\.json|yarn\.lock|bun\.lock|pnpm-lock\.yaml|Cargo\.lock|go\.sum|Gemfile\.lock/.test(f),
    )
    const testChanged = changedFilesForZeroDay.some((f) =>
      /[./]test[./]|\.test\.|\.spec\.|__test|__spec/.test(f),
    )
    await ctx.scheduler.runAfter(
      0,
      internal.zeroDayDetectionIntel.recordZeroDayDetection,
      {
        tenantId:     tenant._id,
        repositoryId: repository._id,
        ref:          args.commitSha,
        changedFiles: changedFilesForZeroDay.slice(0, 200),
        addedLines:   [],
        recentBreachTypes,
        hasTestChanges:     testChanged,
        hasLockfileChanges: lockfileChanged,
      },
    )
  } catch (e) {
    console.error('[zero-day-detection] failed to schedule for repository', repository._id, e)
  }

  // ── WS-99: Security Program Maturity Assessment ───────────────────────────
  // Reads all scanner outputs (SLA, supply chain, compliance, drift, red/blue,
  // attack surface, automation flags) and produces a CMMI-style 5-level
  // maturity score. Runs 13 s after push so all upstream scanners have persisted.
  try {
    await ctx.scheduler.runAfter(
      13_000,
      internal.maturityAssessmentIntel.recordMaturityAssessment,
      {
        tenantId:     tenant._id,
        repositoryId: repository._id,
      },
    )
  } catch (e) {
    console.error('[maturity-assessment] failed to schedule for repository', repository._id, e)
  }

  // ── WS-100: Business Impact Assessment ──────────────────────────────────────
  // Aggregates findings, blast-radius, attack surface, and compliance into a
  // five-dimension business risk picture (spec §3.5.4). Runs 12 s after push
  // so the attack-surface snapshot (runAfter 9 s) is ready.
  try {
    await ctx.scheduler.runAfter(
      12_000,
      internal.businessImpactIntel.recordBusinessImpact,
      {
        tenantId:     tenant._id,
        repositoryId: repository._id,
      },
    )
  } catch (e) {
    console.error('[business-impact] failed to schedule for repository', repository._id, e)
  }

  // ── WS-72: Service Mesh & Zero-Trust Network Security Configuration Drift ─
  // Analyses changed file paths for modifications to service mesh and zero-trust
  // network security configuration files: Istio PeerAuthentication/Authorization
  // Policy CRDs, Envoy static bootstrap and xDS security configs, SPIFFE/SPIRE
  // workload attestation configs, Linkerd Server/ServerAuthorization, Consul
  // service mesh intentions and ACL policies, CNI plugin-specific policies
  // (Cilium/Calico/Antrea), zero-trust access proxies (Teleport/Pomerium/
  // Cloudflare Tunnel/Tailscale ACL), and service mesh gateways/VirtualServices.
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.serviceMeshSecurityDriftIntel.recordServiceMeshSecurityDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[service-mesh-security-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-71: Observability & Security Monitoring Configuration Drift ──────
  // Analyses changed file paths for modifications to observability and security
  // monitoring configuration files: Prometheus alerting rules, Alertmanager
  // routing/silences/inhibitions, log collection pipeline configs (Fluentd/
  // Logstash/Vector/Filebeat), OpenTelemetry collector security configs,
  // Grafana auth and alert channel configs, CloudWatch alarm configurations,
  // distributed tracing backend configs (Jaeger/Tempo/Zipkin), and log
  // retention/rotation configs (logrotate/rsyslog/journald).
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.observabilitySecurityDriftIntel.recordObservabilitySecurityDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[observability-security-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-70: Identity & Privileged Access Management Configuration Drift ─
  // Analyses changed file paths for modifications to identity and privileged
  // access management configuration files: HashiCorp Vault policies, LDAP/AD
  // directory configs, PAM/sudo privilege configs, MFA enforcement configs,
  // SAML/OIDC federation metadata, workload identity files, password policies,
  // and application-level RBAC framework configs (Casbin/Oso/CASL/OpenFGA).
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.identityAccessDriftIntel.recordIdentityAccessDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[identity-access-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-69: Developer Security Tooling & SAST Configuration Drift ────
  // Analyses changed file paths for modifications to developer security tooling
  // configuration files: secret scanners (gitleaks/trufflehog), SAST tools
  // (SonarQube/Semgrep/Bandit/gosec), SCA policy (Snyk/ORT/Dependency-Check),
  // security linters (Brakeman/SpotBugs), DAST configs (ZAP/Burp/Nikto/Nuclei),
  // license policy (FOSSA/license-finder), container scan policy (Trivy/Grype),
  // and security baselines (Talisman/Hadolint/Safety/MegaLinter).
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.devSecToolsDriftIntel.recordDevSecToolsDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[dev-sec-tools-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-68: Network Perimeter & Firewall Configuration Drift ──────────
  // Analyses changed file paths for modifications to host/OS-level firewall
  // and network access-control configuration: iptables/ip6tables rules,
  // nftables config, HAProxy ACL config, UFW rules, WireGuard/OpenVPN VPN
  // configs, BIND/DNSSEC security config, proxy ACL configs, and firewalld
  // zone XML files.
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.networkFirewallDriftIntel.recordNetworkFirewallDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[network-firewall-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-67: Runtime Security Policy & Enforcement Drift ───────────────
  // Analyses changed file paths for modifications to runtime security
  // enforcement policy files: Falco behavioural rules, OPA Rego policies,
  // seccomp/AppArmor profiles, Kyverno ClusterPolicy CRDs, fail2ban config,
  // Linux auditd rules, Snort/Suricata IDS rules, and Sigma/YARA signatures.
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.runtimeSecurityDriftIntel.recordRuntimeSecurityDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[runtime-security-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-66: Cryptographic Certificate & PKI Configuration Drift ───────
  // Analyses changed file paths for modifications to cryptographic trust-layer
  // configuration: cert-manager CRDs, PKI/CA certificate files, ACME/Let's
  // Encrypt renewal configs, certificate pinning (TrustKit, Android NSC,
  // HPKP), SSH authorized_keys and sshd_config, GPG keyrings, Sigstore/cosign
  // signing configs, and TLS CA-bundle/trust-store files.
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.certPkiDriftIntel.recordCertPkiDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[cert-pki-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-65: API Security Configuration Drift Detector ────────────────
  // Analyses changed file paths for modifications to API-layer security
  // configuration files: rate limiting / throttle configs, API key management
  // and rotation configs, GraphQL security (depth limits / permissions shield),
  // OpenAPI / Swagger security schemas, webhook HMAC validation configs,
  // API quota enforcement, request/response validation schemas, and REST API
  // security policies. One finding per triggered rule.
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.apiSecurityDriftIntel.recordApiSecurityDriftScan,
        {
          tenantId:     tenant._id,
          repositoryId: repository._id,
          commitSha:    args.commitSha,
          branch:       args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[api-security-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-64: Database Security Configuration Drift Detector ────────────
  // Analyses changed file paths for modifications to database auth, TLS, and
  // security config files: pg_hba.conf/postgresql.conf (PostgreSQL), my.cnf/
  // mysqld.cnf (MySQL/MariaDB), mongod.conf (MongoDB), redis.conf/redis.acl
  // (Redis), database TLS settings, pgBouncer/pgPool/ProxySQL connection
  // pool config, security-sensitive DB migrations, and Elasticsearch/OpenSearch
  // security configuration. One finding per triggered rule.
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.databaseSecurityDriftIntel.recordDatabaseSecurityDriftScan,
        {
          tenantId: tenant._id,
          repositoryId: repository._id,
          commitSha: args.commitSha,
          branch: args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[database-security-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-63: Kubernetes & Container Security Hardening Drift Detector ──
  // Analyses changed file paths for modifications to Kubernetes security
  // configuration and container hardening files: RBAC manifests, NetworkPolicy,
  // PodSecurityPolicy/Admission, admission controllers (OPA/Kyverno/webhooks),
  // ExternalSecrets/SealedSecrets, Dockerfiles, container runtime security
  // profiles (Seccomp/AppArmor/Falco), and Helm chart security values.
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.containerHardeningDriftIntel.recordContainerHardeningDriftScan,
        {
          tenantId: tenant._id,
          repositoryId: repository._id,
          commitSha: args.commitSha,
          branch: args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[container-hardening-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-62: Cloud Security Configuration Drift Detector ───────────────
  // Analyses changed file paths for modifications to cloud-provider and
  // infrastructure security configuration files: IAM policy, KMS key policy,
  // network security groups, storage bucket policy, API Gateway auth config,
  // secrets backend config, audit logging, and CDN/WAF configuration.
  // One finding per triggered rule; fires mandatory review when critical/high
  // cloud security config files are modified in a push.
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.cloudSecurityDriftIntel.recordCloudSecurityDriftScan,
        {
          tenantId: tenant._id,
          repositoryId: repository._id,
          commitSha: args.commitSha,
          branch: args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[cloud-security-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-61: Test Coverage Gap Detector for Security-Critical Code ─────
  // Analyses changed file paths to detect security-critical source file
  // modifications (auth, crypto, payment, authz, session, middleware) that
  // lack corresponding test coverage changes in the same commit. Fires
  // one finding per domain where source changed but no test changed.
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.testCoverageGapIntel.recordTestCoverageGapScan,
        {
          tenantId: tenant._id,
          repositoryId: repository._id,
          commitSha: args.commitSha,
          branch: args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[test-coverage-gap] failed to schedule for repository', repository._id, e)
  }

  // ── WS-60: Application Security Configuration Drift Detector ─────────
  // Analyses changed file paths for modifications to application-level security
  // configuration files: JWT signing configs, OAuth/SAML/SSO provider configs,
  // CORS policy, CSP headers, TLS options, session/cookie settings, WAF rules,
  // and IAM/permission policy files. One finding per triggered rule.
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.securityConfigDriftIntel.recordSecurityConfigDriftScan,
        {
          tenantId: tenant._id,
          repositoryId: repository._id,
          commitSha: args.commitSha,
          branch: args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[security-config-drift] failed to schedule for repository', repository._id, e)
  }

  // ── WS-59: Build Toolchain Integrity Scanner ──────────────────────────
  // Analyses changed file paths for modifications to build toolchain files:
  // Makefiles, shell build scripts, webpack/vite/rollup bundler configs,
  // babel/swc transpiler configs, Gradle/Maven descriptors, Python setup
  // files, and Ruby gemspecs. One finding per triggered rule.
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.buildConfigIntel.recordBuildConfigScan,
        {
          tenantId: tenant._id,
          repositoryId: repository._id,
          commitSha: args.commitSha,
          branch: args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[build-config] failed to schedule for repository', repository._id, e)
  }

  // ── WS-58: Dependency Lock File Integrity Verifier ────────────────────
  // Analyses changed file paths for dependency lock-file integrity violations:
  // direct lock edits without manifests, mixed npm lock formats, and manifests
  // updated without their corresponding lock files.
  try {
    const allFiles = args.changedFiles ?? []
    if (allFiles.length > 0) {
      await ctx.scheduler.runAfter(
        0,
        internal.depLockIntel.recordDepLockVerifyScan,
        {
          tenantId: tenant._id,
          repositoryId: repository._id,
          commitSha: args.commitSha,
          branch: args.branch,
          changedFiles: allFiles.slice(0, 500),
        },
      )
    }
  } catch (e) {
    console.error('[dep-lock-verify] failed to schedule for repository', repository._id, e)
  }

  return { eventId, workflowRunId, deduped: false }
}

function semanticFingerprintSummary(args: {
  repositoryName: string
  changedFiles: string[]
  matchCount: number
  createdFindingCount: number
}) {
  if (args.matchCount === 0) {
    return `Semantic fingerprinting reviewed ${args.changedFiles.length} changed file path(s) for ${args.repositoryName} and found no candidate behavior matches.`
  }

  return `Semantic fingerprinting matched ${args.matchCount} candidate pattern(s) across ${args.changedFiles.length} changed file path(s) in ${args.repositoryName} and created ${args.createdFindingCount} finding(s).`
}

async function runSemanticFingerprintForWorkflowInternal(
  ctx: MutationCtx,
  workflowRunId: Id<'workflowRuns'>,
) {
  const workflowRun = await ctx.db.get(workflowRunId)

  if (!workflowRun) {
    throw new ConvexError('Workflow run not found')
  }

  const repository = await ctx.db.get(workflowRun.repositoryId)
  if (!repository) {
    throw new ConvexError('Repository not found')
  }

  const event = await ctx.db.get(workflowRun.eventId)
  if (!event) {
    throw new ConvexError('Ingestion event not found')
  }

  const tasks = await ctx.db
    .query('workflowTasks')
    .withIndex('by_workflow_run_and_order', (q) =>
      q.eq('workflowRunId', workflowRunId),
    )
    .collect()

  const analysisTask = tasks.find((task) => task.stage === 'analysis')
  if (!analysisTask) {
    const syncedState = await syncWorkflowState(ctx, workflowRunId)
    return {
      ...syncedState,
      matchCount: 0,
      createdFindingCount: 0,
    }
  }

  for (const task of tasks.filter(
    (task) => task.order < analysisTask.order && task.status === 'queued',
  )) {
    await updateWorkflowTask(
      ctx,
      workflowRunId,
      task.order,
      'completed',
      task.stage === 'intake'
        ? `Normalized stored push metadata for ${repository.name} on ${event.branch ?? 'unknown branch'}.`
        : task.stage === 'inventory'
          ? `Reused the latest imported SBOM snapshot for ${repository.name} while the live repository scan path is still being staged.`
          : task.detail,
    )
  }

  const snapshotInventory = await loadLatestSnapshotInventory(
    ctx,
    repository._id,
  )
  const changedFiles = event.changedFiles ?? []
  const matches = matchSemanticFingerprints({
    repositoryName: repository.name,
    changedFiles,
    inventoryComponents: snapshotInventory.latestComponents.map((component) => ({
      name: component.name,
      sourceFile: component.sourceFile,
      dependents: component.dependents,
    })),
  })

  const existingFindings = await ctx.db
    .query('findings')
    .withIndex('by_workflow_run_and_source', (q) =>
      q.eq('workflowRunId', workflowRunId).eq('source', 'semantic_fingerprint'),
    )
    .collect()

  const existingClasses = new Set(
    existingFindings.map((finding) => finding.vulnClass),
  )

  let createdFindingCount = 0
  const now = Date.now()

  for (const match of matches) {
    if (existingClasses.has(match.vulnClass)) {
      continue
    }

    await ctx.db.insert('findings', {
      tenantId: workflowRun.tenantId,
      repositoryId: repository._id,
      workflowRunId,
      breachDisclosureId: undefined,
      source: 'semantic_fingerprint',
      vulnClass: match.vulnClass,
      title: match.title,
      summary: match.summary,
      confidence: match.confidence,
      severity: match.severity,
      validationStatus: 'pending',
      status: 'open',
      businessImpactScore: businessImpactScoreForSeverity(
        match.severity,
        true,
        false,
      ),
      blastRadiusSummary: match.blastRadiusSummary,
      prUrl: undefined,
      reasoningLogUrl: `artifact://reasoning/${match.fingerprintId.toLowerCase()}-${workflowRunId}`,
      pocArtifactUrl: undefined,
      affectedServices: match.affectedServices,
      affectedFiles: match.matchedFiles,
      affectedPackages: match.affectedPackages,
      regulatoryImplications: [],
      createdAt: now,
      resolvedAt: undefined,
    })

    existingClasses.add(match.vulnClass)
    createdFindingCount += 1
  }

  await updateWorkflowTask(
    ctx,
    workflowRunId,
    analysisTask.order,
    'completed',
    semanticFingerprintSummary({
      repositoryName: repository.name,
      changedFiles,
      matchCount: matches.length,
      createdFindingCount,
    }),
  )

  // Fire-and-forget: real embedding-based semantic analysis (upgrades path-aware results).
  // If OPENAI_API_KEY is not set the action falls back to path-aware matching silently.
  ctx.scheduler.runAfter(0, internal.semanticFingerprintIntel.analyzeCodeChange, {
    tenantId: workflowRun.tenantId,
    repositoryId: repository._id,
    repositoryName: repository.name,
    commitSha: event.commitSha ?? 'unknown',
    branch: event.branch ?? repository.defaultBranch,
    changedFiles,
    packageDependencies: snapshotInventory.latestComponents.map((c) => c.name),
  })

  const syncedState = await syncWorkflowState(ctx, workflowRunId)

  return {
    ...syncedState,
    matchCount: matches.length,
    createdFindingCount,
  }
}

async function runExploitValidationForFindingInternal(
  ctx: MutationCtx,
  findingId: Id<'findings'>,
) {
  const finding = await ctx.db.get(findingId)

  if (!finding) {
    throw new ConvexError('Finding not found')
  }

  const workflowRun = await ctx.db.get(finding.workflowRunId)
  if (!workflowRun) {
    throw new ConvexError('Workflow run not found for finding')
  }

  const repository = await ctx.db.get(finding.repositoryId)
  if (!repository) {
    throw new ConvexError('Repository not found for finding')
  }

  const tasks = await ctx.db
    .query('workflowTasks')
    .withIndex('by_workflow_run_and_order', (q) =>
      q.eq('workflowRunId', workflowRun._id),
    )
    .collect()

  const validationTask = tasks.find((task) => task.stage === 'validation')

  if (validationTask) {
    for (const task of tasks.filter(
      (task) => task.order < validationTask.order && task.status === 'queued',
    )) {
      await updateWorkflowTask(
        ctx,
        workflowRun._id,
        task.order,
        'completed',
        task.stage === 'analysis'
          ? `Promoted the ${finding.vulnClass.replace(/_/g, ' ')} candidate into exploit-first validation for ${repository.name}.`
          : task.detail,
      )
    }
  }

  const disclosure = finding.breachDisclosureId
    ? await ctx.db.get(finding.breachDisclosureId)
    : null
  const assessment = assessExploitValidation({
    repositoryName: repository.name,
    findingId,
    finding: {
      source: finding.source,
      vulnClass: finding.vulnClass,
      severity: finding.severity,
      confidence: finding.confidence,
      affectedFiles: finding.affectedFiles,
      affectedPackages: finding.affectedPackages,
      affectedServices: finding.affectedServices,
    },
    disclosure: disclosure
      ? {
          sourceRef: disclosure.sourceRef,
          exploitAvailable: disclosure.exploitAvailable,
          matchStatus: disclosure.matchStatus,
          fixVersion: disclosure.fixVersion,
        }
      : undefined,
  })

  const startedAt = Date.now()
  const validationRunId = await ctx.db.insert('exploitValidationRuns', {
    tenantId: finding.tenantId,
    repositoryId: finding.repositoryId,
    workflowRunId: workflowRun._id,
    findingId: finding._id,
    status: 'running',
    outcome: undefined,
    validationConfidence: finding.confidence,
    sandboxSummary: `Preparing local-first validation evidence for ${repository.name}.`,
    evidenceSummary: `Queued exploit-first validation for ${finding.title}.`,
    reproductionHint: `Start with ${finding.affectedFiles[0] ?? 'the affected code path'}.`,
    startedAt,
    completedAt: undefined,
  })

  // Fire-and-forget real sandbox validation.
  // The sandbox-manager will OVERRIDE the local-first result below when it
  // completes. If SANDBOX_MANAGER_URL is not set the action safely no-ops.
  ctx.scheduler.runAfter(0, internal.sandboxValidation.triggerSandboxValidation, {
    findingId: finding._id,
    exploitValidationRunId: validationRunId,
    targetBaseUrl: undefined, // populated from env in the action if SANDBOX_TARGET_URL is set
  })

  const completedAt = Date.now()

  await ctx.db.patch('exploitValidationRuns', validationRunId, {
    status: 'completed',
    outcome: assessment.outcome,
    validationConfidence: assessment.validationConfidence,
    sandboxSummary: assessment.sandboxSummary,
    evidenceSummary: assessment.evidenceSummary,
    reproductionHint: assessment.reproductionHint,
    completedAt,
  })

  await ctx.db.patch('findings', finding._id, {
    validationStatus: assessment.outcome,
    status: assessment.outcome === 'unexploitable' ? 'resolved' : finding.status,
    reasoningLogUrl: assessment.reasoningLogUrl,
    pocArtifactUrl: assessment.pocArtifactUrl ?? finding.pocArtifactUrl,
    resolvedAt: assessment.outcome === 'unexploitable' ? completedAt : undefined,
  })

  // Fire-and-forget: outbound webhook + Slack alert for finding.validated events.
  if (assessment.outcome !== 'unexploitable') {
    try {
      const tenant = await ctx.db.get(finding.tenantId)
      if (tenant) {
        await ctx.scheduler.runAfter(
          0,
          internal.webhooks.dispatchWebhookEvent,
          {
            tenantId: finding.tenantId,
            tenantSlug: tenant.slug,
            repositoryFullName: repository.fullName,
            eventPayload: {
              event: 'finding.validated' as const,
              data: {
                findingId: finding._id as string,
                title: finding.title,
                severity: finding.severity,
                vulnClass: finding.vulnClass,
                validationStatus: assessment.outcome,
                validationConfidence: assessment.validationConfidence,
              },
            },
          },
        )

        // Slack alert (critical / high findings only, per SLACK_MIN_SEVERITY env)
        ctx.scheduler.runAfter(0, internal.slack.sendSlackAlert, {
          kind: 'finding_validated',
          tenantSlug: tenant.slug,
          repositoryFullName: repository.fullName,
          severity: finding.severity,
          title: finding.title,
          summary: finding.summary,
          vulnClass: finding.vulnClass,
          blastRadiusSummary: finding.blastRadiusSummary,
          prUrl: finding.prUrl ?? undefined,
          findingId: finding._id as string,
        })

        // Teams alert (parallel to Slack, per TEAMS_MIN_SEVERITY env)
        ctx.scheduler.runAfter(0, internal.teams.sendTeamsAlert, {
          kind: 'finding_validated',
          tenantSlug: tenant.slug,
          repositoryFullName: repository.fullName,
          severity: finding.severity,
          title: finding.title,
          summary: finding.summary,
          vulnClass: finding.vulnClass,
          blastRadiusSummary: finding.blastRadiusSummary,
          prUrl: finding.prUrl ?? undefined,
          findingId: finding._id as string,
        })

        // Opsgenie page (critical findings only, per OPSGENIE_SEVERITY_THRESHOLD env)
        ctx.scheduler.runAfter(0, internal.opsgenie.sendOpsgenieAlert, {
          kind: 'critical_finding',
          tenantSlug: tenant.slug,
          repositoryFullName: repository.fullName,
          severity: finding.severity,
          title: finding.title,
          summary: finding.summary,
          vulnClass: finding.vulnClass,
          findingId: finding._id as string,
        })
      }
    } catch (e) {
      console.error('[webhooks] finding.validated dispatch failed', e)
    }
  }

  if (validationTask) {
    await updateWorkflowTask(
      ctx,
      workflowRun._id,
      validationTask.order,
      'completed',
      assessment.evidenceSummary,
    )
  }

  const syncedState = await syncWorkflowState(ctx, workflowRun._id)

  return {
    ...syncedState,
    findingId: finding._id,
    validationRunId,
    outcome: assessment.outcome,
  }
}

function disclosureFindingTitle(packageName: string, repositoryName: string) {
  return `${packageName} disclosure matched live inventory in ${repositoryName}`
}

function disclosureFindingSummary(args: {
  packageName: string
  disclosureSummary: string
  repositoryName: string
  matchedVersions: string[]
  matchedSourceFiles: string[]
}) {
  const versionSummary =
    args.matchedVersions.length > 0
      ? ` Observed versions: ${args.matchedVersions.join(', ')}.`
      : ''
  const fileSummary =
    args.matchedSourceFiles.length > 0
      ? ` Source manifests: ${args.matchedSourceFiles.join(', ')}.`
      : ''

  return `${args.disclosureSummary} Sentinel matched ${args.packageName} in the latest SBOM snapshot for ${args.repositoryName}.${versionSummary}${fileSummary}`.trim()
}

function blastRadiusSummary(args: {
  repositoryName: string
  directComponentCount: number
  transitiveComponentCount: number
  containerComponentCount: number
}) {
  const segments: string[] = []

  if (args.directComponentCount > 0) {
    segments.push(`${args.directComponentCount} direct dependency path(s)`)
  }

  if (args.transitiveComponentCount > 0) {
    segments.push(`${args.transitiveComponentCount} transitive path(s)`)
  }

  if (args.containerComponentCount > 0) {
    segments.push(`${args.containerComponentCount} container layer reference(s)`)
  }

  if (segments.length === 0) {
    segments.push('tracked package exposure')
  }

  return `${args.repositoryName} is exposed through ${segments.join(', ')}.`
}

async function ingestCanonicalDisclosure(
  ctx: MutationCtx,
  repositoryContext: RepositoryContext,
  snapshotInventory: SnapshotInventory,
  disclosure: CanonicalDisclosureInput,
) {
  const { tenant, repository } = repositoryContext
  const routedWorkflow = buildBreachDisclosureWorkflow({
    packageName: disclosure.packageName,
    sourceName: disclosure.sourceName,
    sourceRef: disclosure.sourceRef,
    severity: disclosure.severity,
  })

  const existingEvent = await ctx.db
    .query('ingestionEvents')
    .withIndex('by_dedupe_key', (q) =>
      q.eq('dedupeKey', routedWorkflow.dedupeKey),
    )
    .unique()

  if (existingEvent) {
    const existingWorkflowRun = await ctx.db
      .query('workflowRuns')
      .withIndex('by_event', (q) => q.eq('eventId', existingEvent._id))
      .unique()

    if (!existingWorkflowRun) {
      throw new ConvexError('Existing workflow run missing for deduped event')
    }

    const existingDisclosure = await ctx.db
      .query('breachDisclosures')
      .withIndex('by_repository_and_source_ref', (q) =>
        q.eq('repositoryId', repository._id).eq('sourceRef', disclosure.sourceRef),
      )
      .unique()

    if (!existingDisclosure) {
      throw new ConvexError('Disclosure record missing for deduped event')
    }

    return {
      eventId: existingEvent._id,
      workflowRunId: existingWorkflowRun._id,
      disclosureId: existingDisclosure._id,
      deduped: true,
    }
  }

  const nameAndVersionMatch =
    snapshotInventory.latestSnapshot === null
      ? {
          matchStatus: 'no_snapshot' as BreachMatchStatus,
          versionMatchStatus: 'unknown' as const,
          matchedComponents: [] as InventoryComponentForBreachMatch[],
          affectedComponents: [] as InventoryComponentForBreachMatch[],
          matchedComponentCount: 0,
          affectedComponentCount: 0,
          matchedVersions: [] as string[],
          affectedMatchedVersions: [] as string[],
          matchedSourceFiles: [] as string[],
          directComponentCount: 0,
          transitiveComponentCount: 0,
          containerComponentCount: 0,
        }
      : matchDisclosureToInventory({
          packageName: disclosure.packageName,
          ecosystem: disclosure.ecosystem,
          affectedVersions: disclosure.affectedVersions,
          fixVersion: disclosure.fixVersion,
          components: snapshotInventory.latestComponents,
        })

  const matchSummary = buildDisclosureMatchSummary({
    packageName: disclosure.packageName,
    repositoryName: repository.name,
    matchStatus: nameAndVersionMatch.matchStatus,
    matchedComponentCount: nameAndVersionMatch.matchedComponentCount,
    affectedComponentCount: nameAndVersionMatch.affectedComponentCount,
    matchedVersions: nameAndVersionMatch.matchedVersions,
    affectedMatchedVersions: nameAndVersionMatch.affectedMatchedVersions,
    affectedVersions: disclosure.affectedVersions,
    fixVersion: disclosure.fixVersion,
  })

  const now = Date.now()
  const disclosureId = await ctx.db.insert('breachDisclosures', {
    repositoryId: repository._id,
    workflowRunId: undefined,
    packageName: disclosure.packageName,
    normalizedPackageName: normalizePackageName(disclosure.packageName),
    ecosystem: normalizeEcosystem(disclosure.ecosystem),
    sourceType: disclosure.sourceType,
    sourceTier: disclosure.sourceTier,
    sourceName: disclosure.sourceName,
    sourceRef: disclosure.sourceRef,
    aliases: uniqueStrings(disclosure.aliases),
    summary: disclosure.summary,
    severity: disclosure.severity,
    affectedVersions: disclosure.affectedVersions,
    fixVersion: disclosure.fixVersion,
    exploitAvailable: disclosure.exploitAvailable,
    matchStatus: nameAndVersionMatch.matchStatus,
    versionMatchStatus: nameAndVersionMatch.versionMatchStatus,
    matchedSnapshotId: snapshotInventory.latestSnapshot?._id,
    matchedComponentCount: nameAndVersionMatch.matchedComponentCount,
    affectedComponentCount: nameAndVersionMatch.affectedComponentCount,
    matchedVersions: nameAndVersionMatch.matchedVersions,
    affectedMatchedVersions: nameAndVersionMatch.affectedMatchedVersions,
    matchSummary,
    findingId: undefined,
    publishedAt: disclosure.publishedAt ?? now,
  })

  const eventId = await ctx.db.insert('ingestionEvents', {
    tenantId: tenant._id,
    repositoryId: repository._id,
    dedupeKey: routedWorkflow.dedupeKey,
    kind: routedWorkflow.kind,
    source: routedWorkflow.source,
    workflowType: routedWorkflow.workflowType,
    status: 'queued',
    externalRef: disclosure.sourceRef,
    summary: routedWorkflow.eventSummary,
    receivedAt: now,
  })

  const workflowRunId = await ctx.db.insert('workflowRuns', {
    tenantId: tenant._id,
    repositoryId: repository._id,
    eventId,
    workflowType: routedWorkflow.workflowType,
    status: 'queued',
    priority: routedWorkflow.priority,
    currentStage: routedWorkflow.currentStage,
    summary: routedWorkflow.workflowSummary,
    totalTaskCount: routedWorkflow.tasks.length,
    completedTaskCount: 0,
    startedAt: now,
    completedAt: undefined,
  })

  await insertWorkflowTasks(
    ctx,
    tenant._id,
    workflowRunId,
    routedWorkflow.tasks,
  )

  await ctx.db.patch('breachDisclosures', disclosureId, {
    workflowRunId,
  })

  await updateWorkflowTask(
    ctx,
    workflowRunId,
    0,
    'completed',
    `Normalized ${disclosure.packageName} from ${disclosure.sourceName} and linked it to ${repository.name}.`,
  )

  await updateWorkflowTask(ctx, workflowRunId, 1, 'completed', matchSummary)

  if (nameAndVersionMatch.affectedComponents.length > 0) {
    const affectedPackages = uniqueStrings(
      nameAndVersionMatch.affectedComponents.map((component) => component.name),
    )
    const affectedServices = uniqueStrings(
      nameAndVersionMatch.affectedComponents.flatMap(
        (component) => component.dependents,
      ),
    )

    for (const component of nameAndVersionMatch.affectedComponents) {
      if (!component._id) {
        continue
      }

      await ctx.db.patch('sbomComponents', component._id, {
        hasKnownVulnerabilities: true,
      })
    }

    const findingId = await ctx.db.insert('findings', {
      tenantId: tenant._id,
      repositoryId: repository._id,
      workflowRunId,
      breachDisclosureId: disclosureId,
      source: 'breach_intel',
      vulnClass: 'supply_chain_disclosure',
      title: disclosureFindingTitle(disclosure.packageName, repository.name),
      summary: disclosureFindingSummary({
        packageName: disclosure.packageName,
        disclosureSummary: disclosure.summary,
        repositoryName: repository.name,
        matchedVersions: nameAndVersionMatch.affectedMatchedVersions,
        matchedSourceFiles: nameAndVersionMatch.matchedSourceFiles,
      }),
      confidence: 0.92,
      severity: disclosure.severity,
      validationStatus: 'pending',
      status: 'open',
      businessImpactScore: businessImpactScoreForSeverity(
        disclosure.severity,
        nameAndVersionMatch.directComponentCount > 0,
        disclosure.exploitAvailable,
      ),
      blastRadiusSummary: blastRadiusSummary({
        repositoryName: repository.name,
        directComponentCount: nameAndVersionMatch.directComponentCount,
        transitiveComponentCount: nameAndVersionMatch.transitiveComponentCount,
        containerComponentCount: nameAndVersionMatch.containerComponentCount,
      }),
      prUrl: undefined,
      reasoningLogUrl: `artifact://reasoning/${disclosure.sourceRef.toLowerCase()}`,
      pocArtifactUrl: undefined,
      affectedServices:
        affectedServices.length > 0 ? affectedServices : [repository.name],
      affectedFiles: nameAndVersionMatch.matchedSourceFiles,
      affectedPackages,
      regulatoryImplications: [],
      createdAt: now,
      resolvedAt: undefined,
    })

    await ctx.db.patch('breachDisclosures', disclosureId, {
      findingId,
    })

    // Fire-and-forget trust score refresh. Re-scores all components in the
    // latest snapshot now that hasKnownVulnerabilities has been patched —
    // this ensures the CVE signal propagates into trustScore immediately and
    // that trust_score.degraded / trust_score.compromised webhooks fire if
    // the new disclosure pushes any package below a threshold.
    if (snapshotInventory.latestSnapshot) {
      try {
        await ctx.scheduler.runAfter(
          0,
          internal.trustScoreIntel.refreshComponentTrustScores,
          { snapshotId: snapshotInventory.latestSnapshot._id },
        )
      } catch (e) {
        console.error('[trust-score] failed to schedule after disclosure match', e)
      }
    }

    // Fire-and-forget blast radius computation. Runs asynchronously so it
    // never aborts or delays the ingestion path if it fails.
    try {
      await ctx.scheduler.runAfter(
        0,
        internal.blastRadiusIntel.computeAndStoreBlastRadius,
        { findingId },
      )
    } catch (e) {
      console.error('[blast-radius] failed to schedule for finding', findingId, e)
    }

    // Fire-and-forget memory aggregation. Refreshes the repository-level
    // learning snapshot after each new finding so adversarial rounds have
    // up-to-date signal.
    try {
      await ctx.scheduler.runAfter(
        0,
        internal.agentMemory.refreshRepositoryMemory,
        { repositoryId: repositoryContext.repository._id },
      )
    } catch (e) {
      console.error('[agent-memory] failed to schedule for repository', repositoryContext.repository._id, e)
    }

    // Fire-and-forget attack surface score refresh. Runs after memory so the
    // new snapshot can benefit from the freshly-updated RepositoryMemoryRecord.
    try {
      await ctx.scheduler.runAfter(
        0,
        internal.attackSurfaceIntel.refreshAttackSurface,
        { repositoryId: repositoryContext.repository._id },
      )
    } catch (e) {
      console.error('[attack-surface] failed to schedule for repository', repositoryContext.repository._id, e)
    }

    // Fire-and-forget regulatory drift refresh. Independent of memory/attack
    // surface — driven purely by the finding set, so it can run in parallel.
    try {
      await ctx.scheduler.runAfter(
        0,
        internal.regulatoryDriftIntel.refreshRegulatoryDrift,
        { repositoryId: repositoryContext.repository._id },
      )
    } catch (e) {
      console.error('[regulatory-drift] failed to schedule for repository', repositoryContext.repository._id, e)
    }

    // Fire-and-forget honeypot plan refresh. Aggregates blast radius snapshots
    // already written by earlier steps, so safe to run after finding creation.
    try {
      await ctx.scheduler.runAfter(
        0,
        internal.honeypotIntel.refreshHoneypotPlan,
        { repositoryId: repositoryContext.repository._id },
      )
    } catch (e) {
      console.error('[honeypot] failed to schedule for repository', repositoryContext.repository._id, e)
    }

    // Fire-and-forget learning profile refresh. Aggregates findings, red/blue
    // rounds, and attack surface history — runs after all prior steps so it
    // sees the most complete picture of the repository's security history.
    try {
      await ctx.scheduler.runAfter(
        0,
        internal.learningProfileIntel.refreshLearningProfile,
        { repositoryId: repositoryContext.repository._id },
      )
    } catch (e) {
      console.error('[learning-profile] failed to schedule for repository', repositoryContext.repository._id, e)
    }

    // Fire-and-forget compliance evidence refresh. Runs last so it can see
    // the full picture of findings, gate decisions, and PRs for this repo.
    try {
      await ctx.scheduler.runAfter(
        0,
        internal.complianceEvidenceIntel.refreshComplianceEvidence,
        { repositoryId: repositoryContext.repository._id },
      )
    } catch (e) {
      console.error('[compliance-evidence] failed to schedule for repository', repositoryContext.repository._id, e)
    }

    // Fire-and-forget cross-repository impact detection. Scans all other
    // repositories in the tenant to identify lateral package exposure from
    // this same disclosure — e.g. the same vulnerable npm package appearing
    // across multiple repos. Runs after all per-repo signals are written so
    // results reflect the full current state.
    try {
      await ctx.scheduler.runAfter(
        0,
        internal.crossRepoIntel.computeAndStoreCrossRepoImpact,
        {
          sourceFindingId: findingId,
          sourceRepositoryId: repository._id,
          tenantId: tenant._id,
          packageName: disclosure.packageName,
          ecosystem: normalizeEcosystem(disclosure.ecosystem),
          severity: disclosure.severity,
          findingTitle: disclosureFindingTitle(
            disclosure.packageName,
            repository.name,
          ),
        },
      )
    } catch (e) {
      console.error('[cross-repo] failed to schedule for finding', findingId, e)
    }

    // Fire-and-forget security debt velocity snapshot. Recomputes the
    // new/resolved velocity and overdue SLA counts for this repository now
    // that a new finding has been added.
    try {
      await ctx.scheduler.runAfter(
        0,
        internal.securityDebtIntel.computeAndStoreSecurityDebt,
        { tenantId: tenant._id, repositoryId: repository._id },
      )
    } catch (e) {
      console.error('[security-debt] failed to schedule for repository', repository._id, e)
    }

    // Fire-and-forget branch protection check. Evaluates the default-branch
    // protection configuration whenever a disclosure finding is created so the
    // dashboard always reflects the current gate posture.
    try {
      const defaultBranch = (repository as { defaultBranch?: string }).defaultBranch ?? 'main'
      await ctx.scheduler.runAfter(
        0,
        internal.branchProtectionIntel.checkAndStoreBranchProtection,
        {
          tenantId: tenant._id,
          repositoryId: repository._id,
          repositoryFullName: repository.fullName,
          defaultBranch,
        },
      )
    } catch (e) {
      console.error('[branch-protection] failed to schedule for repository', repository._id, e)
    }

    await updateWorkflowTask(
      ctx,
      workflowRunId,
      2,
      'running',
      `Created finding ${findingId} after confirming ${nameAndVersionMatch.affectedComponentCount} affected tracked component(s); exploit-first validation is now ready to run.`,
    )
  } else {
    const validationDetail =
      nameAndVersionMatch.matchStatus === 'no_snapshot'
        ? 'Skipped exploit-first validation because this repository has no imported SBOM snapshot yet.'
        : nameAndVersionMatch.matchStatus === 'version_unknown'
          ? 'Skipped exploit-first validation because the package is present but advisory version coverage could not be evaluated automatically yet.'
          : nameAndVersionMatch.matchStatus === 'version_unaffected'
            ? 'Skipped exploit-first validation because the tracked package version is outside the disclosed affected range.'
            : 'Skipped exploit-first validation because the disclosure did not match the latest tracked inventory.'
    const decisionDetail =
      nameAndVersionMatch.matchStatus === 'no_snapshot'
        ? 'Gate posture is unchanged until an SBOM snapshot is available for this repository.'
        : nameAndVersionMatch.matchStatus === 'version_unknown'
          ? 'Gate posture stayed unchanged because the advisory package matched by name, but version impact still needs manual confirmation.'
          : nameAndVersionMatch.matchStatus === 'version_unaffected'
            ? 'Gate posture stayed unchanged because the tracked package version is already outside the affected advisory range.'
            : 'Gate posture stayed unchanged because no live package exposure was found.'

    await updateWorkflowTask(
      ctx,
      workflowRunId,
      2,
      'completed',
      validationDetail,
    )
    await updateWorkflowTask(
      ctx,
      workflowRunId,
      3,
      'completed',
      decisionDetail,
    )
  }

  await syncWorkflowState(ctx, workflowRunId)

  return {
    eventId,
    workflowRunId,
    disclosureId,
    deduped: false,
  }
}

async function syncWorkflowState(
  ctx: MutationCtx,
  workflowRunId: Id<'workflowRuns'>,
) {
  const workflowRun = await ctx.db.get(workflowRunId)

  if (!workflowRun) {
    throw new ConvexError('Workflow run not found')
  }

  const tasks = await ctx.db
    .query('workflowTasks')
    .withIndex('by_workflow_run_and_order', (q) =>
      q.eq('workflowRunId', workflowRunId),
    )
    .collect()

  const completedTaskCount = tasks.filter(
    (task) => task.status === 'completed',
  ).length
  const failedTask = tasks.find((task) => task.status === 'failed') ?? null
  const runningTask = tasks.find((task) => task.status === 'running') ?? null
  const nextQueuedTask = tasks.find((task) => task.status === 'queued') ?? null

  const nextStatus: Doc<'workflowRuns'>['status'] = failedTask
    ? 'failed'
    : completedTaskCount === tasks.length
      ? 'completed'
      : Boolean(runningTask) || completedTaskCount > 0
        ? 'running'
        : 'queued'

  const currentStage =
    failedTask?.stage ??
    runningTask?.stage ??
    nextQueuedTask?.stage ??
    tasks.at(-1)?.stage

  await ctx.db.patch('workflowRuns', workflowRunId, {
    status: nextStatus,
    currentStage,
    summary: buildWorkflowSummary(
      workflowRun.workflowType,
      nextStatus,
      runningTask ?? nextQueuedTask,
      failedTask,
      completedTaskCount,
      tasks.length,
    ),
    totalTaskCount: tasks.length,
    completedTaskCount,
    completedAt:
      nextStatus === 'completed' || nextStatus === 'failed'
        ? Date.now()
        : undefined,
  })

  await ctx.db.patch('ingestionEvents', workflowRun.eventId, {
    status: nextStatus,
  })

  return {
    workflowRunId,
    workflowStatus: nextStatus,
    currentStage,
    completedTaskCount,
    totalTaskCount: tasks.length,
  }
}

export const ingestGithubPush = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    branch: v.string(),
    commitSha: v.string(),
    changedFiles: v.array(v.string()),
    commitMessages: v.optional(v.array(v.string())),
  },
  returns: v.object({
    eventId: v.id('ingestionEvents'),
    workflowRunId: v.id('workflowRuns'),
    deduped: v.boolean(),
  }),
  handler: async (ctx, args) => {
    const repositoryContext = await getRepositoryContext(
      ctx,
      args.tenantSlug,
      args.repositoryFullName,
    )

    return ingestGithubPushForRepository(ctx, repositoryContext, {
      branch: args.branch,
      commitSha: args.commitSha,
      changedFiles: args.changedFiles,
      commitMessages: args.commitMessages,
    })
  },
})

export const ingestGithubPushFromWebhook = internalMutation({
  args: {
    repositoryFullName: v.string(),
    branch: v.string(),
    commitSha: v.string(),
    changedFiles: v.array(v.string()),
    commitMessages: v.optional(v.array(v.string())),
  },
  returns: v.object({
    eventId: v.id('ingestionEvents'),
    workflowRunId: v.id('workflowRuns'),
    deduped: v.boolean(),
  }),
  handler: async (ctx, args) => {
    const repositoryContext = await getRepositoryContextByProviderAndFullName(
      ctx,
      'github',
      args.repositoryFullName,
    )

    return ingestGithubPushForRepository(ctx, repositoryContext, {
      branch: args.branch,
      commitSha: args.commitSha,
      changedFiles: args.changedFiles,
      commitMessages: args.commitMessages,
    })
  },
})

export const runSemanticFingerprintForWorkflow = mutation({
  args: {
    workflowRunId: v.id('workflowRuns'),
  },
  returns: v.object({
    workflowRunId: v.id('workflowRuns'),
    workflowStatus: lifecycleStatus,
    currentStage: v.optional(v.string()),
    completedTaskCount: v.number(),
    totalTaskCount: v.number(),
    matchCount: v.number(),
    createdFindingCount: v.number(),
  }),
  handler: async (ctx, args) => {
    return await runSemanticFingerprintForWorkflowInternal(
      ctx,
      args.workflowRunId,
    )
  },
})

export const runLatestSemanticFingerprint = mutation({
  args: {
    tenantSlug: v.string(),
  },
  returns: v.union(
    v.null(),
    v.object({
      workflowRunId: v.id('workflowRuns'),
      workflowStatus: lifecycleStatus,
      currentStage: v.optional(v.string()),
      completedTaskCount: v.number(),
      totalTaskCount: v.number(),
      matchCount: v.number(),
      createdFindingCount: v.number(),
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) {
      return null
    }

    const workflows = await ctx.db
      .query('workflowRuns')
      .withIndex('by_tenant_and_started_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(10)

    const targetWorkflow = workflows.find(
      (workflow) => workflow.workflowType === 'full_scan',
    )

    if (!targetWorkflow) {
      return null
    }

    return await runSemanticFingerprintForWorkflowInternal(ctx, targetWorkflow._id)
  },
})

export const runExploitValidationForFinding = mutation({
  args: {
    findingId: v.id('findings'),
  },
  returns: v.object({
    workflowRunId: v.id('workflowRuns'),
    workflowStatus: lifecycleStatus,
    currentStage: v.optional(v.string()),
    completedTaskCount: v.number(),
    totalTaskCount: v.number(),
    findingId: v.id('findings'),
    validationRunId: v.id('exploitValidationRuns'),
    outcome: validationOutcome,
  }),
  handler: async (ctx, args) => {
    return await runExploitValidationForFindingInternal(ctx, args.findingId)
  },
})

export const runLatestExploitValidation = mutation({
  args: {
    tenantSlug: v.string(),
  },
  returns: v.union(
    v.null(),
    v.object({
      workflowRunId: v.id('workflowRuns'),
      workflowStatus: lifecycleStatus,
      currentStage: v.optional(v.string()),
      completedTaskCount: v.number(),
      totalTaskCount: v.number(),
      findingId: v.id('findings'),
      validationRunId: v.id('exploitValidationRuns'),
      outcome: validationOutcome,
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) {
      return null
    }

    const candidateFindings = await ctx.db
      .query('findings')
      .withIndex('by_tenant_and_created_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(25)

    const targetFinding = candidateFindings.find(
      (finding) =>
        finding.validationStatus === 'pending' &&
        (finding.status === 'open' || finding.status === 'pr_opened'),
    )

    if (!targetFinding) {
      return null
    }

    return await runExploitValidationForFindingInternal(ctx, targetFinding._id)
  },
})

export const progressWorkflowTask = mutation({
  args: {
    workflowRunId: v.id('workflowRuns'),
    taskOrder: v.number(),
    status: lifecycleStatus,
    detail: v.optional(v.string()),
  },
  returns: v.object({
    workflowRunId: v.id('workflowRuns'),
    workflowStatus: lifecycleStatus,
    currentStage: v.optional(v.string()),
    completedTaskCount: v.number(),
    totalTaskCount: v.number(),
  }),
  handler: async (ctx, args) => {
    await updateWorkflowTask(
      ctx,
      args.workflowRunId,
      args.taskOrder,
      args.status,
      args.detail,
    )

    return syncWorkflowState(ctx, args.workflowRunId)
  },
})

export const simulateLatestWorkflowStep = mutation({
  args: {
    tenantSlug: v.string(),
  },
  returns: v.union(
    v.null(),
    v.object({
      workflowRunId: v.id('workflowRuns'),
      workflowStatus: lifecycleStatus,
      currentStage: v.optional(v.string()),
      completedTaskCount: v.number(),
      totalTaskCount: v.number(),
      advancedTaskTitle: v.string(),
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) {
      return null
    }

    const activeWorkflow = (
      await ctx.db
        .query('workflowRuns')
        .withIndex('by_tenant_and_started_at', (q) =>
          q.eq('tenantId', tenant._id),
        )
        .order('desc')
        .collect()
    ).find(
      (workflow) =>
        workflow.status === 'queued' || workflow.status === 'running',
    )

    if (!activeWorkflow) {
      return null
    }

    const tasks = await ctx.db
      .query('workflowTasks')
      .withIndex('by_workflow_run_and_order', (q) =>
        q.eq('workflowRunId', activeWorkflow._id),
      )
      .collect()

    const runningTask = tasks.find((task) => task.status === 'running')
    const queuedTask = tasks.find((task) => task.status === 'queued')
    const taskToAdvance = runningTask ?? queuedTask

    if (!taskToAdvance) {
      const syncedState = await syncWorkflowState(ctx, activeWorkflow._id)
      return {
        ...syncedState,
        advancedTaskTitle: 'No queued tasks remaining',
      }
    }

    const nextStatus = runningTask ? 'completed' : 'running'
    await updateWorkflowTask(
      ctx,
      activeWorkflow._id,
      taskToAdvance.order,
      nextStatus,
      runningTask
        ? `${taskToAdvance.detail} Completed during local workflow simulation.`
        : `${taskToAdvance.detail} Started during local workflow simulation.`,
    )
    const syncedState = await syncWorkflowState(ctx, activeWorkflow._id)

    return {
      ...syncedState,
      advancedTaskTitle: taskToAdvance.title,
    }
  },
})

export const runGateEvaluationForWorkflowMutation = mutation({
  args: { workflowRunId: v.id('workflowRuns') },
  returns: v.object({
    workflowRunId: v.id('workflowRuns'),
    overallDecision: v.union(v.literal('approved'), v.literal('blocked')),
    blockCount: v.number(),
    totalEvaluated: v.number(),
    newDecisionCount: v.number(),
    summary: v.string(),
  }),
  handler: async (ctx, args) => {
    return runGateEvaluationForWorkflow(ctx, args.workflowRunId)
  },
})

export const runLatestGateEvaluation = mutation({
  args: { tenantSlug: v.string() },
  returns: v.union(
    v.null(),
    v.object({
      workflowRunId: v.id('workflowRuns'),
      overallDecision: v.union(v.literal('approved'), v.literal('blocked')),
      blockCount: v.number(),
      totalEvaluated: v.number(),
      newDecisionCount: v.number(),
      summary: v.string(),
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()

    if (!tenant) return null

    // Find the most recent workflow run that has a policy stage task.
    const recentWorkflows = await ctx.db
      .query('workflowRuns')
      .withIndex('by_tenant_and_started_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(10)

    let targetWorkflowId: Id<'workflowRuns'> | null = null

    for (const workflow of recentWorkflows) {
      const tasks = await ctx.db
        .query('workflowTasks')
        .withIndex('by_workflow_run_and_order', (q) =>
          q.eq('workflowRunId', workflow._id),
        )
        .collect()

      const hasPolicyTask = tasks.some((t) => t.stage === 'policy')
      if (hasPolicyTask) {
        targetWorkflowId = workflow._id
        break
      }
    }

    if (!targetWorkflowId) return null

    return runGateEvaluationForWorkflow(ctx, targetWorkflowId)
  },
})

const githubSecurityAdvisoryValidator = v.object({
  ghsaId: v.string(),
  summary: v.string(),
  description: v.optional(v.string()),
  severity,
  aliases: v.optional(v.array(v.string())),
  exploitAvailable: v.optional(v.boolean()),
  publishedAt: v.optional(v.number()),
  vulnerabilities: v.array(
    v.object({
      packageName: v.string(),
      ecosystem: v.string(),
      vulnerableVersionRange: v.optional(v.string()),
      firstPatchedVersion: v.optional(v.string()),
    }),
  ),
})

const osvAdvisoryValidator = v.object({
  id: v.string(),
  summary: v.string(),
  details: v.optional(v.string()),
  severity: v.optional(severity),
  severityScore: v.optional(v.number()),
  aliases: v.optional(v.array(v.string())),
  exploitAvailable: v.optional(v.boolean()),
  publishedAt: v.optional(v.number()),
  affected: v.array(
    v.object({
      packageName: v.string(),
      ecosystem: v.string(),
      versions: v.optional(v.array(v.string())),
      ranges: v.optional(
        v.array(
          v.object({
            type: v.optional(v.string()),
            events: v.array(
              v.object({
                introduced: v.optional(v.string()),
                fixed: v.optional(v.string()),
                lastAffected: v.optional(v.string()),
                limit: v.optional(v.string()),
              }),
            ),
          }),
        ),
      ),
    }),
  ),
})

export const ingestBreachDisclosure = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    packageName: v.string(),
    sourceName: v.string(),
    sourceRef: v.string(),
    summary: v.string(),
    ecosystem: v.optional(v.string()),
    sourceType: v.optional(
      v.union(
        v.literal('manual'),
        v.literal('github_security_advisory'),
        v.literal('osv'),
        v.literal('nvd'),
        v.literal('npm_advisory'),
        v.literal('pypi_safety'),
        v.literal('rustsec'),
        v.literal('go_vuln'),
        v.literal('github_issues'),
        v.literal('hackerone'),
        v.literal('oss_security'),
        v.literal('packet_storm'),
        v.literal('paste_site'),
        v.literal('credential_dump'),
        v.literal('dark_web_mention'),
      ),
    ),
    sourceTier: v.optional(
      v.union(v.literal('tier_1'), v.literal('tier_2'), v.literal('tier_3')),
    ),
    affectedVersions: v.optional(v.array(v.string())),
    fixVersion: v.optional(v.string()),
    exploitAvailable: v.optional(v.boolean()),
    aliases: v.optional(v.array(v.string())),
    publishedAt: v.optional(v.number()),
    severity,
  },
  returns: v.object({
    eventId: v.id('ingestionEvents'),
    workflowRunId: v.id('workflowRuns'),
    disclosureId: v.id('breachDisclosures'),
    deduped: v.boolean(),
  }),
  handler: async (ctx, args) => {
    const repositoryContext = await getRepositoryContext(
      ctx,
      args.tenantSlug,
      args.repositoryFullName,
    )
    const snapshotInventory = await loadLatestSnapshotInventory(
      ctx,
      repositoryContext.repository._id,
    )

    return ingestCanonicalDisclosure(ctx, repositoryContext, snapshotInventory, {
      packageName: args.packageName,
      ecosystem: args.ecosystem ?? 'unknown',
      sourceName: args.sourceName,
      sourceRef: args.sourceRef,
      sourceType: args.sourceType ?? 'manual',
      sourceTier: args.sourceTier ?? 'tier_1',
      summary: args.summary,
      severity: args.severity,
      affectedVersions: args.affectedVersions ?? [],
      fixVersion: args.fixVersion,
      aliases: args.aliases ?? [args.sourceRef],
      exploitAvailable: args.exploitAvailable ?? false,
      publishedAt: args.publishedAt,
    })
  },
})

export const ingestGithubSecurityAdvisory = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    advisory: githubSecurityAdvisoryValidator,
  },
  returns: v.object({
    eventId: v.id('ingestionEvents'),
    workflowRunId: v.id('workflowRuns'),
    disclosureId: v.id('breachDisclosures'),
    deduped: v.boolean(),
  }),
  handler: async (ctx, args) => {
    const repositoryContext = await getRepositoryContext(
      ctx,
      args.tenantSlug,
      args.repositoryFullName,
    )
    const snapshotInventory = await loadLatestSnapshotInventory(
      ctx,
      repositoryContext.repository._id,
    )
    const normalizedDisclosure = normalizeGithubSecurityAdvisory({
      advisory: args.advisory,
      inventoryComponents: snapshotInventory.latestComponents,
    })

    return ingestCanonicalDisclosure(ctx, repositoryContext, snapshotInventory, {
      ...normalizedDisclosure,
    })
  },
})

export const ingestOsvAdvisory = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    advisory: osvAdvisoryValidator,
  },
  returns: v.object({
    eventId: v.id('ingestionEvents'),
    workflowRunId: v.id('workflowRuns'),
    disclosureId: v.id('breachDisclosures'),
    deduped: v.boolean(),
  }),
  handler: async (ctx, args) => {
    const repositoryContext = await getRepositoryContext(
      ctx,
      args.tenantSlug,
      args.repositoryFullName,
    )
    const snapshotInventory = await loadLatestSnapshotInventory(
      ctx,
      repositoryContext.repository._id,
    )
    const normalizedDisclosure = normalizeOsvAdvisory({
      advisory: args.advisory,
      inventoryComponents: snapshotInventory.latestComponents,
    })

    return ingestCanonicalDisclosure(ctx, repositoryContext, snapshotInventory, {
      ...normalizedDisclosure,
    })
  },
})
