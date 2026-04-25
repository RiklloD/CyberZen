// WS-86 — SIEM & Security Analytics Configuration Drift Detector:
// pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to SIEM detection rules, correlation logic, threat-intel feed configuration,
// SOAR playbooks, and related security-analytics tooling.  A modified Splunk
// savedsearches.conf can silently disable alert generation; a suppressed Elastic
// detection rule creates a monitoring blind spot; an altered SOAR playbook can
// disable automated incident response.
//
// DISTINCT from:
//   WS-15  regulatoryDrift       — SIEM push connector setup (Splunk HEC URL,
//                                   Elastic cloud ID); WS-86 covers the SIEM's
//                                   OWN detection rules and analytics configs
//   WS-67  runtimeSecurityDrift  — host-level enforcement policy files (Falco
//                                   rules, OPA Rego, seccomp, fail2ban, auditd,
//                                   Snort/Suricata/Zeek, SIGMA/YARA); WS-86
//                                   covers higher-level SIEM analytics
//   WS-71  observabilitySecurityDrift — log-shipping pipeline configs (Fluentd,
//                                   Logstash, Vector, Filebeat, Prometheus alert
//                                   rules, Alertmanager); WS-86 covers SIEM
//                                   detection rules and threat analytics, NOT
//                                   the log pipeline itself
//   WS-70  identityAccessDrift    — Vault/LDAP/PAM/SCIM; WS-86 covers SIEM
//                                   role/permission configs only if in a SIEM dir
//
// Covered rule groups (8 rules):
//
//   SPLUNK_DETECTION_CONFIG_DRIFT — Splunk saved searches, correlation searches,
//                                   and alert actions (Enterprise Security)
//   ELASTIC_SIEM_RULE_DRIFT       — Elastic Security detection rule exports
//                                   (.ndjson bundles) and Kibana security config
//   SENTINEL_ANALYTICS_DRIFT      — Microsoft Sentinel analytics rules and
//                                   hunting queries (common in Azure-centric repos)
//   OSQUERY_CONFIG_DRIFT          — osquery configuration and scheduled threat-
//                                   detection query packs (osquery.conf / packs/)
//   SIEM_DETECTION_SUPPRESSION_DRIFT — Alert suppression, exception, and
//                                   allowlist configuration (monitoring blind spots)
//   SOAR_PLAYBOOK_DRIFT           — Security Orchestration, Automation, and
//                                   Response playbooks (Cortex XSOAR/Demisto,
//                                   Splunk SOAR/Phantom) and automation scripts
//   THREAT_INTEL_FEED_DRIFT       — Threat intelligence platform configuration
//                                   (MISP, OpenCTI, TAXII server/client, STIX)
//   SIEM_LOG_SOURCE_DRIFT         — SIEM data-source / forwarder input
//                                   configuration (inputs.conf, log-source rules)
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Vendor directory exclusion applied to all paths.
//   • Same penalty/cap scoring model as WS-60–85 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (firstPath + matchCount).
//   • savedsearches.conf / alert_actions.conf / correlationsearches.conf are
//     globally unambiguous Splunk filenames — matched without directory gating.
//   • osquery.conf / osquery.flags are globally unambiguous osquery filenames.
//   • misp.conf / opencti.yml / taxii-config.json are globally unambiguous
//     threat-intelligence platform filenames.
//   • Generic names (inputs.conf, playbook-*.yaml) are gated on tool-specific
//     directory segments to prevent false positives.
//   • All ungated Set entries are stored lowercase because base is derived from
//     normalise(raw).toLowerCase() — case-sensitivity lesson from WS-83.
//
// Exports:
//   isSiemDetectionRuleFile   — user contribution point (see JSDoc below)
//   SIEM_SECURITY_RULES       — readonly rule registry
//   scanSiemSecurityDrift     — main scanner, returns SiemSecurityDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SiemSecurityRuleId =
  | 'SPLUNK_DETECTION_CONFIG_DRIFT'
  | 'ELASTIC_SIEM_RULE_DRIFT'
  | 'SENTINEL_ANALYTICS_DRIFT'
  | 'OSQUERY_CONFIG_DRIFT'
  | 'SIEM_DETECTION_SUPPRESSION_DRIFT'
  | 'SOAR_PLAYBOOK_DRIFT'
  | 'THREAT_INTEL_FEED_DRIFT'
  | 'SIEM_LOG_SOURCE_DRIFT'

export type SiemSecuritySeverity = 'high' | 'medium' | 'low'
export type SiemSecurityRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type SiemSecurityDriftFinding = {
  ruleId: SiemSecurityRuleId
  severity: SiemSecuritySeverity
  matchedPath: string
  matchCount: number
  description: string
  recommendation: string
}

export type SiemSecurityDriftResult = {
  riskScore: number
  riskLevel: SiemSecurityRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: SiemSecurityDriftFinding[]
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

const SPLUNK_DIRS     = ['splunk/', 'splunk-config/', '.splunk/', 'splunk-apps/', 'splunk-es/', 'apps/splunk/', 'apps/sa-threatintelligence/']
const ELASTIC_SIEM_DIRS = ['detection-rules/', 'detection_rules/', 'elastic-siem/', 'elastic-security/', 'kibana-rules/', 'security-rules/', 'siem-rules/']
const SENTINEL_DIRS   = ['sentinel/', 'azure-sentinel/', 'microsoft-sentinel/', 'sentinel-rules/', 'sentinel-analytics/', 'sentinel-workbooks/', 'azsentinel/']
const OSQUERY_DIRS    = ['osquery/', '.osquery/', 'osquery-config/', 'osquery-packs/', 'packs/osquery/']
const SIEM_DIRS       = ['siem/', 'siem-config/', 'security-rules/', 'detection/', 'soc/', 'security-exceptions/', 'security-config/', 'security-analytics/']
const SOAR_DIRS       = ['soar/', 'demisto/', 'xsoar/', 'cortex-xsoar/', 'phantom/', 'splunk-soar/', 'cortex/', 'paloalto-xsoar/', 'soar-playbooks/', 'ir-playbooks/']
const THREAT_INTEL_DIRS = ['threat-intel/', 'ti/', 'misp/', 'opencti/', 'taxii/', 'stix/', 'ioc/', 'iocs/', 'threat-intelligence/', 'threat_intel/']
const SIEM_INPUT_DIRS = ['splunk/inputs/', 'siem-inputs/', 'log-sources/', 'splunk-forwarder/', 'universal-forwarder/', 'heavy-forwarder/', 'log-collector/']

function inAnyDir(pathLower: string, dirs: readonly string[]): boolean {
  return dirs.some((d) => pathLower.includes(d))
}

// ---------------------------------------------------------------------------
// Rule 1: SPLUNK_DETECTION_CONFIG_DRIFT (high)
// Splunk saved searches, correlation searches, and alert actions
// ---------------------------------------------------------------------------

const SPLUNK_UNGATED = new Set([
  'savedsearches.conf',        // Splunk saved searches — globally unambiguous
  'alert_actions.conf',        // Splunk alert actions — globally unambiguous
  'correlationsearches.conf',  // Splunk Enterprise Security correlation searches
  'notable_event_actions.conf', // Splunk ES notable event actions
])

function isSplunkDetectionConfig(pathLower: string, base: string): boolean {
  if (SPLUNK_UNGATED.has(base)) return true

  // Splunk correlation search filename convention
  if (base.startsWith('correlation_search-') && base.endsWith('.conf')) return true
  if (base.startsWith('splunk-alert-') && base.endsWith('.conf')) return true

  if (!inAnyDir(pathLower, SPLUNK_DIRS)) return false

  // Threat-intel lookups, macros used in correlation rules
  if (base === 'transforms.conf' || base === 'macros.conf') return true
  // Any conf or lookup file in a Splunk app dir
  if (base.endsWith('.conf') || base.endsWith('.csv')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 2: ELASTIC_SIEM_RULE_DRIFT (high)
// Elastic Security detection rule bundles and security configuration
// ---------------------------------------------------------------------------

function isElasticSiemRule(pathLower: string, base: string): boolean {
  // .ndjson is the canonical Elastic detection rule export format
  if (base.endsWith('.ndjson') && inAnyDir(pathLower, ELASTIC_SIEM_DIRS)) return true

  // Prefix patterns specific to Elastic SIEM rule exports
  if (base.startsWith('elastic-siem-') && (base.endsWith('.json') || base.endsWith('.yaml'))) return true
  if (base.startsWith('detection-rule-') && (base.endsWith('.json') || base.endsWith('.yaml') || base.endsWith('.toml'))) return true

  if (!inAnyDir(pathLower, ELASTIC_SIEM_DIRS)) return false

  // Any JSON/YAML/TOML/NDJSON in elastic siem dirs
  if (
    base.endsWith('.json')  || base.endsWith('.yaml') || base.endsWith('.yml') ||
    base.endsWith('.toml')  || base.endsWith('.ndjson')
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 3: SENTINEL_ANALYTICS_DRIFT (high)
// Microsoft Sentinel analytics rules and hunting queries
// ---------------------------------------------------------------------------

const SENTINEL_UNGATED = new Set([
  'analyticsrules.json',    // Sentinel analytics rules export — tool convention
  'analyticsrules.yaml',    // YAML variant
  'huntingqueries.json',    // Sentinel hunting queries export
  'huntingqueries.yaml',
])

function isSentinelAnalyticsConfig(pathLower: string, base: string): boolean {
  if (SENTINEL_UNGATED.has(base)) return true

  // Microsoft Sentinel analytics rule export filename prefix conventions
  if (base.startsWith('analyticsrule-') && (base.endsWith('.json') || base.endsWith('.yaml'))) return true
  if (base.startsWith('huntingquery-') && (base.endsWith('.json') || base.endsWith('.yaml'))) return true
  if (base.startsWith('alertrule-') && (base.endsWith('.json') || base.endsWith('.yaml'))) return true
  if (base.startsWith('sentinel-rule-') && (base.endsWith('.json') || base.endsWith('.yaml'))) return true

  if (!inAnyDir(pathLower, SENTINEL_DIRS)) return false

  if (base.endsWith('.json') || base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.kql')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 4: OSQUERY_CONFIG_DRIFT (high)
// osquery threat-detection configuration and scheduled query packs
// ---------------------------------------------------------------------------

const OSQUERY_UNGATED = new Set([
  'osquery.conf',      // osquery main configuration — globally unambiguous
  'osquery.flags',     // osquery startup flags — globally unambiguous
  '.osquery.conf',     // dot-prefixed variant (common in $HOME)
  'osquery.example.conf', // example config shipped with osquery packages
])

function isOsqueryConfig(pathLower: string, base: string): boolean {
  if (OSQUERY_UNGATED.has(base)) return true

  // osquery pack / config filename prefixes
  if (base.startsWith('osquery-') && (base.endsWith('.conf') || base.endsWith('.json'))) return true
  if (base.startsWith('osquery-packs-') && base.endsWith('.json')) return true

  if (!inAnyDir(pathLower, OSQUERY_DIRS)) return false

  // JSON pack files within osquery packs directories
  if (base.endsWith('.json') || base.endsWith('.conf')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 5: SIEM_DETECTION_SUPPRESSION_DRIFT (medium)
// Alert suppression, exception lists, and allowlists (monitoring blind spots)
// ---------------------------------------------------------------------------

const SUPPRESSION_UNGATED = new Set([
  'detection-exceptions.yaml',
  'detection-exceptions.json',
  'alert-exceptions.yaml',
  'alert-exceptions.json',
  'suppression-rules.yaml',
  'suppression-rules.json',
  'detection-suppressions.yaml',
  'detection-suppressions.json',
])

function isSiemSuppressionConfig(pathLower: string, base: string): boolean {
  if (SUPPRESSION_UNGATED.has(base)) return true

  // Suffix patterns that indicate exception/suppression files
  const suppressionSuffixes = ['-exceptions.yaml', '-exceptions.json', '-whitelist.yaml',
    '-whitelist.json', '-suppression.yaml', '-suppression.json', '-allowlist.yaml',
    '-allowlist.json', '-false-positives.yaml', '-false-positives.json']
  if (suppressionSuffixes.some((s) => base.endsWith(s))) {
    if (inAnyDir(pathLower, SIEM_DIRS) || inAnyDir(pathLower, SPLUNK_DIRS) || inAnyDir(pathLower, ELASTIC_SIEM_DIRS)) return true
  }

  if (!inAnyDir(pathLower, SIEM_DIRS)) return false

  // Generic allowlist / exception filenames gated on SIEM dirs
  if (
    base === 'allowlist.yaml'  || base === 'allowlist.json'  ||
    base === 'exceptions.yaml' || base === 'exceptions.json' ||
    base === 'suppressions.yaml' || base === 'suppressions.json' ||
    base === 'whitelist.yaml'  || base === 'whitelist.json'
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 6: SOAR_PLAYBOOK_DRIFT (medium)
// SOAR playbooks, automation scripts, and IR orchestration configuration
// ---------------------------------------------------------------------------

const SOAR_UNGATED = new Set([
  'xsoar-config.yaml',    // Cortex XSOAR configuration — globally unambiguous
  'xsoar-config.json',
  'demisto-config.yaml',  // Demisto (predecessor to XSOAR) — globally unambiguous
  'demisto-config.json',
  'phantom-config.json',  // Splunk SOAR (formerly Phantom) — globally unambiguous
  'splunk-soar-config.yaml',
])

function isSoarPlaybook(pathLower: string, base: string): boolean {
  if (SOAR_UNGATED.has(base)) return true

  // XSOAR/Demisto playbook prefix naming conventions
  if (base.startsWith('xsoar-playbook-') && (base.endsWith('.yaml') || base.endsWith('.json'))) return true
  if (base.startsWith('demisto-playbook-') && (base.endsWith('.yaml') || base.endsWith('.json'))) return true

  if (!inAnyDir(pathLower, SOAR_DIRS)) return false

  // Any playbook/automation/integration file in SOAR dirs
  if (base.startsWith('playbook-') && (base.endsWith('.yaml') || base.endsWith('.json') || base.endsWith('.yml'))) return true
  if (base.startsWith('automation-') && base.endsWith('.py')) return true
  if (base.startsWith('integration-') && (base.endsWith('.yml') || base.endsWith('.yaml'))) return true

  if (
    base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json') ||
    base.endsWith('.py')   || base.endsWith('.js')
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 7: THREAT_INTEL_FEED_DRIFT (medium)
// Threat intelligence platform configuration (MISP, OpenCTI, TAXII, STIX)
// ---------------------------------------------------------------------------

const THREAT_INTEL_UNGATED = new Set([
  'misp.conf',            // MISP main configuration — globally unambiguous
  'misp-config.yaml',     // MISP configuration in YAML
  'misp-config.json',     // MISP configuration in JSON
  '.misp.conf',           // Dot-prefixed variant
  'opencti.yml',          // OpenCTI threat platform — globally unambiguous
  'opencti.yaml',
  'opencti-config.yaml',
  'taxii-config.json',    // TAXII server/client configuration — globally unambiguous
  'taxii-config.yaml',
  'stix-config.yaml',     // STIX bundle configuration
  'stix-config.json',
])

/**
 * isSiemDetectionRuleFile — USER CONTRIBUTION POINT
 *
 * Determines whether a changed file path is a SIEM-specific detection rule file,
 * as opposed to other rule files (Prometheus alert rules → WS-71, Sigma/YARA rules
 * → WS-67, IaC policy files → WS-62/63) that share similar naming conventions.
 *
 * Context: This function is called by THREAT_INTEL_FEED_DRIFT to gate generic
 * threat-intel file basenames. It must exclude:
 *   • Infrastructure-as-Code directories (terraform/, pulumi/, cdk/, cloudformation/)
 *     which may contain "rule" files unrelated to threat detection
 *   • CI/CD directories (.github/, .gitlab/, .circleci/) — pipeline rule files
 *   • Prometheus/Alertmanager directories — those files belong to WS-71
 *   • Falco/YARA/Sigma directories — those files belong to WS-67
 *
 * And must positively match:
 *   • Files with `threat`, `intel`, `ioc`, `indicator`, `feed`, or `misp` in name
 *   • Files with STIX/TAXII/OpenIOC/CybOX specific extensions or naming patterns
 *   • Files in threat-intelligence-specific directories
 *
 * @param pathLower  — normalised (lowercase, forward-slash) file path
 * @param base       — basename extracted from pathLower
 * @returns true if the file is a SIEM threat-intel configuration file
 */
export function isSiemDetectionRuleFile(pathLower: string, base: string): boolean {
  // Exclude IaC and CI/CD dirs — not threat-intel context
  if (
    pathLower.includes('terraform/') || pathLower.includes('pulumi/') ||
    pathLower.includes('cdk/') || pathLower.includes('cloudformation/') ||
    pathLower.includes('.github/') || pathLower.includes('.gitlab/') ||
    pathLower.includes('.circleci/') || pathLower.includes('.buildkite/')
  ) return false

  // Exclude Prometheus/Alertmanager dirs (WS-71 territory)
  if (
    pathLower.includes('prometheus-rules/') || pathLower.includes('prometheus/rules/') ||
    pathLower.includes('alert-rules/') || pathLower.includes('alertmanager/')
  ) return false

  // Exclude Sigma/YARA/Falco dirs (WS-67 territory)
  if (
    pathLower.includes('sigma/') || pathLower.includes('yara/') ||
    pathLower.includes('falco/') || pathLower.includes('sigma-rules/')
  ) return false

  // Threat-intel keyword in basename
  const threatKeywords = ['threat', 'intel', 'ioc', 'indicator', 'feed', 'misp', 'opencti', 'stix', 'taxii']
  if (
    threatKeywords.some((k) => base.includes(k)) &&
    (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json') || base.endsWith('.conf'))
  ) return true

  // Must be in a threat-intel directory
  if (!inAnyDir(pathLower, THREAT_INTEL_DIRS)) return false

  if (
    base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json') ||
    base.endsWith('.conf') || base.endsWith('.xml') || base.endsWith('.stix')
  ) return true

  return false
}

function isThreatIntelFeedConfig(pathLower: string, base: string): boolean {
  if (THREAT_INTEL_UNGATED.has(base)) return true

  // MISP prefix naming conventions
  if (base.startsWith('misp-') && (base.endsWith('.yaml') || base.endsWith('.json') || base.endsWith('.conf'))) return true
  // OpenIOC / Indicator feed configs
  if (base.startsWith('openioc-') && base.endsWith('.xml')) return true
  if (base.startsWith('taxii-') && (base.endsWith('.json') || base.endsWith('.yaml'))) return true

  return isSiemDetectionRuleFile(pathLower, base)
}

// ---------------------------------------------------------------------------
// Rule 8: SIEM_LOG_SOURCE_DRIFT (low)
// SIEM data source / forwarder input configuration
// ---------------------------------------------------------------------------

const SIEM_INPUT_UNGATED = new Set([
  'inputs.conf',    // Splunk universal/heavy forwarder data inputs — gated below
  'outputs.conf',   // Splunk forwarder output target — gated below
])

function isSiemLogSourceConfig(pathLower: string, base: string): boolean {
  // inputs.conf / outputs.conf are only unambiguous in Splunk forwarder dirs
  if (SIEM_INPUT_UNGATED.has(base) && inAnyDir(pathLower, SPLUNK_DIRS)) return true
  if (SIEM_INPUT_UNGATED.has(base) && inAnyDir(pathLower, SIEM_INPUT_DIRS)) return true

  if (!inAnyDir(pathLower, SIEM_INPUT_DIRS)) return false

  // Log source / forwarder configuration files in siem input dirs
  if (
    base.endsWith('.conf')  || base.endsWith('.yaml') || base.endsWith('.yml') ||
    base.endsWith('.json')  || base.endsWith('.ini')
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

export const SIEM_SECURITY_RULES: ReadonlyArray<{
  id: SiemSecurityRuleId
  severity: SiemSecuritySeverity
  description: string
  recommendation: string
  match: (pathLower: string, base: string) => boolean
}> = [
  {
    id: 'SPLUNK_DETECTION_CONFIG_DRIFT',
    severity: 'high',
    description: 'Splunk detection or correlation configuration changed — alert rules, saved searches, or automated response actions may have been modified.',
    recommendation:
      'Review savedsearches.conf for removed or disabled scheduled searches that generate security alerts; inspect alert_actions.conf for changes to email recipients, webhook URLs, or suppression windows that could silence notifications; audit correlationsearches.conf for disabled correlation searches in Splunk Enterprise Security; check transforms.conf for changes to threat-intel lookup tables that feed correlation rules; verify that any added scheduling windows or `max_concurrent` reductions do not create detection gaps; and confirm all changes correspond to documented tuning tickets rather than unauthorised modifications.',
    match: (p, b) => isSplunkDetectionConfig(p, b),
  },
  {
    id: 'ELASTIC_SIEM_RULE_DRIFT',
    severity: 'high',
    description: 'Elastic Security detection rule file changed — .ndjson rule bundle or detection rule configuration modified.',
    recommendation:
      'Export the current detection rule set from Kibana Security → Detection Rules and diff it against the committed version; identify any rules whose `enabled` field was set to false, whose `risk_score` was reduced, or whose `query` or `threshold` was loosened; review changes to exception lists referenced by rules for added entries that could suppress true-positive alerts; confirm that any new rules have undergone peer review; and validate that rule severity thresholds align with your incident response playbook tier definitions.',
    match: (p, b) => isElasticSiemRule(p, b),
  },
  {
    id: 'SENTINEL_ANALYTICS_DRIFT',
    severity: 'high',
    description: 'Microsoft Sentinel analytics rule or hunting query changed — detection logic or KQL query may have been modified.',
    recommendation:
      'Compare the committed analytics rule YAML/JSON against the version deployed in Azure Sentinel via the Analytics blade; check for changes to `enabled` status, `severity`, `queryFrequency`, `queryPeriod`, or `suppressionDuration` that could reduce detection coverage; review KQL query changes for relaxed filter conditions or added exclusions; validate that any modified hunting queries still cover the intended threat scenarios; and confirm that changes to entity mappings or alert detail templates are intentional and have been approved through your security change management process.',
    match: (p, b) => isSentinelAnalyticsConfig(p, b),
  },
  {
    id: 'OSQUERY_CONFIG_DRIFT',
    severity: 'high',
    description: 'osquery configuration or query pack changed — scheduled threat-detection queries or daemon configuration may have been altered.',
    recommendation:
      'Review osquery.conf for changes to schedule section that remove or extend intervals on security-critical queries (e.g., listening_ports, processes, logged_in_users, shell_history); inspect pack configuration files in the packs/ directory for disabled queries or loosened event_types filters; verify that any new queries added to the configuration do not introduce performance-impacting full-table scans on production hosts; check osquery.flags for changes to --allow_unsafe, --disable_events, or --disable_audit flags that could weaken the collection capability; and confirm that configuration changes were tested against osquery daemon performance limits.',
    match: (p, b) => isOsqueryConfig(p, b),
  },
  {
    id: 'SIEM_DETECTION_SUPPRESSION_DRIFT',
    severity: 'medium',
    description: 'SIEM alert suppression, exception list, or allowlist configuration changed — detection rules may have been silenced.',
    recommendation:
      'Audit every entry added to the exception or suppression configuration: a new suppression rule covering a broad IP range, username pattern, or process name can create a permanent monitoring blind spot; require that each suppression entry references a documented false-positive ticket with an expiry date; review wildcard patterns for overly permissive matches that could inadvertently suppress true-positive alerts; confirm that suppression changes were approved by a security team lead; and validate that exception lists are scoped to the minimum necessary specificity (prefer exact-value matches over regex wildcards).',
    match: (p, b) => isSiemSuppressionConfig(p, b),
  },
  {
    id: 'SOAR_PLAYBOOK_DRIFT',
    severity: 'medium',
    description: 'SOAR playbook or automated incident response configuration changed — automated remediation actions may have been altered.',
    recommendation:
      'Review changes to SOAR playbooks for modified action sequences that skip containment steps (e.g., removed "disable user account" or "block IP" actions); inspect changes to alert trigger conditions for raised thresholds that could delay automated response; audit integration script modifications in automation-*.py files for changed API endpoints or credential references; verify that any new playbook branches cover all required approval gates before destructive actions; and confirm that playbook version history in the SOAR platform matches the committed revision to detect out-of-band changes.',
    match: (p, b) => isSoarPlaybook(p, b),
  },
  {
    id: 'THREAT_INTEL_FEED_DRIFT',
    severity: 'medium',
    description: 'Threat intelligence platform configuration changed — MISP, OpenCTI, TAXII, or IOC feed settings may have been altered.',
    recommendation:
      'Review MISP configuration changes for modified event correlation settings, changed feed pull intervals, or altered sync filters that could cause indicators to stop flowing into downstream SIEM rules; inspect OpenCTI connector configuration for changed data source credentials, disabled connectors, or modified TLP classification settings; audit TAXII client configuration for changed collection URLs, polling intervals, or credential rotation; verify that any IOC allowlisting changes (marking indicators as false positives) are accompanied by documented evidence; and confirm that feed authentication credentials have been rotated and stored in a secrets manager rather than committed in plaintext.',
    match: (p, b) => isThreatIntelFeedConfig(p, b),
  },
  {
    id: 'SIEM_LOG_SOURCE_DRIFT',
    severity: 'low',
    description: 'SIEM data source or forwarder input configuration changed — log collection coverage may have changed.',
    recommendation:
      'Review Splunk inputs.conf changes for removed monitor stanzas, modified batch intervals, or changed sourcetype definitions that could cause events to stop indexing or be misclassified; inspect outputs.conf for changes to indexer target addresses that could redirect logs to an unauthorised indexer; verify that any new inputs added correspond to documented log source onboarding requests; confirm that removed inputs are intentionally decommissioned rather than accidentally deleted; and validate that changes to index targets send events to appropriately retention-configured indexes.',
    match: (p, b) => isSiemLogSourceConfig(p, b),
  },
]

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

const SEVERITY_PENALTIES: Record<SiemSecuritySeverity, { per: number; cap: number }> = {
  high:   { per: 15, cap: 45 },
  medium: { per: 8,  cap: 25 },
  low:    { per: 4,  cap: 15 },
}

function computeRiskScore(findings: SiemSecurityDriftFinding[]): number {
  let score = 0
  for (const f of findings) {
    const { per, cap } = SEVERITY_PENALTIES[f.severity]
    score += Math.min(f.matchCount * per, cap)
  }
  return Math.min(score, 100)
}

function computeRiskLevel(score: number): SiemSecurityRiskLevel {
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

export function scanSiemSecurityDrift(changedFiles: string[]): SiemSecurityDriftResult {
  const normalise = (p: string) => p.replace(/\\/g, '/').toLowerCase()

  const findings: SiemSecurityDriftFinding[] = []

  for (const rule of SIEM_SECURITY_RULES) {
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
  const ORDER: Record<SiemSecuritySeverity, number> = { high: 0, medium: 1, low: 2 }
  findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity])

  const riskScore   = computeRiskScore(findings)
  const riskLevel   = computeRiskLevel(riskScore)
  const highCount   = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount    = findings.filter((f) => f.severity === 'low').length

  const summary =
    findings.length === 0
      ? 'No SIEM or security analytics configuration drift detected.'
      : `${findings.length} SIEM security rule${findings.length === 1 ? '' : 's'} triggered ` +
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
