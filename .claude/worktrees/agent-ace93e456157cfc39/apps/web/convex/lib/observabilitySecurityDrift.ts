// WS-71 — Observability & Security Monitoring Configuration Drift Detector:
// pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to observability and security monitoring configuration files. This scanner
// focuses on the *observability plane* — the configs that govern how security
// events are collected, routed, alerted, and retained. Drift here means
// attacks go undetected even while the security control plane functions
// correctly.
//
// DISTINCT from:
//   WS-15  complianceHardening       — Splunk/Elastic SIEM *push* integrations
//                                      (the connector sending data out); WS-71
//                                      covers the pipeline itself (Fluentd/
//                                      Logstash/Vector) that *collects* logs
//   WS-62  cloudSecurityDriftResults — cloud audit logging configs (CloudTrail/
//                                      Stackdriver) managed by IaC; WS-71 covers
//                                      the CloudWatch *alarm* layer that fires
//                                      on those logs, and the on-prem log pipeline
//   WS-67  runtimeSecurityDriftResults — auditd event collection (kernel syscall
//                                        auditing); WS-71 covers what happens to
//                                        those log streams downstream
//
// WS-71 vs WS-15: WS-15 wires Splunk/Elastic endpoints for alert *delivery*.
//   WS-71 detects drift in Prometheus/Alertmanager *rules* and Fluentd/Logstash
//   *pipeline configs* — the collection-to-routing layer.
//
// WS-71 vs WS-67: WS-67 detects changes to auditd.conf/rules (the kernel
//   audit source). WS-71 detects changes to the log shipper (filebeat.yml,
//   fluent.conf) that forwards those events, and the alert routing config
//   (alertmanager.yml) that decides who gets paged.
//
// Covered rule groups (8 rules):
//
//   PROMETHEUS_ALERT_RULES_DRIFT   — Prometheus alerting rules and recording rules
//   ALERTMANAGER_CONFIG_DRIFT      — Alertmanager routing, inhibition, silences
//   LOG_PIPELINE_SECURITY_DRIFT    — Fluentd / Logstash / Vector / Filebeat configs
//   OTEL_COLLECTOR_DRIFT           — OpenTelemetry collector security configs
//   GRAFANA_SECURITY_DRIFT         — Grafana auth, alerting, and datasource configs
//   CLOUDWATCH_ALARM_DRIFT         — CloudWatch alarms and SNS notification configs
//   TRACING_SECURITY_DRIFT         — Jaeger / Tempo / Zipkin config   ← user contribution
//   LOG_RETENTION_POLICY_DRIFT     — logrotate / rsyslog / syslog retention configs
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Vendor directory exclusion applied to all paths.
//   • Same penalty/cap scoring model as WS-60–70 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (matchedPath + matchCount).
//   • prometheus.yml alone is not flagged — it is the scrape config, not the
//     alert rules. Alert rules live in separate *.rules.yml / alerts.yaml files
//     or in dedicated alerting/ subdirectories.
//   • alertmanager.yml / alertmanager.yaml are unambiguous exact names.
//   • fluent.conf / logstash.conf / vector.toml are unambiguous tool signals.
//   • grafana.ini is always flagged; grafana.yaml requires a grafana/ directory
//     context to avoid collisions with generic datasource YAML files.
//   • CloudWatch alarm configs gated on cloudwatch- prefix or cloudwatch/ dir
//     to avoid false positives from any generic alarms.json.
//   • Tracing configs (Jaeger/Tempo/Zipkin) gated to avoid WS-63 k8s overlap.
//
// Exports:
//   isTracingSecurityConfig        — user contribution point (see JSDoc below)
//   OBSERVABILITY_SECURITY_RULES   — readonly rule registry
//   scanObservabilitySecurityDrift — main scanner, returns ObservabilitySecurityDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ObservabilitySecurityRuleId =
  | 'PROMETHEUS_ALERT_RULES_DRIFT'
  | 'ALERTMANAGER_CONFIG_DRIFT'
  | 'LOG_PIPELINE_SECURITY_DRIFT'
  | 'OTEL_COLLECTOR_DRIFT'
  | 'GRAFANA_SECURITY_DRIFT'
  | 'CLOUDWATCH_ALARM_DRIFT'
  | 'TRACING_SECURITY_DRIFT'
  | 'LOG_RETENTION_POLICY_DRIFT'

export type ObservabilitySecuritySeverity = 'high' | 'medium' | 'low'
export type ObservabilitySecurityRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type ObservabilitySecurityDriftFinding = {
  ruleId: ObservabilitySecurityRuleId
  severity: ObservabilitySecuritySeverity
  matchedPath: string
  matchCount: number
  description: string
  recommendation: string
}

export type ObservabilitySecurityDriftResult = {
  riskScore: number
  riskLevel: ObservabilitySecurityRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: ObservabilitySecurityDriftFinding[]
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
// Detection helpers — PROMETHEUS_ALERT_RULES_DRIFT
// ---------------------------------------------------------------------------

const PROMETHEUS_ALERT_EXACT = new Set([
  'alerts.yml', 'alerts.yaml',
  'alert-rules.yml', 'alert-rules.yaml',
  'recording-rules.yml', 'recording-rules.yaml',
  'prometheus-rules.yml', 'prometheus-rules.yaml',
  'rules.yml', 'rules.yaml',
])

const PROMETHEUS_ALERT_DIRS = [
  'prometheus/', 'alerting/', 'alerts/', 'prometheus-rules/',
  'monitoring/rules/', 'observability/rules/',
]

function isPrometheusAlertRulesFile(pathLower: string, base: string): boolean {
  // prometheus.yml alone is the scrape config, not alert rules — skip it
  if (base === 'prometheus.yml' || base === 'prometheus.yaml') return false

  // Exact filenames that are always Prometheus alert/recording rules
  if (PROMETHEUS_ALERT_EXACT.has(base)) return true

  // Files in alerting/prometheus directories with .rules.yml or .rules.yaml
  if (base.endsWith('.rules.yml') || base.endsWith('.rules.yaml')) return true

  // In prometheus/alerting directories, any .yml/.yaml is relevant
  for (const dir of PROMETHEUS_ALERT_DIRS) {
    if (pathLower.includes(dir) &&
        (base.endsWith('.yml') || base.endsWith('.yaml') || base.endsWith('.json'))) {
      return true
    }
  }
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — ALERTMANAGER_CONFIG_DRIFT
// ---------------------------------------------------------------------------

const ALERTMANAGER_EXACT = new Set([
  'alertmanager.yml', 'alertmanager.yaml',
  'alertmanager-config.yml', 'alertmanager-config.yaml',
  'alertmanager.json',
])

const ALERTMANAGER_DIRS = ['alertmanager/', 'etc/alertmanager/', 'alertmanager-config/']

function isAlertmanagerConfigFile(pathLower: string, base: string): boolean {
  if (ALERTMANAGER_EXACT.has(base)) return true
  for (const dir of ALERTMANAGER_DIRS) {
    if (pathLower.includes(dir) &&
        (base.endsWith('.yml') || base.endsWith('.yaml') || base.endsWith('.json'))) {
      return true
    }
  }
  if (base.startsWith('alertmanager-')) return true
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — LOG_PIPELINE_SECURITY_DRIFT
// ---------------------------------------------------------------------------

const LOG_PIPELINE_EXACT = new Set([
  // Fluentd / Fluent Bit
  'fluent.conf', 'fluentd.conf', 'fluent-bit.conf',
  'fluent-bit.yaml', 'fluent-bit.yml',
  'fluentbit.conf', 'fluentbit.yaml',
  'td-agent.conf',                               // Fluentd legacy
  // Logstash
  'logstash.conf', 'logstash.yml', 'logstash.yaml',
  'logstash-sample.conf',
  // Vector
  'vector.toml', 'vector.yaml', 'vector.yml',
  // Filebeat / Beats
  'filebeat.yml', 'filebeat.yaml',
  'metricbeat.yml', 'metricbeat.yaml',
  'auditbeat.yml', 'auditbeat.yaml',
  'heartbeat.yml', 'heartbeat.yaml',
])

const LOG_PIPELINE_DIRS = [
  'fluentd/', 'fluent/', 'fluent-bit/', 'fluentbit/',
  'logstash/', 'logstash/pipeline/', 'logstash/config/',
  'vector/', 'filebeat/', 'beats/', 'log-pipeline/', 'logging/pipeline/',
]

function isLogPipelineFile(pathLower: string, base: string): boolean {
  if (LOG_PIPELINE_EXACT.has(base)) return true
  for (const dir of LOG_PIPELINE_DIRS) {
    if (pathLower.includes(dir)) return true
  }
  // fluentd/logstash/vector prefixed configs
  if (base.startsWith('fluentd-') || base.startsWith('fluent-bit-') ||
      base.startsWith('logstash-') || base.startsWith('vector-') ||
      base.startsWith('filebeat-')) {
    return true
  }
  // Logstash pipeline configs in logstash/ dirs are .conf files
  if (pathLower.includes('logstash') && base.endsWith('.conf')) return true
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — OTEL_COLLECTOR_DRIFT
// ---------------------------------------------------------------------------

const OTEL_UNGATED_EXACT = new Set([
  'otel-collector.yaml', 'otel-collector.yml',
  'otelcol.yaml', 'otelcol.yml',
  'opentelemetry-collector.yaml', 'opentelemetry-collector.yml',
  'otel-config.yaml', 'otel-config.yml',
  'otelcol-config.yaml', 'otelcol-config.yml',
])

const OTEL_DIRS = ['otel/', 'opentelemetry/', 'observability/otel/', 'otelcol/']

function isOtelCollectorFile(pathLower: string, base: string): boolean {
  if (OTEL_UNGATED_EXACT.has(base)) return true
  for (const dir of OTEL_DIRS) {
    if (pathLower.includes(dir) &&
        (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json') || base.endsWith('.toml'))) {
      return true
    }
  }
  if (base.startsWith('otel-') || base.startsWith('otelcol-')) return true
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — GRAFANA_SECURITY_DRIFT
// ---------------------------------------------------------------------------

const GRAFANA_UNGATED_EXACT = new Set([
  'grafana.ini',                                 // always unambiguous
  'grafana-datasources.yaml', 'grafana-datasources.yml',
  'grafana-datasources.json',
  'grafana-auth.yaml', 'grafana-auth.yml',
])

const GRAFANA_DIRS = [
  'grafana/', 'grafana/provisioning/', 'grafana/config/',
  'monitoring/grafana/', 'observability/grafana/',
]

function isGrafanaSecurityFile(pathLower: string, base: string): boolean {
  if (GRAFANA_UNGATED_EXACT.has(base)) return true
  for (const dir of GRAFANA_DIRS) {
    if (pathLower.includes(dir) &&
        (base.endsWith('.ini') || base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json'))) {
      return true
    }
  }
  if (base.startsWith('grafana-')) return true
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — CLOUDWATCH_ALARM_DRIFT
// ---------------------------------------------------------------------------

const CLOUDWATCH_EXACT = new Set([
  'cloudwatch-alarms.json', 'cloudwatch-alarms.yaml', 'cloudwatch-alarms.yml',
  'cloudwatch.config', 'cloudwatch-config.json',
  'cloudwatch-agent.json', 'cloudwatch-agent.toml',
  'monitoring-alarms.json', 'monitoring-alarms.yaml',
])

const CLOUDWATCH_DIRS = [
  'cloudwatch/', 'cloudwatch-alarms/', 'monitoring/alarms/', 'aws/cloudwatch/',
]

function isCloudWatchAlarmFile(pathLower: string, base: string): boolean {
  if (CLOUDWATCH_EXACT.has(base)) return true
  for (const dir of CLOUDWATCH_DIRS) {
    if (pathLower.includes(dir) &&
        (base.endsWith('.json') || base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.toml') || base.endsWith('.config'))) {
      return true
    }
  }
  if (base.startsWith('cloudwatch-') || base.startsWith('cw-alarm')) return true
  return false
}

// ---------------------------------------------------------------------------
// TRACING_SECURITY_DRIFT — user contribution point
// ---------------------------------------------------------------------------

/**
 * isTracingSecurityConfig — determines whether a file path is a distributed
 * tracing backend security configuration that is NOT already covered by:
 *   - WS-63 (containerHardeningDrift): Kubernetes deployments OF tracing
 *     services (e.g., a Jaeger Deployment manifest, Helm chart for Tempo)
 *   - WS-62 (cloudSecurityDriftResults): Cloud-native tracing configs managed
 *     as Terraform/Pulumi IaC resources
 *
 * Target files: Jaeger collector and agent configs, Grafana Tempo configs,
 * Zipkin configs, and OpenZipkin configs that control *how* tracing data is
 * authenticated, stored, and exported — not the k8s deployment manifests.
 *
 * Core ambiguity: "jaeger.yaml" and "tempo.yaml" can be:
 *   (a) A Jaeger/Tempo *backend configuration* (auth, storage, TLS) — flag ✓
 *   (b) A Kubernetes *deployment manifest* for Jaeger/Tempo — skip (WS-63)
 *   (c) A Helm values override for the Jaeger/Tempo chart — skip (WS-63)
 *
 * Design trade-offs to consider:
 *
 *   (a) k8s/helm exclusion: files inside k8s/, kubernetes/, kustomize/, helm/,
 *       charts/ directories should be skipped here (WS-63 covers them). The
 *       same jaeger.yaml in a config/ or tracing/ directory should be flagged.
 *
 *   (b) IaC exclusion: files inside terraform/, pulumi/, cdk/, cloudformation/
 *       directories should be skipped (WS-62 covers cloud-layer resources).
 *
 *   (c) Exact filename signals: jaeger.yaml / jaeger-config.yaml / tempo.yaml /
 *       tempo-config.yaml / zipkin.yaml / zipkin-config.yaml are strong signals
 *       when outside k8s/helm/IaC directories.
 *
 *   (d) Tracing directory context: files inside jaeger/, tempo/, tracing/,
 *       observability/ directories with .yaml/.yml/.toml/.json extensions are
 *       likely tracing backend configs regardless of exact filename.
 *
 * Implement to return true for tracing backend security configuration files
 * and false for k8s/helm deployment manifests or IaC-managed resources.
 */
export function isTracingSecurityConfig(pathLower: string): boolean {
  const base = pathLower.split('/').at(-1) ?? pathLower
  const ext  = base.includes('.') ? `.${base.split('.').at(-1)}` : ''

  // k8s manifest directories — skip (WS-63 covers these)
  const K8S_DIRS = ['k8s/', 'kubernetes/', 'kustomize/', 'helm/', 'charts/', 'manifests/']
  for (const dir of K8S_DIRS) {
    if (pathLower.includes(dir)) return false
  }

  // IaC directories — skip (WS-62 covers cloud-layer resources)
  const IAC_DIRS = ['terraform/', 'pulumi/', 'cdk/', 'cloudformation/', 'bicep/']
  for (const dir of IAC_DIRS) {
    if (pathLower.includes(dir)) return false
  }

  // Canonical exact filenames — always flag when outside k8s/IaC dirs
  const TRACING_EXACT = new Set([
    'jaeger.yaml', 'jaeger.yml', 'jaeger-config.yaml', 'jaeger-config.yml',
    'jaeger-agent.yaml', 'jaeger-collector.yaml',
    'tempo.yaml', 'tempo.yml', 'tempo-config.yaml', 'tempo-config.yml',
    'zipkin.yaml', 'zipkin.yml', 'zipkin-config.yaml', 'zipkin-config.yml',
    'zipkin-server.yaml',
    'otel-tracing.yaml', 'otel-tracing.yml',
  ])
  if (TRACING_EXACT.has(base)) return true

  // Tracing-backend prefix patterns
  if (base.startsWith('jaeger-') || base.startsWith('tempo-') || base.startsWith('zipkin-')) {
    if (ext === '.yaml' || ext === '.yml' || ext === '.json' || ext === '.toml') return true
  }

  // Tracing directory context
  const TRACING_DIRS = ['jaeger/', 'tempo/', 'tracing/', 'distributed-tracing/', 'zipkin/', 'opentracing/']
  for (const dir of TRACING_DIRS) {
    if (pathLower.includes(dir) &&
        (ext === '.yaml' || ext === '.yml' || ext === '.toml' || ext === '.json' || ext === '.conf')) {
      return true
    }
  }

  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — LOG_RETENTION_POLICY_DRIFT
// ---------------------------------------------------------------------------

const LOG_RETENTION_EXACT = new Set([
  'logrotate.conf', 'logrotate.d',
  'rsyslog.conf', 'syslog.conf', 'syslog-ng.conf',
  'journald.conf', 'journal.conf',
  'log-retention.yaml', 'log-retention.yml', 'log-retention.json',
  'log-policy.yaml', 'log-policy.yml',
])

const LOG_RETENTION_DIRS = [
  'etc/logrotate.d/', 'logrotate.d/', 'etc/rsyslog.d/', 'rsyslog.d/',
  'log-retention/', 'log-policy/',
]

function isLogRetentionFile(pathLower: string, base: string): boolean {
  if (LOG_RETENTION_EXACT.has(base)) return true
  for (const dir of LOG_RETENTION_DIRS) {
    if (pathLower.includes(dir)) return true
  }
  if (base.startsWith('log-retention') || base.startsWith('log-policy') || base.startsWith('rsyslog-')) return true
  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

type ObservabilitySecurityRule = {
  id: ObservabilitySecurityRuleId
  severity: ObservabilitySecuritySeverity
  description: string
  recommendation: string
  matches: (pathLower: string, base: string, ext: string) => boolean
}

export const OBSERVABILITY_SECURITY_RULES: readonly ObservabilitySecurityRule[] = [
  {
    id: 'PROMETHEUS_ALERT_RULES_DRIFT',
    severity: 'high',
    description: 'Prometheus alerting or recording rules files were modified. Changes can silence security-critical alerts (authentication failures, rate limit breaches, privilege escalation attempts), leaving incidents undetected.',
    recommendation: 'Review whether any alert thresholds were raised, expressions changed, or security-relevant alert rules were removed. Alert rule changes affecting production monitoring should require a security review before merge.',
    matches: (p, b) => isPrometheusAlertRulesFile(p, b),
  },
  {
    id: 'ALERTMANAGER_CONFIG_DRIFT',
    severity: 'high',
    description: 'Alertmanager routing, inhibition, or silence configuration was modified. Changes can route security alerts to the wrong receiver, introduce perpetual silences, or create inhibition rules that suppress critical security notifications.',
    recommendation: 'Audit whether any new silence rules were added with broad matchers, inhibition rules were added that could suppress security alerts, or alert routing was changed to bypass on-call channels. Alertmanager config changes should be reviewed by the SOC or security team.',
    matches: (p, b) => isAlertmanagerConfigFile(p, b),
  },
  {
    id: 'LOG_PIPELINE_SECURITY_DRIFT',
    severity: 'high',
    description: 'Log collection pipeline configuration files (Fluentd, Logstash, Vector, Filebeat) were modified. Changes can redirect, drop, or filter security-critical log streams before they reach the SIEM, defeating the audit logging infrastructure.',
    recommendation: 'Verify that no log sources were removed, filter rules were not added that exclude security events (authentication, authorization, audit), and output destinations were not changed to unmonitored targets. Log pipeline changes should be reviewed alongside SIEM ingestion metrics.',
    matches: (p, b) => isLogPipelineFile(p, b),
  },
  {
    id: 'OTEL_COLLECTOR_DRIFT',
    severity: 'medium',
    description: 'OpenTelemetry Collector configuration was modified. The OTEL Collector controls which telemetry (traces, metrics, logs) is exported and where — changes can exfiltrate sensitive trace data or drop security-relevant spans.',
    recommendation: 'Confirm that exporter endpoints have not been changed to untrusted destinations, TLS settings for exporters are intact, and no processors were added that redact or drop security-relevant attributes from traces.',
    matches: (p, b) => isOtelCollectorFile(p, b),
  },
  {
    id: 'GRAFANA_SECURITY_DRIFT',
    severity: 'medium',
    description: 'Grafana authentication, alert notification, or datasource configuration was modified. Grafana auth bypass is a well-known attack vector; alert channel changes can silence SOC notifications without affecting dashboard visibility.',
    recommendation: 'Review whether auth.anonymous was enabled, admin credentials changed, alert notification channels removed or redirected, or datasources were added pointing to uncontrolled data sources. Grafana config changes should be tested in staging before production promotion.',
    matches: (p, b) => isGrafanaSecurityFile(p, b),
  },
  {
    id: 'CLOUDWATCH_ALARM_DRIFT',
    severity: 'medium',
    description: 'CloudWatch alarm or CloudWatch Agent configuration was modified. CloudTrail-backed CloudWatch alarms are the primary detection mechanism for unauthorized AWS API calls — alarm threshold or action changes can create blind spots.',
    recommendation: 'Verify that alarm thresholds were not raised beyond detection sensitivity, SNS topics still point to the correct notification targets, and CloudWatch Agent collectors were not modified to exclude security-relevant log groups.',
    matches: (p, b) => isCloudWatchAlarmFile(p, b),
  },
  {
    id: 'TRACING_SECURITY_DRIFT',
    severity: 'medium',
    description: 'Distributed tracing backend configuration (Jaeger, Grafana Tempo, Zipkin) was modified. Tracing configs control authentication, storage backend, and data retention — changes can expose sensitive distributed request traces or break the tracing security boundary.',
    recommendation: 'Confirm that backend authentication was not weakened, storage retention was not shortened to defeat forensic investigation, and trace sampling rates were not set to zero for security-critical services. Tracing config changes should be reviewed alongside the service mesh security policy.',
    matches: (p) => isTracingSecurityConfig(p),
  },
  {
    id: 'LOG_RETENTION_POLICY_DRIFT',
    severity: 'low',
    description: 'Log rotation, retention, or syslog configuration was modified. If retention periods are shortened or log files are rotated more aggressively, forensic evidence of security incidents may be destroyed before investigation.',
    recommendation: 'Verify that log retention periods were not reduced below compliance minimums (typically 90 days for SOC 2, 1 year for PCI-DSS), and that rotation schedules do not purge logs before they are shipped to a SIEM. Changes to logrotate or rsyslog configs should be reviewed by the compliance team.',
    matches: (p, b) => isLogRetentionFile(p, b),
  },
]

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

function penaltyFor(sev: ObservabilitySecuritySeverity, count: number): number {
  switch (sev) {
    case 'high':   return Math.min(count * HIGH_PENALTY_PER, HIGH_PENALTY_CAP)
    case 'medium': return Math.min(count * MED_PENALTY_PER,  MED_PENALTY_CAP)
    case 'low':    return Math.min(count * LOW_PENALTY_PER,  LOW_PENALTY_CAP)
  }
}

function toRiskLevel(score: number): ObservabilitySecurityRiskLevel {
  if (score === 0)  return 'none'
  if (score < 20)  return 'low'
  if (score < 45)  return 'medium'
  if (score < 70)  return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Main scanner
// ---------------------------------------------------------------------------

export function scanObservabilitySecurityDrift(filePaths: string[]): ObservabilitySecurityDriftResult {
  if (filePaths.length === 0) return emptyResult()

  const paths = filePaths
    .map((p) => p.replace(/\\/g, '/'))
    .filter((p) => {
      const lower = p.toLowerCase()
      return !VENDOR_DIRS.some((d) => lower.includes(d))
    })

  if (paths.length === 0) return emptyResult()

  const accumulated = new Map<ObservabilitySecurityRuleId, { firstPath: string; count: number }>()

  for (const path of paths) {
    const pathLower = path.toLowerCase()
    const base = pathLower.split('/').at(-1) ?? pathLower
    const ext  = base.includes('.') ? `.${base.split('.').at(-1)}` : ''

    for (const rule of OBSERVABILITY_SECURITY_RULES) {
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

  const SEVERITY_ORDER: Record<ObservabilitySecuritySeverity, number> = { high: 0, medium: 1, low: 2 }
  const findings: ObservabilitySecurityDriftFinding[] = []

  for (const rule of OBSERVABILITY_SECURITY_RULES) {
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

function emptyResult(): ObservabilitySecurityDriftResult {
  return {
    riskScore: 0, riskLevel: 'none',
    totalFindings: 0, highCount: 0, mediumCount: 0, lowCount: 0,
    findings: [], summary: 'No observability and security monitoring configuration drift detected.',
  }
}

function buildSummary(
  level: ObservabilitySecurityRiskLevel,
  high: number,
  medium: number,
  low: number,
  findings: ObservabilitySecurityDriftFinding[],
): string {
  if (level === 'none') return 'No observability and security monitoring configuration drift detected.'

  const parts: string[] = []
  if (high > 0)   parts.push(`${high} high`)
  if (medium > 0) parts.push(`${medium} medium`)
  if (low > 0)    parts.push(`${low} low`)

  const topRule  = findings[0]
  const topLabel = topRule ? topRule.ruleId.replace(/_/g, ' ').toLowerCase() : 'monitoring config'

  return `Observability and security monitoring drift detected (${parts.join(', ')} finding${findings.length !== 1 ? 's' : ''}). Most prominent: ${topLabel}. Review changes to ensure security alerts and log pipelines remain intact.`
}
