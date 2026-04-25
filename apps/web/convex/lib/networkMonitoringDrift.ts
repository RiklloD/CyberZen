// WS-94 — Network Monitoring & SNMP Security Configuration Drift Detector.
//
// Analyses a list of changed file paths (from a push event) for modifications
// to network monitoring and SNMP security configuration: SNMP daemon community
// strings and v3 auth (snmpd.conf), Nagios/NRPE monitoring and remote command
// execution config (nagios.cfg, nrpe.cfg), Zabbix server/agent configuration
// (zabbix_server.conf, zabbix_agentd.conf), NetFlow/sFlow traffic analysis
// (pmacct.conf, ntopng.conf), LibreNMS/Oxidized NMS and network backup tool
// configuration, Netdata streaming and health configuration, SNMP trap
// receiver handling (snmptrapd.conf), and network probe/scanner configuration.
//
// Distinct from:
//   WS-71 (Prometheus / Alertmanager / Grafana / OTel observability)
//   WS-86 (Splunk / Elastic SIEM / security analytics)
//   WS-88 (BIND / Unbound / CoreDNS DNS server security)
//   WS-68 (iptables / nftables / UFW / firewalld perimeter)

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function normalise(raw: string): string {
  return raw.replace(/\\/g, '/').replace(/^\.\//, '')
}

const VENDOR_DIRS = [
  'node_modules/', 'vendor/', '.git/', 'dist/', 'build/', '.cache/',
  '.npm/', '.yarn/', '__pycache__/', '.venv/', 'venv/', 'target/',
]

function isVendorPath(p: string): boolean {
  return VENDOR_DIRS.some((v) => p.includes(v))
}

// ---------------------------------------------------------------------------
// Rule 1: SNMPD_DAEMON_DRIFT (high)
// ---------------------------------------------------------------------------
// SNMP daemon configuration.  snmpd.conf holds community strings (v1/v2c
// "passwords"), v3 auth credentials, and access control — a misconfigured
// "rocommunity public" grants read access to all OIDs on every monitored
// device.

const SNMPD_UNGATED = new Set([
  'snmpd.conf', 'snmp.conf', 'snmpd.conf.local', 'snmpd-v3.conf',
  'snmp-v3.conf', 'snmp.conf.local', 'snmpd-listen.conf',
  'snmpd.conf.d', 'snmp-access.conf', 'snmpd-access.conf',
])

const SNMPD_DIRS = [
  'snmp/', 'snmpd/', 'etc/snmp/', 'snmp-config/', 'monitoring/snmp/',
  'snmp-agent/', 'network-mgmt/',
]

const SNMPD_GATED_EXACT = new Set([
  'community.conf', 'users.conf', 'access.conf', 'mibs.conf',
])

function isSnmpdDaemonConfig(path: string, base: string): boolean {
  if (SNMPD_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (SNMPD_GATED_EXACT.has(base) && SNMPD_DIRS.some((d) => low.includes(d))) return true

  if (base.startsWith('snmpd-') || base.startsWith('snmp-config-')) {
    return /\.(conf|cfg|json|yaml|yml)$/.test(base)
  }

  return SNMPD_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|ini|yaml|yml|json)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 2: NAGIOS_NRPE_DRIFT (high)
// ---------------------------------------------------------------------------
// Nagios monitoring server and NRPE (Nagios Remote Plugin Executor) agent
// configuration.  NRPE misconfigurations (allowed_hosts=0.0.0.0/0, dont_blame_nrpe=1)
// enable remote command execution on every monitored host.

const NAGIOS_UNGATED = new Set([
  'nagios.cfg', 'nagios.conf', 'nagios3.cfg', 'nagios4.cfg',
  'nrpe.cfg', 'nrpe.conf', 'nrpe_local.cfg', 'nrpe-local.cfg',
  'icinga.cfg', 'icinga2.conf', 'icingaweb2.ini', 'icinga.conf',
  'nagios-commands.cfg',
])

const NAGIOS_DIRS = [
  'nagios/', 'nagios3/', 'nagios4/', 'nrpe/', 'icinga/', 'icinga2/',
  'nagios-config/', 'icinga-config/', 'etc/nagios/', 'etc/icinga/',
  'nagios-objects/', 'nagios3/conf.d/', 'nagios4/conf.d/',
]

const NAGIOS_GATED_EXACT = new Set([
  'objects.cfg', 'hosts.cfg', 'services.cfg', 'contacts.cfg',
  'timeperiods.cfg', 'commands.cfg', 'templates.cfg', 'localhost.cfg',
])

function isNagiosNrpeConfig(path: string, base: string): boolean {
  if (NAGIOS_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (NAGIOS_GATED_EXACT.has(base) && NAGIOS_DIRS.some((d) => low.includes(d))) return true

  if (base.startsWith('nagios-') || base.startsWith('nrpe-') || base.startsWith('icinga-')) {
    return /\.(cfg|conf|ini|yaml|yml|json)$/.test(base)
  }

  return NAGIOS_DIRS.some((d) => low.includes(d)) &&
    /\.(cfg|conf|ini|yaml|yml|json)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 3: ZABBIX_MONITORING_DRIFT (high)
// ---------------------------------------------------------------------------
// Zabbix server, proxy, and agent configuration.  The Zabbix agent can
// execute arbitrary commands on monitored hosts when AllowRoot=1 or
// UserParameter entries run unsanitised shell commands.

const ZABBIX_UNGATED = new Set([
  'zabbix_server.conf', 'zabbix_agentd.conf', 'zabbix_proxy.conf',
  'zabbix_agent.conf', 'zabbix_agent2.conf', 'zabbix.conf',
  'zabbix-server.conf', 'zabbix-agent.conf',
])

const ZABBIX_DIRS = [
  'zabbix/', 'zabbix-server/', 'zabbix-agent/', 'etc/zabbix/',
  'zabbix-config/', 'zabbix-proxy/', 'zabbix-agent2/',
]

function isZabbixMonitoringConfig(path: string, base: string): boolean {
  if (ZABBIX_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (base.startsWith('zabbix-') || base.startsWith('zabbix_')) {
    return /\.(conf|cfg|yaml|yml|json)$/.test(base)
  }

  return ZABBIX_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|yaml|yml|json)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 4: NETFLOW_ANALYSIS_DRIFT (high)
// ---------------------------------------------------------------------------
// NetFlow/IPFIX/sFlow traffic analysis and capture tool configuration.  These
// tools capture and store network traffic metadata including source/destination
// IPs, ports, and byte counts — misconfigs can expose sensitive traffic
// patterns or export data to unauthorised collectors.

const NETFLOW_UNGATED = new Set([
  'pmacct.conf', 'pmacctd.conf', 'nfdump.conf', 'ntopng.conf',
  'nprobe.conf', 'softflowd.conf', 'fprobe.conf', 'ipt-netflow.conf',
  'flowctl.conf', 'nfsen.conf', 'fastnetmon.conf', 'fastnetmon.lua',
  'sflowtool.conf', 'sflow.conf', 'netflow.conf',
])

const NETFLOW_DIRS = [
  'pmacct/', 'nfdump/', 'ntopng/', 'netflow/', 'nflow/', 'sflow/',
  'traffic-analysis/', 'flow-collector/', 'netflow-config/',
]

function isNetflowAnalysisConfig(path: string, base: string): boolean {
  if (NETFLOW_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('pmacct-') ||
    base.startsWith('ntopng-') ||
    base.startsWith('netflow-') ||
    base.startsWith('sflow-') ||
    base.startsWith('fastnetmon-')
  ) {
    return /\.(conf|cfg|lua|yaml|yml|json)$/.test(base)
  }

  return NETFLOW_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|lua|yaml|yml|json|toml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 5: LIBRENMS_OXIDIZED_DRIFT (medium) — exported user contribution
// ---------------------------------------------------------------------------
// Determines whether a file configures a network management system (NMS) or
// network device configuration backup tool.
//
// Trade-offs to consider:
//   - config.php is used by many PHP applications, so require librenms/ or
//     cacti/ directory context to avoid false positives
//   - oxidized.conf is globally unambiguous (Oxidized backup tool)
//   - Observium uses config.php too — gated on observium/ dir
//   - Generic NMS dirs with config extensions are medium confidence

const NMS_UNGATED = new Set([
  'oxidized.conf', 'oxidized.yaml', 'oxidized.yml',
  'netdisco.conf', 'netdisco.yml',
  'rancid.conf', 'rancid-run', '.rancid.conf',
])

const NMS_DIRS = [
  'librenms/', 'oxidized/', 'cacti/', 'observium/', 'nms/',
  'network-monitoring/', 'rancid/', 'netdisco/', 'network-mgmt/',
]

export function isNetworkNmsConfig(path: string, base: string): boolean {
  if (NMS_UNGATED.has(base)) return true

  const low = path.toLowerCase()

  // config.php is common — require NMS directory context
  if ((base === 'config.php' || base === 'config.custom.php' || base === 'settings.php') &&
      NMS_DIRS.some((d) => low.includes(d))) {
    return true
  }

  if (
    base.startsWith('librenms-') ||
    base.startsWith('oxidized-') ||
    base.startsWith('cacti-') ||
    base.startsWith('observium-') ||
    base.startsWith('rancid-')
  ) {
    return /\.(conf|cfg|yaml|yml|json|php)$/.test(base)
  }

  return NMS_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|yaml|yml|json|php|ini|toml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 6: NETDATA_STREAMING_DRIFT (medium)
// ---------------------------------------------------------------------------
// Netdata monitoring agent streaming and health alarm notification
// configuration.  Netdata streaming misconfigs can export all host metrics
// to unauthorised parent/proxy nodes.

const NETDATA_UNGATED = new Set([
  'netdata.conf', 'health_alarm_notify.conf', 'exporting.conf',
  'netdata-exporters.conf', 'go.d.conf', 'apps_groups.conf',
])

const NETDATA_DIRS = [
  'netdata/', '.netdata/', 'etc/netdata/', 'netdata-config/',
  'netdata-health/', 'netdata-exporting/',
]

const NETDATA_GATED_EXACT = new Set([
  'stream.conf', 'health.conf', 'python.d.conf', 'charts.d.conf',
  'node.d.conf', 'statsd.conf',
])

function isNetdataStreamingConfig(path: string, base: string): boolean {
  if (NETDATA_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (NETDATA_GATED_EXACT.has(base) && NETDATA_DIRS.some((d) => low.includes(d))) return true

  if (base.startsWith('netdata-') || base.startsWith('health-')) {
    return /\.(conf|cfg|yaml|yml|json)$/.test(base)
  }

  return NETDATA_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|yaml|yml|json|toml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 7: SNMP_TRAP_RECEIVER_DRIFT (medium)
// ---------------------------------------------------------------------------
// SNMP trap daemon and trap translator configuration.  Trap handlers are
// shell scripts executed on receipt of network traps — injection via crafted
// trap messages is a known attack vector.

const TRAP_UNGATED = new Set([
  'snmptrapd.conf', 'snmptt.conf', 'snmptt.ini',
  'trapd.conf', 'snmp-traps.conf', 'traphandle.conf',
  'snmptrapd-config.conf', 'trapd-config.conf',
])

const TRAP_DIRS = [
  'snmptrap/', 'snmptt/', 'traps/', 'snmp-traps/',
  'snmptrapd/', 'trap-handler/', 'snmp/traps/',
]

function isSnmpTrapReceiverConfig(path: string, base: string): boolean {
  if (TRAP_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (base.startsWith('snmptrapd-') || base.startsWith('snmptt-') || base.startsWith('trap-')) {
    return /\.(conf|cfg|ini|yaml|yml|json)$/.test(base)
  }

  return TRAP_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|ini|yaml|yml|json|pl|sh)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 8: NETWORK_PROBE_CONFIG_DRIFT (low)
// ---------------------------------------------------------------------------
// Network scanner and probe tool configuration.  Scanner configs identify
// internal subnet targets and authorised scanning schedules — exposure can
// aid attacker reconnaissance.

const PROBE_UNGATED = new Set([
  'masscan.conf', 'masscan.json', 'unicornscan.conf', 'zmap.conf',
  'nmap.conf', 'nmap.ini',
])

const PROBE_DIRS = [
  'nmap/', 'masscan/', 'netscan/', 'probe/', 'network-scan/',
  'scanner/', 'recon/', 'network-probe/',
]

function isNetworkProbeConfig(path: string, base: string): boolean {
  if (PROBE_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (base.startsWith('masscan-') || base.startsWith('nmap-config-') || base.startsWith('zmap-')) {
    return /\.(conf|cfg|json|yaml|yml|txt)$/.test(base)
  }

  return PROBE_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|yaml|yml|json|nse|txt)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rules registry
// ---------------------------------------------------------------------------

type Severity = 'high' | 'medium' | 'low'

type NetworkMonitoringRule = {
  id: string
  severity: Severity
  description: string
  recommendation: string
  match: (path: string, base: string) => boolean
}

const RULES: NetworkMonitoringRule[] = [
  {
    id: 'SNMPD_DAEMON_DRIFT',
    severity: 'high',
    description: 'SNMP daemon configuration modified.',
    recommendation: 'Remove default community strings (public/private), migrate to SNMPv3 with auth+encryption, restrict access via VACM to authorised management subnets only.',
    match: isSnmpdDaemonConfig,
  },
  {
    id: 'NAGIOS_NRPE_DRIFT',
    severity: 'high',
    description: 'Nagios monitoring server or NRPE agent configuration modified.',
    recommendation: 'Audit nrpe.cfg for dont_blame_nrpe=1 and overly permissive allowed_hosts; restrict check commands to safe read-only operations; enable TLS for NRPE transport.',
    match: isNagiosNrpeConfig,
  },
  {
    id: 'ZABBIX_MONITORING_DRIFT',
    severity: 'high',
    description: 'Zabbix server, proxy, or agent configuration modified.',
    recommendation: 'Review UserParameter entries for shell injection, set AllowRoot=0, restrict Zabbix agent network source to server/proxy IPs only, enable TLS PSK for agent connections.',
    match: isZabbixMonitoringConfig,
  },
  {
    id: 'NETFLOW_ANALYSIS_DRIFT',
    severity: 'high',
    description: 'NetFlow, IPFIX, or sFlow traffic analysis configuration modified.',
    recommendation: 'Ensure flow export targets are restricted to authorised collectors, verify sampling rates do not disable capture, and protect SNMP community strings used for device polling.',
    match: isNetflowAnalysisConfig,
  },
  {
    id: 'LIBRENMS_OXIDIZED_DRIFT',
    severity: 'medium',
    description: 'Network management system (LibreNMS, Oxidized, Cacti) configuration modified.',
    recommendation: 'Review Oxidized/RANCID credential storage for device access (should use secrets management), restrict API keys, and verify backup file permissions prevent credential leakage.',
    match: (p, b) => isNetworkNmsConfig(p, b),
  },
  {
    id: 'NETDATA_STREAMING_DRIFT',
    severity: 'medium',
    description: 'Netdata monitoring agent streaming or health notification configuration modified.',
    recommendation: 'Ensure stream.conf restricts parent node connections to authorised IPs, verify API key rotation, and review alarm notification channels for credential exposure.',
    match: isNetdataStreamingConfig,
  },
  {
    id: 'SNMP_TRAP_RECEIVER_DRIFT',
    severity: 'medium',
    description: 'SNMP trap daemon or trap translator configuration modified.',
    recommendation: 'Review trap handler scripts for injection vulnerabilities, restrict trap sources to known device IPs, and validate SNMPTT format strings to prevent command injection.',
    match: isSnmpTrapReceiverConfig,
  },
  {
    id: 'NETWORK_PROBE_CONFIG_DRIFT',
    severity: 'low',
    description: 'Network scanner or probe tool configuration modified.',
    recommendation: 'Verify scanner target subnets are restricted to authorised test ranges, ensure scanning schedules are approved, and remove hardcoded credentials from scan profiles.',
    match: isNetworkProbeConfig,
  },
]

// ---------------------------------------------------------------------------
// Scoring model (identical to all WS-60+ detectors)
// ---------------------------------------------------------------------------

const SEVERITY_PENALTY: Record<Severity, number> = { high: 15, medium: 8, low: 4 }
const SEVERITY_CAP:     Record<Severity, number> = { high: 45, medium: 25, low: 15 }

type NetworkMonitoringRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

function computeRiskLevel(score: number): NetworkMonitoringRiskLevel {
  if (score === 0)  return 'none'
  if (score < 15)   return 'low'
  if (score < 45)   return 'medium'
  if (score < 80)   return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export type NetworkMonitoringFinding = {
  ruleId:         string
  severity:       Severity
  matchedPath:    string
  matchCount:     number
  description:    string
  recommendation: string
}

export type NetworkMonitoringDriftResult = {
  riskScore:     number
  riskLevel:     NetworkMonitoringRiskLevel
  totalFindings: number
  highCount:     number
  mediumCount:   number
  lowCount:      number
  findings:      NetworkMonitoringFinding[]
  summary:       string
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

export function scanNetworkMonitoringDrift(
  changedFiles: string[],
): NetworkMonitoringDriftResult {
  const findings: NetworkMonitoringFinding[] = []

  for (const rule of RULES) {
    let firstPath  = ''
    let matchCount = 0

    for (const raw of changedFiles) {
      const path = normalise(raw)
      if (isVendorPath(path)) continue
      const base = path.split('/').pop() ?? ''
      if (rule.match(path, base)) {
        matchCount++
        if (matchCount === 1) firstPath = path
      }
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

  const grouped = { high: 0, medium: 0, low: 0 }
  for (const f of findings) grouped[f.severity]++

  let score = 0
  for (const sev of ['high', 'medium', 'low'] as Severity[]) {
    score += Math.min(grouped[sev] * SEVERITY_PENALTY[sev], SEVERITY_CAP[sev])
  }
  score = Math.min(score, 100)

  const riskLevel     = computeRiskLevel(score)
  const totalFindings = findings.length

  const summary =
    totalFindings === 0
      ? 'No network monitoring or SNMP security configuration changes detected.'
      : `${totalFindings} network monitoring/SNMP security configuration ${totalFindings === 1 ? 'file' : 'files'} modified (risk score ${score}/100).`

  return {
    riskScore:   score,
    riskLevel,
    totalFindings,
    highCount:   grouped.high,
    mediumCount: grouped.medium,
    lowCount:    grouped.low,
    findings,
    summary,
  }
}
