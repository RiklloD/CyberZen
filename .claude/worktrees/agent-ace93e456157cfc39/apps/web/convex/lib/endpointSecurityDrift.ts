// WS-95 — Endpoint Security & EDR Configuration Drift Detector.
//
// Analyses a list of changed file paths (from a push event) for modifications
// to endpoint security and EDR configuration: CrowdStrike Falcon agent and
// prevention policy configuration, SentinelOne agent/policy configuration,
// Microsoft Defender for Endpoint managed configuration, EDR/AV exclusion
// lists (attackers deliberately target exclusion paths), MDM device enrollment
// and compliance policy configuration (Jamf Pro, Microsoft Intune, SCCM),
// Carbon Black / Sophos endpoint security configuration, vulnerability scanner
// agent configuration (Nessus, OpenVAS, Qualys, Tenable), and Tanium / BigFix
// endpoint management configuration.
//
// Distinct from:
//   WS-67 (runtime security: Falco / OPA / Seccomp / AppArmor / fail2ban / auditd)
//   WS-69 (developer security tooling: SAST / SCA / secret scanning)
//   WS-74 (mobile app security: iOS entitlements / Android manifest)
//   WS-83 (config management: Ansible / Puppet / Chef / SaltStack)
//   WS-89 (OS hardening: sshd_config / sudoers / sysctl / PAM)

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
// Rule 1: CROWDSTRIKE_FALCON_DRIFT (high)
// ---------------------------------------------------------------------------
// CrowdStrike Falcon EDR agent and prevention policy configuration.
// Falcon prevention policy files control which attack techniques are blocked
// or detected — disabling policies creates silent blind spots in endpoint
// telemetry.

const CROWDSTRIKE_UNGATED = new Set([
  'falcon.cfg', 'falcon-sensor.cfg', 'falcon-agent.conf',
  'cs.conf', 'crowdstrike.conf', 'falcon.conf',
  'falcon-sensor.conf', 'falcon-prevention.json',
  'crowdstrike-policy.json', 'crowdstrike-config.json',
])

const CROWDSTRIKE_DIRS = [
  'crowdstrike/', 'falcon/', 'falcon-sensor/', 'cs-agent/',
  'crowdstrike-config/', 'falcon-config/', 'edr/crowdstrike/',
]

function isCrowdstrikeFalconConfig(path: string, base: string): boolean {
  if (CROWDSTRIKE_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (base.startsWith('crowdstrike-') || base.startsWith('falcon-')) {
    return /\.(conf|cfg|json|yaml|yml)$/.test(base)
  }

  return CROWDSTRIKE_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|json|yaml|yml|toml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 2: SENTINELONE_POLICY_DRIFT (high)
// ---------------------------------------------------------------------------
// SentinelOne agent and policy configuration.  Policy files govern detection
// engines, exclusions, and network quarantine — misconfigs can suppress
// detection or disable automatic remediation.

const SENTINELONE_UNGATED = new Set([
  'sentinelone.conf', 'sentinelone.json', 's1.conf',
  's1-agent.conf', 's1-policy.json', 'sentinelone-policy.json',
  'sentinelone-config.json', 'sentinelone-agent.conf',
])

const SENTINELONE_DIRS = [
  'sentinelone/', 's1/', 's1-agent/', 'sentinelone-config/',
  'edr/sentinelone/', 'sentinel-one/',
]

function isSentinelonePolicyConfig(path: string, base: string): boolean {
  if (SENTINELONE_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (base.startsWith('sentinelone-') || base.startsWith('s1-')) {
    return /\.(conf|cfg|json|yaml|yml)$/.test(base)
  }

  return SENTINELONE_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|json|yaml|yml|toml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 3: DEFENDER_ENDPOINT_DRIFT (high)
// ---------------------------------------------------------------------------
// Microsoft Defender for Endpoint (MDE) managed configuration.
// mdatp-managed.json controls cloud-delivered protection, tamper protection,
// and real-time scanning — managed config files deployed via MDM can override
// local settings, making them a high-value drift target.

const DEFENDER_UNGATED = new Set([
  'mdatp-managed.json', 'mdatp.conf', 'mdatp-config.json',
  'wdav-config.json', 'wdavcfg', 'defender-atp.json',
  'defender-policy.json', 'mde-config.json', 'mdatp-managed.yaml',
  'defender-for-endpoint.json',
])

const DEFENDER_DIRS = [
  'mdatp/', 'defender/', 'microsoft-defender/', 'mde/',
  'defender-config/', 'wdav/', 'microsoft-edr/',
]

function isDefenderEndpointConfig(path: string, base: string): boolean {
  if (DEFENDER_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (base.startsWith('mdatp-') || base.startsWith('defender-') || base.startsWith('mde-')) {
    return /\.(conf|cfg|json|yaml|yml)$/.test(base)
  }

  return DEFENDER_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|json|yaml|yml|toml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 4: EDR_EXCLUSION_LIST_DRIFT (high)
// ---------------------------------------------------------------------------
// EDR and antivirus exclusion lists.  Adversaries specifically target
// exclusion paths — adding a malware drop directory to the exclusion list
// prevents EDR from scanning or blocking it.  Any change to exclusion
// configuration warrants scrutiny.

const EXCLUSION_UNGATED = new Set([
  'edr-exclusions.json', 'av-exclusions.conf', 'defender-exclusions.json',
  'edr-exclusions.yaml', 'av-exclusions.json', 'security-exclusions.json',
  'exclusion-list.json', 'scan-exclusions.json', 'endpoint-exclusions.yaml',
  'av-exclusions.yaml', 'edr-exclusions.yml', 'av-whitelist.conf',
  'antivirus-exclusions.json', 'edr-whitelist.json',
])

const EXCLUSION_DIRS = [
  'edr-exclusions/', 'av-exclusions/', 'edr-config/', 'endpoint-security/',
  'av-config/', 'security-exclusions/', 'exclusions/',
]

function isEdrExclusionList(path: string, base: string): boolean {
  if (EXCLUSION_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('edr-exclusion') ||
    base.startsWith('av-exclusion') ||
    base.startsWith('defender-exclusion') ||
    base.startsWith('endpoint-exclusion') ||
    base.startsWith('scan-exclusion') ||
    base.startsWith('antivirus-exclusion')
  ) {
    return /\.(json|yaml|yml|conf|txt)$/.test(base)
  }

  return EXCLUSION_DIRS.some((d) => low.includes(d)) &&
    /\.(json|yaml|yml|conf|txt)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 5: MDM_DEVICE_POLICY_DRIFT (medium) — exported user contribution
// ---------------------------------------------------------------------------
// Determines whether a file configures an MDM (Mobile Device Management) or
// UEM (Unified Endpoint Management) device enrollment or compliance policy.
//
// Trade-offs to consider:
//   - .mobileconfig extension is globally unambiguous (Apple MDM profile)
//   - enrollment.json is too generic — require MDM directory context
//   - device-compliance.json could be anything — require MDM directory
//   - jamf.conf / jamf.json are specific enough to match ungated
//   - intune-policy.json / intune-compliance.json are unambiguous

const MDM_UNGATED_EXACT = new Set([
  'jamf.conf', 'jamf.json', 'jamf-config.json',
  'intune-policy.json', 'intune-compliance.json', 'intune-config.json',
  'sccm-config.xml', 'mecm-config.xml',
])

const MDM_DIRS = [
  'jamf/', 'intune/', 'mdm/', 'sccm/', 'jamfpro/',
  'microsoft-endpoint/', 'uem/', 'mdm-config/', 'device-management/',
]

export function isMdmDevicePolicyFile(path: string, base: string): boolean {
  // .mobileconfig extension is exclusively Apple MDM profiles
  if (base.endsWith('.mobileconfig')) return true

  if (MDM_UNGATED_EXACT.has(base)) return true

  const low = path.toLowerCase()

  // enrollment.json / device-policy.json / compliance.json are generic —
  // require MDM directory context
  if (
    (base === 'enrollment.json' ||
     base === 'device-policy.json' ||
     base === 'compliance.json' ||
     base === 'device-compliance.json' ||
     base === 'enrollment.xml') &&
    MDM_DIRS.some((d) => low.includes(d))
  ) {
    return true
  }

  if (
    base.startsWith('jamf-') ||
    base.startsWith('intune-') ||
    base.startsWith('mdm-') ||
    base.startsWith('sccm-') ||
    base.startsWith('mecm-')
  ) {
    return /\.(conf|cfg|json|yaml|yml|xml|mobileconfig|plist)$/.test(base)
  }

  return MDM_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|json|yaml|yml|xml|mobileconfig|plist)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 6: CARBON_BLACK_SOPHOS_DRIFT (medium)
// ---------------------------------------------------------------------------
// VMware Carbon Black and Sophos endpoint security agent configuration.
// Carbon Black Response / Defense stores event filtering and sensor
// configuration; Sophos SAVdi scanner configuration controls real-time
// protection behaviour.

const CBSOPHOS_UNGATED = new Set([
  'cbagent.cfg', 'cb.conf', 'cbrespond.conf', 'cbdaemon.conf',
  'carbon_black.conf', 'carbon-black.conf', 'cbc.conf',
  'sophos.conf', 'savdi.conf', 'sav-linux.conf',
  'sep.conf', 'symantec-endpoint.conf',
])

const CBSOPHOS_DIRS = [
  'carbon-black/', 'carbonblack/', 'cb-defense/', 'cb-response/',
  'cb-protect/', 'sophos/', 'symantec/', 'sep/',
]

function isCarbonBlackSophosConfig(path: string, base: string): boolean {
  if (CBSOPHOS_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('carbonblack-') ||
    base.startsWith('cb-defense-') ||
    base.startsWith('cb-response-') ||
    base.startsWith('sophos-') ||
    base.startsWith('symantec-')
  ) {
    return /\.(conf|cfg|json|yaml|yml)$/.test(base)
  }

  return CBSOPHOS_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|json|yaml|yml|xml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 7: VULNERABILITY_SCANNER_DRIFT (medium)
// ---------------------------------------------------------------------------
// Vulnerability scanner agent configuration.  Nessus, OpenVAS/GVM, Qualys,
// and Tenable agent configs control scan targets, credentials, and reporting
// — misconfigs can suppress scan results or expose scan credentials.

const VULNSCAN_UNGATED = new Set([
  'nessus.conf', 'nessud.conf', 'nessusd.conf',
  'openvas.conf', 'openvassd.conf', 'gvm.conf', 'gvmd.conf', 'openvasmd.conf',
  'qualys-cloud-agent.conf', 'qualys-agent.conf',
  'tenable-agent.conf', 'tenable.conf', 'tenablesc.conf',
  'rapid7-agent.conf', 'nexpose.conf',
])

const VULNSCAN_DIRS = [
  'nessus/', 'openvas/', 'gvm/', 'qualys/', 'tenable/',
  'vulnerability-scanner/', 'vuln-scan/', 'rapid7/', 'nexpose/',
]

function isVulnerabilityScannerConfig(path: string, base: string): boolean {
  if (VULNSCAN_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('nessus-') ||
    base.startsWith('openvas-') ||
    base.startsWith('qualys-') ||
    base.startsWith('tenable-') ||
    base.startsWith('rapid7-')
  ) {
    return /\.(conf|cfg|json|yaml|yml|xml)$/.test(base)
  }

  return VULNSCAN_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|json|yaml|yml|xml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 8: TANIUM_ENDPOINT_MGMT_DRIFT (low)
// ---------------------------------------------------------------------------
// Tanium and IBM BigFix endpoint management configuration.  These platforms
// distribute and enforce endpoint policies — misconfigs can disable patch
// management, disable endpoint telemetry collection, or expose management
// credentials.

const TANIUM_UNGATED = new Set([
  'tanium.conf', 'tanium-client.conf', 'tanium-config.json', 'taniumclient.conf',
  'bigfix.conf', 'bigfix-config.json', 'besclient.conf', 'besclient.cfg',
  'manageengine.conf', 'me-agent.conf',
])

const TANIUM_DIRS = [
  'tanium/', 'bigfix/', 'manageengine/', 'endpoint-management/',
  'uem/', 'tanium-config/', 'bigfix-config/', 'ibm-bigfix/',
]

function isTaniumEndpointMgmtConfig(path: string, base: string): boolean {
  if (TANIUM_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('tanium-') ||
    base.startsWith('bigfix-') ||
    base.startsWith('manageengine-') ||
    base.startsWith('besclient-')
  ) {
    return /\.(conf|cfg|json|yaml|yml)$/.test(base)
  }

  return TANIUM_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|json|yaml|yml|xml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rules registry
// ---------------------------------------------------------------------------

type Severity = 'high' | 'medium' | 'low'

type EndpointSecRule = {
  id: string
  severity: Severity
  description: string
  recommendation: string
  match: (path: string, base: string) => boolean
}

const RULES: EndpointSecRule[] = [
  {
    id: 'CROWDSTRIKE_FALCON_DRIFT',
    severity: 'high',
    description: 'CrowdStrike Falcon EDR agent or prevention policy configuration modified.',
    recommendation: 'Verify prevention policy changes are authorised, ensure tamper protection is enabled, and confirm no detection engines have been disabled or exceptions added for sensitive paths.',
    match: isCrowdstrikeFalconConfig,
  },
  {
    id: 'SENTINELONE_POLICY_DRIFT',
    severity: 'high',
    description: 'SentinelOne EDR agent or policy configuration modified.',
    recommendation: 'Audit policy changes for disabled detection modes or new exclusions; verify agent configuration is centrally managed and not overridden locally.',
    match: isSentinelonePolicyConfig,
  },
  {
    id: 'DEFENDER_ENDPOINT_DRIFT',
    severity: 'high',
    description: 'Microsoft Defender for Endpoint managed configuration modified.',
    recommendation: 'Review mdatp-managed.json for disabled cloud protection, tamper protection, or real-time scanning; verify changes are deployed via approved MDM channels.',
    match: isDefenderEndpointConfig,
  },
  {
    id: 'EDR_EXCLUSION_LIST_DRIFT',
    severity: 'high',
    description: 'EDR or antivirus exclusion list modified.',
    recommendation: 'Carefully audit every added exclusion path — adversaries target exclusion lists to create scanning blind spots; remove unnecessary exclusions and require security team approval for all changes.',
    match: isEdrExclusionList,
  },
  {
    id: 'MDM_DEVICE_POLICY_DRIFT',
    severity: 'medium',
    description: 'MDM or UEM device enrollment or compliance policy configuration modified.',
    recommendation: 'Review .mobileconfig profiles and Intune/Jamf compliance policies for weakened security baselines, disabled encryption requirements, or permissive passcode policies.',
    match: (p, b) => isMdmDevicePolicyFile(p, b),
  },
  {
    id: 'CARBON_BLACK_SOPHOS_DRIFT',
    severity: 'medium',
    description: 'Carbon Black or Sophos endpoint security agent configuration modified.',
    recommendation: 'Verify Carbon Black sensor event filtering has not been relaxed, check Sophos real-time protection settings, and confirm agent credentials are not exposed in config files.',
    match: isCarbonBlackSophosConfig,
  },
  {
    id: 'VULNERABILITY_SCANNER_DRIFT',
    severity: 'medium',
    description: 'Vulnerability scanner agent configuration modified.',
    recommendation: 'Audit scan target subnets for scope creep, verify scanner credentials are stored in secrets management rather than config files, and ensure scan schedules have not been disabled.',
    match: isVulnerabilityScannerConfig,
  },
  {
    id: 'TANIUM_ENDPOINT_MGMT_DRIFT',
    severity: 'low',
    description: 'Tanium or IBM BigFix endpoint management configuration modified.',
    recommendation: 'Review endpoint management agent configuration for unauthorised policy changes, verify patch management schedules are intact, and rotate management credentials.',
    match: isTaniumEndpointMgmtConfig,
  },
]

// ---------------------------------------------------------------------------
// Scoring model (identical to all WS-60+ detectors)
// ---------------------------------------------------------------------------

const SEVERITY_PENALTY: Record<Severity, number> = { high: 15, medium: 8, low: 4 }
const SEVERITY_CAP:     Record<Severity, number> = { high: 45, medium: 25, low: 15 }

type EndpointSecRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

function computeRiskLevel(score: number): EndpointSecRiskLevel {
  if (score === 0)  return 'none'
  if (score < 15)   return 'low'
  if (score < 45)   return 'medium'
  if (score < 80)   return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export type EndpointSecFinding = {
  ruleId:         string
  severity:       Severity
  matchedPath:    string
  matchCount:     number
  description:    string
  recommendation: string
}

export type EndpointSecDriftResult = {
  riskScore:     number
  riskLevel:     EndpointSecRiskLevel
  totalFindings: number
  highCount:     number
  mediumCount:   number
  lowCount:      number
  findings:      EndpointSecFinding[]
  summary:       string
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

export function scanEndpointSecurityDrift(
  changedFiles: string[],
): EndpointSecDriftResult {
  const findings: EndpointSecFinding[] = []

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
      ? 'No endpoint security or EDR configuration changes detected.'
      : `${totalFindings} endpoint security configuration ${totalFindings === 1 ? 'file' : 'files'} modified (risk score ${score}/100).`

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
