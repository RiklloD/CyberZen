// WS-93 — VoIP & Unified Communications Security Configuration Drift Detector.
//
// Analyses a list of changed file paths (from a push event) for modifications
// to VoIP/UC security configuration: Asterisk PBX, Kamailio/OpenSIPS SIP
// proxy, FreeSWITCH, SIP trunk provider credentials, Jitsi/TURN/WebRTC,
// VoIP gateway configs, web conferencing servers, and CDR/monitoring.
//
// Distinct from:
//   WS-70 (LDAP / PAM / Vault auth)
//   WS-68 (host-level iptables / nftables)
//   WS-66 (certificate PKI material)
//   WS-78 (MQTT / RabbitMQ / NATS messaging)

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
// Rule 1: ASTERISK_PBX_DRIFT (high)
// ---------------------------------------------------------------------------
// Asterisk PBX and FreePBX configuration.  sip.conf / pjsip.conf hold SIP
// peer passwords and trunk credentials; extensions.conf defines the dialplan;
// manager.conf controls AMI remote management access — all high-value targets
// for toll-fraud attackers.

const ASTERISK_UNGATED = new Set([
  'asterisk.conf', 'sip.conf', 'pjsip.conf', 'extensions.conf',
  'voicemail.conf', 'queues.conf', 'agents.conf', 'sip_notify.conf',
  'iax.conf', 'iax2.conf', 'extensions_custom.conf',
  'pjsip_wizard.conf', 'pjsip_notify.conf',
])

const ASTERISK_DIRS = [
  'asterisk/', '.asterisk/', 'freepbx/', 'etc/asterisk/',
  'asterisk-config/', 'pbx/', 'asterisk-conf/',
]

const ASTERISK_GATED_EXACT = new Set([
  'manager.conf', 'rtp.conf', 'modules.conf', 'logger.conf',
  'res_odbc.conf', 'cdr.conf', 'cel.conf',
])

function isAsteriskPbxConfig(path: string, base: string): boolean {
  if (ASTERISK_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (ASTERISK_GATED_EXACT.has(base) && ASTERISK_DIRS.some((d) => low.includes(d))) return true

  if (base.startsWith('asterisk-') || base.startsWith('freepbx-')) {
    return /\.(conf|cfg|json|yaml|yml)$/.test(base)
  }

  return ASTERISK_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|xml|json|yaml|yml|ael|lua)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 2: KAMAILIO_OPENSIPS_DRIFT (high)
// ---------------------------------------------------------------------------
// Kamailio and OpenSIPS SIP proxy/registrar configuration.  These files
// control SIP authentication, TLS termination, rate-limiting modules,
// and routing logic — misconfigs can disable authentication entirely.

const KAMAILIO_UNGATED = new Set([
  'kamailio.cfg', 'opensips.cfg', 'opensips.conf',
  'kamailio.json', 'opensips.json', 'kamailio.conf',
  'kamailio-local.cfg', 'opensips-local.cfg',
])

const KAMAILIO_DIRS = [
  'kamailio/', 'opensips/', 'sip-proxy/', 'sip-server/',
  'kamailio-config/', 'opensips-config/', 'sip-registrar/',
]

function isKamailioOpensipsConfig(path: string, base: string): boolean {
  if (KAMAILIO_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (base.startsWith('kamailio-') || base.startsWith('opensips-')) {
    return /\.(cfg|conf|json|yaml|yml|xml)$/.test(base)
  }

  return KAMAILIO_DIRS.some((d) => low.includes(d)) &&
    /\.(cfg|conf|json|yaml|yml|xml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 3: FREESWITCH_DRIFT (high)
// ---------------------------------------------------------------------------
// FreeSWITCH PBX configuration.  vars.xml contains shared secrets and
// credentials; SIP profiles define authentication; dialplan XML controls call
// routing and potential exposure.

const FREESWITCH_UNGATED = new Set([
  'freeswitch.xml', 'freeswitch.conf', 'switch.conf.xml',
  'freeswitch.json', 'freeswitch.yaml',
])

const FREESWITCH_DIRS = [
  'freeswitch/', 'etc/freeswitch/', 'freeswitch-config/',
  'fs-config/', 'freeswitch-conf/', '.freeswitch/',
]

const FREESWITCH_GATED_EXACT = new Set([
  'vars.xml', 'dialplan.xml', 'directory.xml',
  'sofia.conf.xml', 'event_socket.conf.xml',
])

function isFreeswitchConfig(path: string, base: string): boolean {
  if (FREESWITCH_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (FREESWITCH_GATED_EXACT.has(base) && FREESWITCH_DIRS.some((d) => low.includes(d))) return true

  if (base.startsWith('freeswitch-') || base.startsWith('fs-')) {
    return /\.(xml|conf|cfg|json|yaml|yml)$/.test(base)
  }

  return FREESWITCH_DIRS.some((d) => low.includes(d)) &&
    /\.(xml|conf|cfg|json|yaml|yml|lua)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 4: SIP_TRUNK_CREDENTIALS_DRIFT (high)
// ---------------------------------------------------------------------------
// SIP trunk provider credential and registration configuration.  These files
// store authentication usernames, passwords, and provider URIs for outbound
// PSTN calling — leakage leads directly to toll fraud.

const SIP_TRUNK_UNGATED = new Set([
  'sip-trunk.conf', 'sip-trunk.yaml', 'sip-trunk.yml', 'sip-trunk.json',
  'sip-provider.conf', 'sip-provider.json', 'sip-provider.yaml',
  'sip-credentials.conf', 'sip-credentials.json',
  'voip-credentials.conf', 'voip-credentials.json',
  'trunk-config.conf', 'trunk-config.yaml',
])

const SIP_TRUNK_DIRS = [
  'sip/', 'voip/', 'sip-trunk/', 'trunks/', 'sip-config/',
  'voip-config/', 'pbx-trunk/', 'sip-providers/', 'voip-trunks/',
]

const SIP_TRUNK_GATED_EXACT = new Set([
  'trunk.conf', 'trunk.json', 'trunk.yaml', 'trunk.yml',
  'provider.conf', 'provider.json',
])

function isSipTrunkCredentialsConfig(path: string, base: string): boolean {
  if (SIP_TRUNK_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (SIP_TRUNK_GATED_EXACT.has(base) && SIP_TRUNK_DIRS.some((d) => low.includes(d))) return true

  if (
    base.startsWith('sip-trunk-') ||
    base.startsWith('sip-provider-') ||
    base.startsWith('voip-trunk-') ||
    base.startsWith('voip-credentials-') ||
    base.startsWith('sip-credentials-')
  ) {
    return /\.(conf|cfg|json|yaml|yml)$/.test(base)
  }

  return SIP_TRUNK_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|json|yaml|yml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 5: JITSI_WEBRTC_DRIFT (medium)
// ---------------------------------------------------------------------------
// Jitsi Meet and TURN / STUN server configuration.  coturn.conf holds the
// shared TURN secret; jicofo.conf controls focus component auth; Jitsi
// Videobridge TLS/DTLS settings protect media encryption.

const JITSI_UNGATED = new Set([
  'jitsi-meet.conf', 'coturn.conf', 'turnserver.conf',
  'jicofo.conf', 'jvb.conf', 'jvb.yaml',
  'coturn.yaml', 'turn.conf', 'stun.conf',
  'prosody.cfg.lua',
])

const JITSI_DIRS = [
  'jitsi/', 'jitsi-meet/', 'coturn/', 'turn-server/',
  'jitsi-config/', 'webrtc/', 'turn/', 'stun/', 'jvb/',
]

function isJitsiWebrtcConfig(path: string, base: string): boolean {
  if (JITSI_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('jitsi-') ||
    base.startsWith('coturn-') ||
    base.startsWith('turn-') ||
    base.startsWith('stun-') ||
    base.startsWith('webrtc-')
  ) {
    return /\.(conf|cfg|json|yaml|yml|lua)$/.test(base)
  }

  return JITSI_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|json|yaml|yml|lua|toml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 6: VOIP_GATEWAY_DRIFT (medium)
// ---------------------------------------------------------------------------
// VoIP gateway and analogue-telephone-adapter configuration.  These devices
// bridge traditional PSTN to SIP and often hold provider credentials and
// routing tables.

const VOIP_GATEWAY_UNGATED = new Set([
  'voip-gateway.conf', 'voip-gateway.yaml', 'voip-gateway.yml',
  'voip-gateway.json', 'sip-gateway.conf', 'sip-gateway.json',
  'ata-config.conf', 'ata-config.json', 'ata-config.yaml',
])

const VOIP_GATEWAY_DIRS = [
  'voip-gateway/', 'gateway/', 'pbx-gateway/', 'sip-gateway/',
  'voip/', 'pbx/', 'ata/', 'voip-config/',
]

function isVoipGatewayConfig(path: string, base: string): boolean {
  if (VOIP_GATEWAY_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('voip-gateway-') ||
    base.startsWith('sip-gateway-') ||
    base.startsWith('sangoma-') ||
    base.startsWith('audiocodes-') ||
    base.startsWith('patton-') ||
    base.startsWith('grandstream-') ||
    base.startsWith('ata-')
  ) {
    return /\.(conf|cfg|json|yaml|yml|xml)$/.test(base)
  }

  return VOIP_GATEWAY_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|json|yaml|yml|xml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 7: WEBCONFERENCE_SECURITY_DRIFT (medium) — exported user contribution
// ---------------------------------------------------------------------------
// Determines whether a file configures a web conferencing or team
// communication server (Matrix/Synapse, BigBlueButton, Rocket.Chat, Element).
//
// Trade-offs to consider:
//   - homeserver.yaml is the canonical Matrix/Synapse config, but the base
//     name alone is ambiguous ("homeserver" could mean anything) — require a
//     matrix/ or synapse/ dir segment, OR check for the synapse.yaml name
//   - bigbluebutton.properties is unambiguous (globally unique format)
//   - synapse.yaml / synapse.conf are unambiguous (Synapse-specific)
//   - rocketchat.conf / rocket.chat.conf are unambiguous

const WEBCONF_DIRS = [
  'matrix/', 'synapse/', 'element/', 'bigbluebutton/', 'bbb/',
  'rocketchat/', 'rocket-chat/', 'nextcloud/', 'nextcloud-talk/',
  'mattermost/', 'mattermost-config/', 'webconference/', 'uc-config/',
]

const WEBCONF_UNGATED_EXACT = new Set([
  'bigbluebutton.properties', 'bbb-conf.conf', 'bbb-web.properties',
  'synapse.yaml', 'synapse.conf', 'synapse.json',
  'rocketchat.conf', 'rocket.chat.conf', 'rocketchat.yaml',
  'mattermost.json', 'mattermost.yaml', 'mattermost.conf',
])

export function isWebConferenceServerConfig(path: string, base: string): boolean {
  if (WEBCONF_UNGATED_EXACT.has(base)) return true

  const low = path.toLowerCase()

  // homeserver.yaml/yml — unambiguous ONLY within matrix/synapse directory context
  if ((base === 'homeserver.yaml' || base === 'homeserver.yml' || base === 'homeserver.json') &&
      (low.includes('matrix/') || low.includes('synapse/'))) {
    return true
  }

  // Prefix-ungated: synapse-*, matrix-*, bbb-*, mattermost-* are specific enough
  if (
    base.startsWith('synapse-') ||
    base.startsWith('matrix-') ||
    base.startsWith('bbb-') ||
    base.startsWith('mattermost-') ||
    base.startsWith('rocketchat-') ||
    base.startsWith('nextcloud-talk-')
  ) {
    return /\.(conf|cfg|json|yaml|yml|properties|env)$/.test(base)
  }

  // General config files gated on web conferencing directory context
  return WEBCONF_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|json|yaml|yml|properties|env|toml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rule 8: VOIP_CDR_MONITORING_DRIFT (low)
// ---------------------------------------------------------------------------
// VoIP CDR (Call Detail Record), Homer SIP capture, and SNGREP monitoring
// configuration.  While lower severity, CDR pipeline misconfigs can suppress
// fraud-detection signals or expose sensitive call metadata.

const CDR_UNGATED = new Set([
  'homer.cfg', 'homer.conf', 'homer.yaml', 'homer.yml',
  'sngrep.conf', 'sngrep.yaml', 'sipcapture.conf',
  'heplify.yml', 'heplify.yaml', 'heplify-server.yaml',
])

const CDR_DIRS = [
  'homer/', 'cdr/', 'voip-monitor/', 'call-records/',
  'sngrep/', 'sipcapture/', 'heplify/', 'voip-cdr/',
]

function isVoipCdrMonitoringConfig(path: string, base: string): boolean {
  if (CDR_UNGATED.has(base)) return true

  const low = path.toLowerCase()
  if (
    base.startsWith('homer-') ||
    base.startsWith('sngrep-') ||
    base.startsWith('heplify-') ||
    base.startsWith('sipcapture-') ||
    base.startsWith('voip-monitor-') ||
    base.startsWith('voip-cdr-')
  ) {
    return /\.(conf|cfg|yaml|yml|json|toml)$/.test(base)
  }

  return CDR_DIRS.some((d) => low.includes(d)) &&
    /\.(conf|cfg|yaml|yml|json|toml)$/.test(base)
}

// ---------------------------------------------------------------------------
// Rules registry
// ---------------------------------------------------------------------------

type Severity = 'high' | 'medium' | 'low'

type VoipSecRule = {
  id: string
  severity: Severity
  description: string
  recommendation: string
  match: (path: string, base: string) => boolean
}

const RULES: VoipSecRule[] = [
  {
    id: 'ASTERISK_PBX_DRIFT',
    severity: 'high',
    description: 'Asterisk PBX or FreePBX configuration modified.',
    recommendation: 'Audit sip.conf/pjsip.conf peer secrets, manager.conf AMI credentials, and extensions.conf dialplan for unauthorized external routes.',
    match: isAsteriskPbxConfig,
  },
  {
    id: 'KAMAILIO_OPENSIPS_DRIFT',
    severity: 'high',
    description: 'Kamailio or OpenSIPS SIP proxy configuration modified.',
    recommendation: 'Verify authentication module settings, TLS configuration, rate-limiting rules, and IP allowlists for SIP registration.',
    match: isKamailioOpensipsConfig,
  },
  {
    id: 'FREESWITCH_DRIFT',
    severity: 'high',
    description: 'FreeSWITCH PBX configuration modified.',
    recommendation: 'Review vars.xml for credential exposure, SIP profile authentication settings, and event_socket.conf.xml ACLs.',
    match: isFreeswitchConfig,
  },
  {
    id: 'SIP_TRUNK_CREDENTIALS_DRIFT',
    severity: 'high',
    description: 'SIP trunk provider credential or registration configuration modified.',
    recommendation: 'Ensure SIP trunk credentials are stored in secrets management (not plaintext), verify allowed destination patterns, and review outbound call routing restrictions.',
    match: isSipTrunkCredentialsConfig,
  },
  {
    id: 'JITSI_WEBRTC_DRIFT',
    severity: 'medium',
    description: 'Jitsi Meet, TURN server, or WebRTC configuration modified.',
    recommendation: 'Verify coturn shared secret rotation, DTLS-SRTP enforcement, and Jitsi Videobridge TLS settings.',
    match: isJitsiWebrtcConfig,
  },
  {
    id: 'VOIP_GATEWAY_DRIFT',
    severity: 'medium',
    description: 'VoIP gateway or analogue-telephone-adapter configuration modified.',
    recommendation: 'Audit gateway SIP registration credentials, DTMF handling settings, and codec negotiation security options.',
    match: isVoipGatewayConfig,
  },
  {
    id: 'WEBCONFERENCE_SECURITY_DRIFT',
    severity: 'medium',
    description: 'Web conferencing or team communication server configuration modified.',
    recommendation: 'Review Matrix/Synapse registration settings, BigBlueButton shared secrets, and Mattermost OAuth/SAML configuration.',
    match: (p, b) => isWebConferenceServerConfig(p, b),
  },
  {
    id: 'VOIP_CDR_MONITORING_DRIFT',
    severity: 'low',
    description: 'VoIP CDR or SIP capture monitoring configuration modified.',
    recommendation: 'Ensure CDR pipelines are not silently dropping records, Homer capture filters are correctly scoped, and monitoring credentials are rotated.',
    match: isVoipCdrMonitoringConfig,
  },
]

// ---------------------------------------------------------------------------
// Scoring model (identical to all WS-60+ detectors)
// ---------------------------------------------------------------------------

const SEVERITY_PENALTY: Record<Severity, number> = { high: 15, medium: 8, low: 4 }
const SEVERITY_CAP:     Record<Severity, number> = { high: 45, medium: 25, low: 15 }

type VoipSecRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

function computeRiskLevel(score: number): VoipSecRiskLevel {
  if (score === 0)  return 'none'
  if (score < 15)   return 'low'
  if (score < 45)   return 'medium'
  if (score < 80)   return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export type VoipSecFinding = {
  ruleId:         string
  severity:       Severity
  matchedPath:    string
  matchCount:     number
  description:    string
  recommendation: string
}

export type VoipSecDriftResult = {
  riskScore:     number
  riskLevel:     VoipSecRiskLevel
  totalFindings: number
  highCount:     number
  mediumCount:   number
  lowCount:      number
  findings:      VoipSecFinding[]
  summary:       string
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

export function scanVoipSecurityDrift(
  changedFiles: string[],
): VoipSecDriftResult {
  const findings: VoipSecFinding[] = []

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
      ? 'No VoIP or unified communications security configuration changes detected.'
      : `${totalFindings} VoIP/UC security configuration ${totalFindings === 1 ? 'file' : 'files'} modified (risk score ${score}/100).`

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
