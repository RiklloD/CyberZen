// WS-90 — Wireless Network & RADIUS Authentication Security Configuration
// Drift Detector: pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to wireless access-point configuration, WPA supplicant credentials, RADIUS
// AAA server configuration, TACACS+ network-device authentication, wireless
// controller settings, RADIUS policy and virtual-server config, 802.1X/EAP
// supplicant profiles, and captive portal daemon configuration.
//
// DISTINCT from:
//   WS-68  networkFirewallDrift    — iptables/nftables/UFW packet-filter rules;
//                                    WS-90 covers wireless authentication layer
//                                    (WPA2/WPA3, 802.1X, RADIUS)
//   WS-70  identityAccessDrift     — Vault/LDAP/PAM server-side identity configs;
//                                    WS-90 covers RADIUS and TACACS+ AAA which
//                                    authenticate network devices and users at the
//                                    network access layer (not application identity)
//   WS-78  messagingSecurityDrift  — MQTT broker (mosquitto.conf) covered there;
//                                    WS-90 covers the wireless access layer beneath
//   WS-84  vpnRemoteAccessDrift    — VPN daemon configs (OpenVPN/WireGuard/IPsec);
//                                    WS-90 covers wireless/802.11 access control,
//                                    not layer-3 tunnelling
//   WS-89  osSecurityHardeningDrift — OS-level hardening (sshd_config, sudoers);
//                                    WS-90 covers the wireless and RADIUS layer
//
// Covered rule groups (8 rules):
//
//   HOSTAPD_AP_CONFIG_DRIFT        — Wi-Fi access point daemon configuration:
//                                    WPA2/WPA3 cipher suites, PMKSA caching,
//                                    SSID, channel, power, management-frame
//                                    protection settings (hostapd.conf)
//   WPA_SUPPLICANT_DRIFT           — WPA supplicant client configuration: holds
//                                    PSK passphrases and EAP credentials in
//                                    plaintext or hashed form (wpa_supplicant.conf,
//                                    wpa_supplicant-<iface>.conf)
//   FREERADIUS_SERVER_DRIFT        — FreeRADIUS AAA server: main daemon config,
//                                    NAS client definitions with shared secrets,
//                                    and the user authentication database
//                                    (radiusd.conf, clients.conf, users)
//   TACACS_PLUS_DRIFT              — TACACS+ network-device authentication daemon:
//                                    used for authenticating logins to Cisco/Juniper/
//                                    Palo Alto routers and switches (tac_plus.conf)
//   WIRELESS_CONTROLLER_DRIFT      — Wireless controller configuration: Ubiquiti
//                                    UniFi, Aruba, Cisco WLC, Ruckus — manages
//                                    SSID policy, VLAN assignment, RF settings
//                                    across a fleet of APs (user contribution)
//   RADIUS_POLICY_DRIFT            — FreeRADIUS virtual-server and policy config:
//                                    proxy.conf, sites-enabled/*, policy.d/*,
//                                    mods-enabled/* — controls authentication flow
//                                    and authorisation policy
//   DOT1X_EAP_PROFILE_DRIFT        — 802.1X/EAP method profile configuration:
//                                    EAP certificate paths, inner-method selection,
//                                    and identity supplicant profiles (eapol.conf,
//                                    eap.conf in radius/hostapd dirs)
//   CAPTIVE_PORTAL_DRIFT           — Captive portal daemon configuration: controls
//                                    which clients are authenticated and redirected
//                                    (nodogsplash.conf, coova-chilli, chillispot)
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Vendor directory exclusion applied to all paths before rule evaluation.
//   • Same penalty/cap scoring model as WS-60–89 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (firstPath + matchCount).
//   • hostapd.conf/radiusd.conf/tac_plus.conf globally unambiguous — ungated.
//   • wpa_supplicant.conf globally unambiguous; interface-specific variants
//     (wpa_supplicant-wlan0.conf) matched by startsWith prefix.
//   • clients.conf and users gated on RADIUS dirs (too generic ungated).
//   • All ungated Set entries stored lowercase (base is .toLowerCase()).
//
// Exports:
//   isWirelessControllerConfig     — user contribution point (see JSDoc below)
//   WIRELESS_RADIUS_RULES          — readonly rule registry
//   scanWirelessRadiusDrift        — main scanner, returns WirelessRadiusDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type WirelessRadiusRuleId =
  | 'HOSTAPD_AP_CONFIG_DRIFT'
  | 'WPA_SUPPLICANT_DRIFT'
  | 'FREERADIUS_SERVER_DRIFT'
  | 'TACACS_PLUS_DRIFT'
  | 'WIRELESS_CONTROLLER_DRIFT'
  | 'RADIUS_POLICY_DRIFT'
  | 'DOT1X_EAP_PROFILE_DRIFT'
  | 'CAPTIVE_PORTAL_DRIFT'

export type WirelessRadiusSeverity  = 'high' | 'medium' | 'low'
export type WirelessRadiusRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type WirelessRadiusFinding = {
  ruleId:         WirelessRadiusRuleId
  severity:       WirelessRadiusSeverity
  matchedPath:    string
  matchCount:     number
  description:    string
  recommendation: string
}

export type WirelessRadiusDriftResult = {
  riskScore:     number
  riskLevel:     WirelessRadiusRiskLevel
  totalFindings: number
  highCount:     number
  mediumCount:   number
  lowCount:      number
  findings:      WirelessRadiusFinding[]
  summary:       string
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

const HOSTAPD_DIRS   = ['hostapd/', 'hostapd-config/', 'wlan/', 'wifi/', 'wireless/', 'ap/', 'access-point/', 'etc/hostapd/']
const WPA_DIRS       = ['wpa_supplicant/', 'etc/wpa_supplicant/', 'wireless/wpa/', 'network/wireless/']
const RADIUS_DIRS    = ['freeradius/', 'radius/', 'radiusd/', 'raddb/', 'etc/raddb/', 'etc/freeradius/', 'freeradius3/', 'freeradius-config/']
const TACACS_DIRS    = ['tacacs/', 'tacacs+/', 'tac_plus/', 'tacacsplus/', 'aaa/tacacs/', 'network-aaa/', 'aaa/']
const WC_DIRS        = ['wireless-controller/', 'wlc/', 'unifi/', 'aruba/', 'cisco-wlc/', 'wifi-controller/', 'ap-controller/', 'ruckus/', 'meraki/']
const DOT1X_DIRS     = ['dot1x/', '802.1x/', 'eap/', 'eapol/', 'network-auth/', 'radius/eap/', 'supplicant/', '802-1x/']
const PORTAL_DIRS    = ['nodogsplash/', 'chillispot/', 'coova-chilli/', 'coova/', 'captive-portal/', 'portal/', 'wifi-portal/', 'hotspot/']

function inAnyDir(pathLower: string, dirs: readonly string[]): boolean {
  return dirs.some((d) => pathLower.includes(d))
}

// ---------------------------------------------------------------------------
// Rule 1: HOSTAPD_AP_CONFIG_DRIFT (high)
// Wi-Fi access point daemon configuration
// ---------------------------------------------------------------------------

const HOSTAPD_UNGATED = new Set([
  'hostapd.conf',      // main hostapd config — globally unambiguous
  'hostapd.wpa_psk',   // per-station PSK file — globally unambiguous
  'hostapd.eap_user',  // EAP user database for hostapd — globally unambiguous
  'hostapd.accept',    // MAC address allowlist — globally unambiguous
  'hostapd.deny',      // MAC address blocklist — globally unambiguous
])

function isHostapdApConfig(pathLower: string, base: string): boolean {
  if (HOSTAPD_UNGATED.has(base)) return true

  // hostapd-*.conf prefix (e.g. hostapd-wpa3.conf, hostapd-5ghz.conf)
  if (base.startsWith('hostapd') && base.endsWith('.conf')) return true
  if (base.startsWith('hostapd.')) return true

  if (!inAnyDir(pathLower, HOSTAPD_DIRS)) return false

  if (base.endsWith('.conf') || base.endsWith('.psk') || base.endsWith('.eap_user')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 2: WPA_SUPPLICANT_DRIFT (high)
// WPA supplicant client configuration (holds PSK / EAP credentials)
// ---------------------------------------------------------------------------

const WPA_UNGATED = new Set([
  'wpa_supplicant.conf',    // main supplicant config — globally unambiguous
])

function isWpaSupplicantConfig(pathLower: string, base: string): boolean {
  if (WPA_UNGATED.has(base)) return true

  // interface-specific: wpa_supplicant-wlan0.conf, wpa_supplicant-wlp2s0.conf
  if (base.startsWith('wpa_supplicant-') && base.endsWith('.conf')) return true
  if (base.startsWith('wpa-supplicant') && base.endsWith('.conf')) return true
  // wpa_supplicant.conf.j2 / wpa_supplicant.conf.bak templates
  if (base.startsWith('wpa_supplicant.conf.') || base.startsWith('wpa_supplicant.conf-')) return true

  if (!inAnyDir(pathLower, WPA_DIRS)) return false

  if (base.endsWith('.conf') || base.endsWith('.wpa') || base.endsWith('.psk')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 3: FREERADIUS_SERVER_DRIFT (high)
// FreeRADIUS AAA server configuration
// ---------------------------------------------------------------------------

const RADIUS_UNGATED = new Set([
  'radiusd.conf',     // FreeRADIUS main daemon config — globally unambiguous
  'freeradius.conf',  // alternative name — globally unambiguous
])

// Exact gated names (require RADIUS dir context)
const RADIUS_GATED_EXACT = new Set([
  'clients.conf',  // NAS client definitions with shared secrets — gated
  'users',         // user authentication database — gated
  'huntgroups',    // group-based access control — gated
  'dictionary',    // RADIUS attribute dictionary — gated
])

function isFreeradiusServerConfig(pathLower: string, base: string): boolean {
  if (RADIUS_UNGATED.has(base)) return true

  // radiusd.conf.j2 / freeradius.conf.bak templates
  if (base.startsWith('radiusd.conf.') || base.startsWith('freeradius.conf.')) return true

  if (!inAnyDir(pathLower, RADIUS_DIRS)) return false

  if (RADIUS_GATED_EXACT.has(base)) return true

  if (base.endsWith('.conf') || base.endsWith('.cfg')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 4: TACACS_PLUS_DRIFT (high)
// TACACS+ network-device authentication daemon
// ---------------------------------------------------------------------------

const TACACS_UNGATED = new Set([
  'tac_plus.conf',   // TACACS+ daemon (tac_plus) main config — globally unambiguous
  'tac_plus.cfg',    // alternative extension
  'tacacs.conf',     // generic TACACS config name — globally unambiguous
  'tacacs+.conf',    // explicit TACACS+ suffix — globally unambiguous
])

function isTacacsPlusConfig(pathLower: string, base: string): boolean {
  if (TACACS_UNGATED.has(base)) return true

  // tac_plus-*.conf / tacacs-*.conf prefix
  if (base.startsWith('tac_plus') && (base.endsWith('.conf') || base.endsWith('.cfg'))) return true
  if (base.startsWith('tacacs') && (base.endsWith('.conf') || base.endsWith('.cfg'))) return true

  if (!inAnyDir(pathLower, TACACS_DIRS)) return false

  if (base.endsWith('.conf') || base.endsWith('.cfg') || base === 'users') return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 5: WIRELESS_CONTROLLER_DRIFT (medium) — USER CONTRIBUTION
// Wireless controller configuration (UniFi, Aruba, Cisco WLC, Ruckus, Meraki)
// ---------------------------------------------------------------------------

/**
 * Determine whether `path` is a wireless controller configuration file.
 * Called for the MEDIUM-severity WIRELESS_CONTROLLER_DRIFT rule.
 *
 * The path is already confirmed NOT to be a vendor path. `base` is the
 * lowercase, normalised filename. `pathLower` is the full normalised path.
 *
 * Implement the body: decide whether to match only vendor-specific config file
 * names (narrower, fewer false positives — e.g. unifi.conf, wlc-config.yaml)
 * or also include generic controller config.yaml files inside wireless-
 * controller/ directories (broader, more coverage but risks matching
 * non-security infrastructure YAML files).
 *
 * Many wireless controllers export config in YAML/JSON; others use binary
 * formats committed as config.json or system.cfg.
 *
 * Return true if the file is a wireless controller configuration file.
 */
export function isWirelessControllerConfig(pathLower: string, base: string): boolean {
  // UniFi Controller: config.gateway.json, config.system.json, config.properties
  if (
    (base === 'config.gateway.json' || base === 'config.system.json' || base === 'config.properties') &&
    inAnyDir(pathLower, WC_DIRS)
  ) return true

  // Ubiquiti / UniFi: site/<name>/config files in unifi/ dir
  if (inAnyDir(pathLower, WC_DIRS) && (
    base.endsWith('.json') || base.endsWith('.yaml') ||
    base.endsWith('.cfg')  || base.endsWith('.conf')
  )) return true

  // Cisco WLC / Aruba prefix patterns
  if (base.startsWith('wlc-') && (base.endsWith('.conf') || base.endsWith('.yaml'))) return true
  if (base.startsWith('aruba-') && (base.endsWith('.conf') || base.endsWith('.yaml'))) return true
  if (base.startsWith('unifi-') && (base.endsWith('.conf') || base.endsWith('.json') || base.endsWith('.yaml'))) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 6: RADIUS_POLICY_DRIFT (medium)
// FreeRADIUS virtual-server, proxy, and policy configuration
// ---------------------------------------------------------------------------

function isRadiusPolicyConfig(pathLower: string, base: string): boolean {
  if (!inAnyDir(pathLower, RADIUS_DIRS)) return false

  // proxy.conf — RADIUS proxy / home-server config
  if (base === 'proxy.conf') return true

  // Virtual-server configs in sites-available / sites-enabled
  if (pathLower.includes('sites-enabled/') || pathLower.includes('sites-available/')) return true

  // Policy definition files in policy.d/
  if (pathLower.includes('policy.d/') && base.endsWith('.conf')) return true

  // Module configs in mods-enabled / mods-available
  if (pathLower.includes('mods-enabled/') || pathLower.includes('mods-available/')) return true

  // Generic policy files in RADIUS dirs
  if (base === 'policy.conf' || base === 'filter.conf' || base === 'sql.conf') return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 7: DOT1X_EAP_PROFILE_DRIFT (medium)
// 802.1X / EAP supplicant profile and method configuration
// ---------------------------------------------------------------------------

const EAP_UNGATED = new Set([
  'eapol.conf',        // 802.1X supplicant (older wired Ethernet) — globally unambiguous
  'eapol_test.conf',   // eapol_test utility config — globally unambiguous
])

function isDot1xEapProfileConfig(pathLower: string, base: string): boolean {
  if (EAP_UNGATED.has(base)) return true

  // eap-*.conf / eap_*.conf EAP method configs
  if ((base.startsWith('eap-') || base.startsWith('eap_')) && base.endsWith('.conf')) return true
  // eap.conf in radius or hostapd directories
  if (base === 'eap.conf' && (inAnyDir(pathLower, RADIUS_DIRS) || inAnyDir(pathLower, HOSTAPD_DIRS))) return true

  if (!inAnyDir(pathLower, DOT1X_DIRS)) return false

  if (base.endsWith('.conf') || base.endsWith('.cfg') || base.endsWith('.pem') || base.endsWith('.crt')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 8: CAPTIVE_PORTAL_DRIFT (low)
// Captive portal daemon configuration
// ---------------------------------------------------------------------------

const PORTAL_UNGATED = new Set([
  'nodogsplash.conf',    // NoDogSplash captive portal — globally unambiguous
  'chillispot.conf',     // ChilliSpot hotspot daemon — globally unambiguous
  'chilli.conf',         // CoovaChilli shorthand — globally unambiguous
  'coova-chilli.conf',   // CoovaChilli explicit name — globally unambiguous
])

function isCaptivePortalConfig(pathLower: string, base: string): boolean {
  if (PORTAL_UNGATED.has(base)) return true

  // nodogsplash-*.conf / chilli-*.conf prefix
  if (base.startsWith('nodogsplash') && base.endsWith('.conf')) return true
  if (base.startsWith('chilli') && (base.endsWith('.conf') || base.endsWith('.cfg'))) return true
  if (base.startsWith('coova') && base.endsWith('.conf')) return true

  if (!inAnyDir(pathLower, PORTAL_DIRS)) return false

  if (base.endsWith('.conf') || base.endsWith('.cfg') || base.endsWith('.json')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

interface WirelessRadiusRule {
  id:             WirelessRadiusRuleId
  severity:       WirelessRadiusSeverity
  description:    string
  recommendation: string
  match:          (pathLower: string, base: string) => boolean
}

export const WIRELESS_RADIUS_RULES: readonly WirelessRadiusRule[] = [
  {
    id:             'HOSTAPD_AP_CONFIG_DRIFT',
    severity:       'high',
    description:    'Wi-Fi access point daemon configuration changed (hostapd.conf, hostapd.wpa_psk, or hostapd EAP user file). hostapd controls WPA2/WPA3 cipher suites, management-frame protection (802.11w), PMKSA caching, and per-station PSK assignments — changes can silently downgrade wireless security.',
    recommendation: 'Review the changed hostapd configuration. Ensure WPA3-SAE or WPA2-PSK with CCMP is enforced, weak protocols (WEP, TKIP, WPA1) are disabled, ieee80211w=2 (required MFP) is set, and the PSK/EAP user file has not introduced weak passphrases or unauthorised station entries.',
    match:          isHostapdApConfig,
  },
  {
    id:             'WPA_SUPPLICANT_DRIFT',
    severity:       'high',
    description:    'WPA supplicant configuration changed (wpa_supplicant.conf or interface-specific variant). wpa_supplicant.conf commonly stores WPA-PSK passphrases in plaintext or EAP credentials (username/password/certificate paths) used for 802.1X enterprise authentication.',
    recommendation: 'Review the changed supplicant configuration. Ensure PSK passphrases are sufficiently long (≥20 characters), EAP method is TLS/TTLS/PEAP (not deprecated MD5/LEAP), server certificate validation is enabled (ca_cert is set), and no credentials have been weakened or exposed.',
    match:          isWpaSupplicantConfig,
  },
  {
    id:             'FREERADIUS_SERVER_DRIFT',
    severity:       'high',
    description:    'FreeRADIUS AAA server configuration changed (radiusd.conf, clients.conf, or user database). clients.conf stores the RADIUS shared secret used by every NAS (switch, AP, VPN concentrator) to authenticate to the RADIUS server; exposure compromises the entire network access layer.',
    recommendation: 'Review the changed RADIUS configuration. Ensure shared secrets in clients.conf are long and random (≥32 characters), the users file does not add plaintext passwords, the radiusd.conf does not enable insecure EAP methods (EAP-MD5, EAP-LEAP), and the daemon binds only to intended interfaces.',
    match:          isFreeradiusServerConfig,
  },
  {
    id:             'TACACS_PLUS_DRIFT',
    severity:       'high',
    description:    'TACACS+ daemon configuration changed (tac_plus.conf). TACACS+ is used for authentication, authorisation, and accounting on network devices (routers, switches, firewalls); a weakened configuration can allow unauthorised administrative access to the entire network infrastructure.',
    recommendation: 'Review the changed TACACS+ configuration. Ensure the shared key (key =) is strong, encryption is enabled, allow/deny rules are not overly permissive (avoid user = DEFAULT { login = cleartext }), and service authorisation is scoped to the minimum necessary privilege levels.',
    match:          isTacacsPlusConfig,
  },
  {
    id:             'WIRELESS_CONTROLLER_DRIFT',
    severity:       'medium',
    description:    'Wireless controller configuration changed (UniFi, Aruba, Cisco WLC, Ruckus, or Meraki controller config). Wireless controllers centrally manage SSID policy, VLAN assignment, RF power, client isolation, and 802.1X authentication across the AP fleet.',
    recommendation: 'Review the changed wireless controller configuration. Ensure SSID security modes have not been downgraded, management VLAN isolation is intact, client isolation is enabled on guest SSIDs, and any RADIUS server references use updated shared secrets.',
    match:          isWirelessControllerConfig,
  },
  {
    id:             'RADIUS_POLICY_DRIFT',
    severity:       'medium',
    description:    'FreeRADIUS virtual-server, policy, or module configuration changed (sites-enabled/*, policy.d/*, mods-enabled/*, proxy.conf). These files control the authentication flow, attribute mapping, EAP method selection, and proxying rules for the RADIUS server.',
    recommendation: 'Review the changed RADIUS policy configuration. Ensure inner EAP methods in virtual servers are not downgraded to MD5/LEAP, proxy.conf does not forward authentication to untrusted home servers, and new module configurations have been reviewed for credential leakage or overly permissive access rules.',
    match:          isRadiusPolicyConfig,
  },
  {
    id:             'DOT1X_EAP_PROFILE_DRIFT',
    severity:       'medium',
    description:    '802.1X/EAP supplicant profile or EAP method configuration changed (eapol.conf, eap.conf, eap-tls.conf, or files in dot1x/ directories). EAP profiles define the certificate validation chain, inner authentication method, and identity sent to the RADIUS server.',
    recommendation: 'Review the changed EAP profile. Ensure server certificate validation is enforced (ca_cert is present and correct), weak inner methods (MD5, LEAP, GTC-plaintext) are not in use, client certificates are from the correct PKI, and anonymous identity is used for the outer EAP identity where supported.',
    match:          isDot1xEapProfileConfig,
  },
  {
    id:             'CAPTIVE_PORTAL_DRIFT',
    severity:       'low',
    description:    'Captive portal daemon configuration changed (nodogsplash.conf, coova-chilli, or captive portal config in portal/ directories). Captive portal settings control which clients bypass authentication, allowed bandwidth, session timeout, and the redirect URL.',
    recommendation: 'Review the changed captive portal configuration. Ensure the allowed hosts whitelist has not been expanded unexpectedly, session timeouts are set to reasonable values, and the redirect URL points to the correct portal endpoint.',
    match:          isCaptivePortalConfig,
  },
]

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

const PENALTY: Record<WirelessRadiusSeverity, number> = { high: 15, medium: 8, low: 4 }
const CAP:     Record<WirelessRadiusSeverity, number> = { high: 45, medium: 25, low: 15 }
const SCORE_MAX = 100

function computeRiskLevel(score: number): WirelessRadiusRiskLevel {
  if (score === 0)  return 'none'
  if (score < 15)   return 'low'
  if (score < 45)   return 'medium'
  if (score < 80)   return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

export function scanWirelessRadiusDrift(changedFiles: string[]): WirelessRadiusDriftResult {
  const clean = changedFiles
    .map((f) => f.replace(/\\/g, '/'))
    .filter((f) => !isVendor(f))

  const findings: WirelessRadiusFinding[] = []

  for (const rule of WIRELESS_RADIUS_RULES) {
    let firstPath  = ''
    let matchCount = 0

    for (const path of clean) {
      const pathLower = path.toLowerCase()
      const base      = pathLower.split('/').pop() ?? pathLower
      if (rule.match(pathLower, base)) {
        matchCount++
        if (!firstPath) firstPath = path
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

  // Penalty/cap scoring
  const accumulated: Record<WirelessRadiusSeverity, number> = { high: 0, medium: 0, low: 0 }
  for (const f of findings) {
    accumulated[f.severity] = Math.min(
      accumulated[f.severity] + PENALTY[f.severity],
      CAP[f.severity],
    )
  }
  const raw   = accumulated.high + accumulated.medium + accumulated.low
  const score = Math.min(raw, SCORE_MAX)

  const highCount   = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount    = findings.filter((f) => f.severity === 'low').length

  const riskLevel = computeRiskLevel(score)

  let summary: string
  if (findings.length === 0) {
    summary = 'No wireless network or RADIUS authentication configuration changes detected.'
  } else {
    const parts: string[] = []
    if (highCount)   parts.push(`${highCount} high-severity`)
    if (mediumCount) parts.push(`${mediumCount} medium-severity`)
    if (lowCount)    parts.push(`${lowCount} low-severity`)
    summary = `Wireless/RADIUS authentication drift detected: ${parts.join(', ')} finding${findings.length !== 1 ? 's' : ''} (risk score ${score}/100, level: ${riskLevel}).`
  }

  return {
    riskScore:     score,
    riskLevel,
    totalFindings: findings.length,
    highCount,
    mediumCount,
    lowCount,
    findings,
    summary,
  }
}
