// WS-84 — VPN & Remote Access Security Configuration Drift Detector:
// pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to VPN server, remote access gateway, and secure tunnelling configuration
// files.  A modified OpenVPN server config, WireGuard interface file (which
// embeds the private key inline), or IPsec pre-shared-key store gives an
// attacker the ability to decrypt or impersonate VPN traffic for every host
// that trusts those credentials.
//
// DISTINCT from:
//   WS-66  certPkiDrift           — TLS certificate lifecycle, Let's Encrypt,
//                                   cert-manager, general PKI CA infrastructure;
//                                   WS-84 covers VPN-specific key material
//   WS-68  networkFirewallDrift   — iptables/UFW/nftables packet-filter rules;
//                                   WS-84 covers VPN tunnel configuration,
//                                   not the firewall that surrounds it
//   WS-70  identityAccessDrift    — Vault policy HCL, LDAP, PAM; WS-84 covers
//                                   the VPN transport layer and access gateways
//   WS-72  serviceMeshDrift       — Istio/Envoy east-west mTLS inside the
//                                   cluster; WS-84 covers north-south VPN
//                                   tunnels from external clients into the fleet
//
// Covered rule groups (8 rules):
//
//   OPENVPN_CONFIG_DRIFT         — OpenVPN server/client configuration, TLS
//                                  auth/crypt keys, and DH parameter files
//   WIREGUARD_CONFIG_DRIFT       — WireGuard interface configs (private key
//                                  embedded inline) and key material
//   IPSEC_STRONGSWAN_DRIFT       — IPsec/StrongSwan/Libreswan configuration
//                                  and ipsec.secrets PSK/RSA key file
//   VPN_PKI_CREDENTIAL_DRIFT     — VPN-context PKI material: CA certs,
//                                  server/client keys in VPN dirs (user
//                                  contribution — see isVpnPkiCredential)
//   REMOTE_ACCESS_GATEWAY_DRIFT  — Apache Guacamole, Teleport, JumpServer
//                                  bastion configuration
//   CISCO_VPN_DRIFT              — Cisco AnyConnect profiles and ASA VPN
//                                  configuration
//   SSL_VPN_SERVER_DRIFT         — Pritunl, OpenConnect (ocserv), SoftEther,
//                                  PPTP (pptpd), L2TP (xl2tpd) VPN servers
//   VPN_CLIENT_PROFILE_DRIFT     — NetworkManager VPN connection files,
//                                  committed client bundles, CCD configs
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Vendor directory exclusion applied to all paths.
//   • Same penalty/cap scoring model as WS-60–83 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (firstPath + matchCount).
//   • openvpn.conf / ipsec.conf / ipsec.secrets / strongswan.conf are globally
//     unambiguous — they match anywhere in a repo.
//   • .ovpn extension is OpenVPN-specific and matches ungated.
//   • wg0.conf / wg1.conf etc. follow the wgN.conf canonical naming convention
//     and are matched via /^wg\d+\.conf$/ — globally unambiguous.
//   • ta.key / tls-auth.key / tls-crypt.key are OpenVPN-specific TLS auth keys.
//   • dh.pem / dh2048.pem are OpenVPN DH parameter files.
//   • chap-secrets / pap-secrets are PPP authentication secrets — VPN-specific.
//   • guacamole.properties / teleport.yaml / pritunl.conf / ocserv.conf /
//     pptpd.conf / xl2tpd.conf are globally unambiguous product config files.
//   • Generic PKI material (.pem/.key/.crt) in VPN dirs handled by user
//     contribution isVpnPkiCredential to avoid WS-66 overlap.
//
// Exports:
//   isVpnPkiCredential   — user contribution point (see JSDoc below)
//   VPN_REMOTE_ACCESS_RULES — readonly rule registry
//   scanVpnRemoteAccessDrift — main scanner, returns VpnRemoteAccessDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type VpnRemoteAccessRuleId =
  | 'OPENVPN_CONFIG_DRIFT'
  | 'WIREGUARD_CONFIG_DRIFT'
  | 'IPSEC_STRONGSWAN_DRIFT'
  | 'VPN_PKI_CREDENTIAL_DRIFT'
  | 'REMOTE_ACCESS_GATEWAY_DRIFT'
  | 'CISCO_VPN_DRIFT'
  | 'SSL_VPN_SERVER_DRIFT'
  | 'VPN_CLIENT_PROFILE_DRIFT'

export type VpnRemoteAccessSeverity = 'high' | 'medium' | 'low'
export type VpnRemoteAccessRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type VpnRemoteAccessDriftFinding = {
  ruleId: VpnRemoteAccessRuleId
  severity: VpnRemoteAccessSeverity
  matchedPath: string
  matchCount: number
  description: string
  recommendation: string
}

export type VpnRemoteAccessDriftResult = {
  riskScore: number
  riskLevel: VpnRemoteAccessRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: VpnRemoteAccessDriftFinding[]
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

const OPENVPN_DIRS    = ['openvpn/', '.openvpn/', 'vpn/openvpn/', 'openvpn-config/', 'openvpn-keys/']
const WIREGUARD_DIRS  = ['wireguard/', '.wireguard/', 'wg/', 'vpn/wireguard/', 'wireguard-config/']
const IPSEC_DIRS      = ['ipsec/', 'strongswan/', 'libreswan/', 'vpn/ipsec/', 'ipsec-config/']
const VPN_PKI_DIRS    = ['openvpn/', 'wireguard/', '.wireguard/', 'ipsec/', 'strongswan/', 'vpn/', 'vpn-certs/', 'vpn-keys/', 'vpn-pki/', 'wg/']
const GUACAMOLE_DIRS  = ['guacamole/', '.guacamole/', 'guacamole-config/', 'guacamole-home/']
const TELEPORT_DIRS   = ['teleport/', '.teleport/', 'teleport-config/', 'teleport-data/']
const BASTION_DIRS    = ['bastion/', 'jumpserver/', 'jump-server/', 'bastion-host/']
const ANYCONNECT_DIRS = ['anyconnect/', 'cisco-vpn/', 'asa/', 'cisco-anyconnect/']
const SSL_VPN_DIRS    = ['pritunl/', 'ocserv/', 'softether/', 'pptp/', 'l2tp/', 'ssl-vpn/', 'openvpn-as/', 'xl2tpd/']
const VPN_CLIENT_DIRS = ['vpn-clients/', 'client-vpn/', 'vpn-profiles/', 'network-manager/', 'networkmanager/', 'system-connections/', 'ccd/']

function inAnyDir(pathLower: string, dirs: readonly string[]): boolean {
  return dirs.some((d) => pathLower.includes(d))
}

// ---------------------------------------------------------------------------
// Rule 1: OPENVPN_CONFIG_DRIFT (high)
// OpenVPN server/client configuration, TLS auth keys, and DH parameter files
// ---------------------------------------------------------------------------

const OPENVPN_UNGATED = new Set([
  'openvpn.conf',     // Canonical OpenVPN configuration file — globally unambiguous
  'ta.key',           // OpenVPN TLS authentication key
  'tls-auth.key',     // OpenVPN TLS-auth variant
  'tls-crypt.key',    // OpenVPN TLS-crypt (encrypts + authenticates control channel)
  'dh.pem',           // Diffie-Hellman parameters — named by OpenVPN convention
  'dh2048.pem',       // DH params with explicit bit size
  'dh4096.pem',
])

function isOpenVpnConfig(pathLower: string, base: string): boolean {
  if (OPENVPN_UNGATED.has(base)) return true
  if (base.endsWith('.ovpn')) return true                                    // OpenVPN client profile — globally unambiguous extension
  if (base.startsWith('openvpn-') && base.endsWith('.conf')) return true    // openvpn-server.conf, openvpn-client.conf

  if (!inAnyDir(pathLower, OPENVPN_DIRS)) return false

  if (base === 'server.conf' || base === 'client.conf' || base === 'server.ovpn') return true
  if (base === 'ca.crt' || base === 'server.crt' || base === 'client.crt') return true
  if (base.endsWith('.conf') || base.endsWith('.ovpn')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 2: WIREGUARD_CONFIG_DRIFT (high)
// WireGuard interface configs (private key embedded) and key material
// ---------------------------------------------------------------------------

function isWireGuardConfig(pathLower: string, base: string): boolean {
  if (base === 'wireguard.conf') return true
  if (/^wg\d+\.conf$/.test(base)) return true                               // wg0.conf, wg1.conf, wg10.conf — canonical naming
  if (base.startsWith('wg-') && base.endsWith('.conf')) return true         // wg-server.conf, wg-client.conf
  if (base.startsWith('wireguard-') && (base.endsWith('.conf') || base.endsWith('.toml'))) return true

  if (!inAnyDir(pathLower, WIREGUARD_DIRS)) return false

  if (base.endsWith('.conf') || base.endsWith('.key')) return true
  if (base === 'privatekey' || base === 'publickey' || base === 'presharedkey') return true  // WireGuard key files
  if (base === 'server.conf' || base === 'wg.conf') return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 3: IPSEC_STRONGSWAN_DRIFT (high)
// IPsec/StrongSwan/Libreswan configuration and PSK/RSA key secrets file
// ---------------------------------------------------------------------------

const IPSEC_UNGATED = new Set([
  'ipsec.conf',      // IPsec main configuration file — globally unambiguous
  'ipsec.secrets',   // PSK and RSA private key references — globally unambiguous
  'strongswan.conf', // StrongSwan main configuration file
])

function isIpsecStrongswanConfig(pathLower: string, base: string): boolean {
  if (IPSEC_UNGATED.has(base)) return true
  if (base.startsWith('ipsec-') && base.endsWith('.conf')) return true
  if (base.startsWith('strongswan-') && (base.endsWith('.conf') || base.endsWith('.yaml'))) return true

  if (!inAnyDir(pathLower, IPSEC_DIRS)) return false

  if (
    base === 'charon.conf'    ||  // StrongSwan IKE daemon config
    base === 'swanctl.conf'   ||  // StrongSwan swanctl config
    base === 'libreswan.conf' ||
    base.endsWith('.secrets') ||
    base.endsWith('.conf')
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 4: VPN_PKI_CREDENTIAL_DRIFT (high) — user contribution
// VPN-context PKI material: CA certs, server/client keys inside VPN dirs
// ---------------------------------------------------------------------------

/**
 * WS-84 user contribution — determines whether a file path contains VPN-
 * specific PKI credential material that warrants a security drift alert.
 *
 * The challenge: .pem/.key/.crt files appear throughout repositories in many
 * TLS and PKI contexts.  WS-66 (certPkiDrift) already covers general
 * certificate lifecycle management (Let's Encrypt, certbot, cert-manager, PKI
 * CA infrastructure).  WS-84 covers VPN-specific credential material — the
 * private keys and certificates committed to repositories alongside VPN
 * configuration files.
 *
 * Two disambiguation signals:
 *
 *   1. The file lives in a recognised VPN-specific directory segment
 *      (openvpn/, wireguard/, .wireguard/, ipsec/, strongswan/, vpn/,
 *      vpn-certs/, vpn-keys/, vpn-pki/, wg/) AND has a PKI file extension
 *      (.pem, .key, .crt, .p12, .pfx, .der, .crl, .secrets).
 *
 *   2. Files already captured ungated by other rules in this detector are
 *      excluded — ta.key, tls-auth.key, tls-crypt.key (OPENVPN rule),
 *      ipsec.secrets, dh.pem, dh2048.pem, dh4096.pem — to prevent redundant
 *      findings for files the more-specific rules already handle.
 *
 * Exclusions:
 *   • Let's Encrypt / certbot directories — defer to WS-66.
 *   • cert-manager / acme directories — defer to WS-66.
 *   • Files already matched ungated by OPENVPN_CONFIG_DRIFT or
 *     IPSEC_STRONGSWAN_DRIFT (ta.key, ipsec.secrets, dh.pem family).
 *
 * @param pathLower  Lowercased, forward-slash-normalised file path.
 * @param base       Lowercased filename component of `pathLower`.
 */
export function isVpnPkiCredential(pathLower: string, base: string): boolean {
  // Defer to WS-66 for dedicated certificate management infrastructure
  if (
    pathLower.includes('letsencrypt/') || pathLower.includes('certbot/') ||
    pathLower.includes('cert-manager/') || pathLower.includes('acme/')
  ) return false

  // Already captured ungated by OPENVPN_CONFIG_DRIFT — skip to avoid redundant findings
  if (
    base === 'ta.key' || base === 'tls-auth.key' || base === 'tls-crypt.key' ||
    base === 'dh.pem' || base === 'dh2048.pem'   || base === 'dh4096.pem'
  ) return false

  // Already captured ungated by IPSEC_STRONGSWAN_DRIFT
  if (base === 'ipsec.secrets') return false

  // Must be inside a VPN-specific directory segment
  if (!inAnyDir(pathLower, VPN_PKI_DIRS)) return false

  // Any PKI material file format found in a VPN directory is high-value
  return (
    base.endsWith('.pem') || base.endsWith('.key') || base.endsWith('.crt') ||
    base.endsWith('.p12') || base.endsWith('.pfx') || base.endsWith('.der') ||
    base.endsWith('.crl') || base.endsWith('.secrets')
  )
}

// ---------------------------------------------------------------------------
// Rule 5: REMOTE_ACCESS_GATEWAY_DRIFT (medium)
// Apache Guacamole, Teleport, JumpServer bastion configuration
// ---------------------------------------------------------------------------

const GATEWAY_UNGATED = new Set([
  'guacamole.properties',  // Apache Guacamole canonical config — globally unambiguous
  'teleport.yaml',         // Teleport access proxy config — globally unambiguous
  'teleport.toml',         // Teleport alternative format
])

function isRemoteAccessGatewayConfig(pathLower: string, base: string): boolean {
  if (GATEWAY_UNGATED.has(base)) return true

  // guacamole-* / teleport-* prefix
  if (base.startsWith('guacamole-') && (base.endsWith('.conf') || base.endsWith('.yaml') || base.endsWith('.properties'))) return true
  if (base.startsWith('teleport-') && (base.endsWith('.yaml') || base.endsWith('.toml') || base.endsWith('.json'))) return true

  if (inAnyDir(pathLower, GUACAMOLE_DIRS)) {
    if (
      base === 'user-mapping.xml' ||  // Guacamole user authentication store
      base === 'logback.xml'      ||  // Logging config (can expose connection details)
      base === 'guacamole.properties' ||
      base.endsWith('.xml') || base.endsWith('.properties') || base === '.env'
    ) return true
  }

  if (inAnyDir(pathLower, TELEPORT_DIRS)) {
    if (base.endsWith('.yaml') || base.endsWith('.toml') || base.endsWith('.json') || base === '.env') return true
  }

  if (inAnyDir(pathLower, BASTION_DIRS)) {
    if (
      base.endsWith('.conf') || base.endsWith('.yaml') || base.endsWith('.json') ||
      base === 'config' || base === '.env'
    ) return true
  }

  return false
}

// ---------------------------------------------------------------------------
// Rule 6: CISCO_VPN_DRIFT (medium)
// Cisco AnyConnect profiles and Cisco ASA VPN configuration
// ---------------------------------------------------------------------------

function isCiscoVpnConfig(pathLower: string, base: string): boolean {
  // anyconnect.xml / anyconnect-*.xml are globally unambiguous (Cisco product)
  if (base === 'anyconnect.xml') return true
  if ((base.startsWith('anyconnect-') || base.startsWith('anyconnect_')) && base.endsWith('.xml')) return true
  if (base.startsWith('cisco-vpn-') && (base.endsWith('.conf') || base.endsWith('.xml'))) return true

  if (!inAnyDir(pathLower, ANYCONNECT_DIRS)) return false

  if (
    base === 'profile.xml'     ||  // AnyConnect client profile
    base === 'vpn-profile.xml' ||
    base === 'preferences.xml' ||
    base.endsWith('.xml')      ||  // Any XML in Cisco dirs (policy, ACL, profile files)
    base.endsWith('.cfg')      ||  // ASA configuration files
    base === '.env'
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 7: SSL_VPN_SERVER_DRIFT (medium)
// Pritunl, OpenConnect (ocserv), SoftEther, PPTP, L2TP VPN server configs
// ---------------------------------------------------------------------------

const SSL_VPN_UNGATED = new Set([
  'pritunl.conf',   // Pritunl VPN server — globally unambiguous
  'ocserv.conf',    // OpenConnect VPN server — globally unambiguous
  'pptpd.conf',     // PPTP VPN daemon — globally unambiguous
  'xl2tpd.conf',    // L2TP/IPsec daemon — globally unambiguous
  'chap-secrets',   // PPP CHAP authentication secrets (VPN-specific)
  'pap-secrets',    // PPP PAP authentication secrets (VPN-specific)
])

function isSslVpnServerConfig(pathLower: string, base: string): boolean {
  if (SSL_VPN_UNGATED.has(base)) return true

  // pritunl-* / ocserv-* prefix
  if (base.startsWith('pritunl-') && (base.endsWith('.conf') || base.endsWith('.json'))) return true
  if (base.startsWith('ocserv-') && base.endsWith('.conf')) return true

  if (!inAnyDir(pathLower, SSL_VPN_DIRS)) return false

  if (
    base.endsWith('.conf') || base.endsWith('.json') ||
    base.endsWith('.yaml') || base.endsWith('.ini') ||
    base === '.env'
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 8: VPN_CLIENT_PROFILE_DRIFT (low)
// NetworkManager VPN connection files, CCD configs, client bundles
// ---------------------------------------------------------------------------

function isVpnClientProfile(pathLower: string, base: string): boolean {
  // .nmconnection — NetworkManager VPN connection file — globally unambiguous extension
  if (base.endsWith('.nmconnection')) return true

  // vpn-client-* prefix — explicit client profile files
  if (
    base.startsWith('vpn-client-') &&
    (base.endsWith('.conf') || base.endsWith('.ovpn') || base.endsWith('.yaml') || base.endsWith('.json'))
  ) return true

  if (!inAnyDir(pathLower, VPN_CLIENT_DIRS)) return false

  if (
    base === 'vpn-config.json'    || base === 'vpn-settings.yaml' ||
    base === 'vpn-settings.json'  || base === 'vpn-profile.json'  ||
    base.endsWith('.json')        || base.endsWith('.yaml')        ||
    base.endsWith('.conf')        || base.endsWith('.ovpn')
  ) return true

  // OpenVPN Client Configuration Directory (ccd/): one file per client, named by CN
  if (pathLower.includes('ccd/') && !base.includes('.')) return true   // bare CN filenames

  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

export const VPN_REMOTE_ACCESS_RULES: ReadonlyArray<{
  id: VpnRemoteAccessRuleId
  severity: VpnRemoteAccessSeverity
  description: string
  recommendation: string
  match: (pathLower: string, base: string) => boolean
}> = [
  {
    id: 'OPENVPN_CONFIG_DRIFT',
    severity: 'high',
    description: 'OpenVPN server or client configuration, TLS auth key, or DH parameter file changed.',
    recommendation:
      'Review openvpn.conf for tls-auth and tls-crypt changes that could weaken the control-channel protection, verify that the ta.key or tls-crypt.key has not been regenerated without distributing the new key to all clients and servers, confirm that dh.pem bit-length has not been downgraded below 2048, and audit any .ovpn client profiles for server address or certificate authority changes that could redirect client connections.',
    match: (p, b) => isOpenVpnConfig(p, b),
  },
  {
    id: 'WIREGUARD_CONFIG_DRIFT',
    severity: 'high',
    description: 'WireGuard interface configuration or key material changed.',
    recommendation:
      'Verify that the PrivateKey value in the WireGuard interface config has not changed without a corresponding AllowedIPs update for all peers, confirm that any new PublicKey or Endpoint additions in [Peer] sections represent authorized nodes, audit PreSharedKey changes between peer pairs for unintended key rotation, and review any key file additions to the wireguard/ directory for key material committed in cleartext.',
    match: (p, b) => isWireGuardConfig(p, b),
  },
  {
    id: 'IPSEC_STRONGSWAN_DRIFT',
    severity: 'high',
    description: 'IPsec/StrongSwan/Libreswan configuration or PSK secrets file changed.',
    recommendation:
      'Inspect ipsec.secrets for new or modified pre-shared key (%any or host-specific PSK entries) and RSA private key references, verify that ipsec.conf conn definitions have not relaxed keyexchange, ike, or esp algorithm suites to permit weak cipher negotiation, confirm that new connections defined in strongswan.conf do not allow anonymous or certificate-free peer authentication, and audit left/right identity settings for changes that could enable identity spoofing.',
    match: (p, b) => isIpsecStrongswanConfig(p, b),
  },
  {
    id: 'VPN_PKI_CREDENTIAL_DRIFT',
    severity: 'high',
    description: 'VPN-specific PKI credential file (CA key, server/client certificate or private key) changed in a VPN directory.',
    recommendation:
      'Confirm that the CA private key (ca.key) has not been committed to the repository — CA keys should never be stored in version control; review server.key and client.key changes for unintended key rotation that would invalidate existing VPN sessions; verify that certificate changes (ca.crt, server.crt) correspond to intentional re-issuance rather than accidental overwrites; and ensure CRL files are not being committed without a corresponding revocation event.',
    match: (p, b) => isVpnPkiCredential(p, b),
  },
  {
    id: 'REMOTE_ACCESS_GATEWAY_DRIFT',
    severity: 'medium',
    description: 'Remote access gateway configuration (Guacamole, Teleport, JumpServer) changed.',
    recommendation:
      'Review guacamole.properties for changes to connection database credentials, LDAP bind password, or guacd connection settings that could expose session data; verify teleport.yaml changes to auth_service and proxy_service listen addresses, trusted_cluster definitions, or connector credentials have not widened the trust boundary; audit user-mapping.xml for new user-to-connection grants in Guacamole; and confirm that any added bastion targets are authorized infrastructure.',
    match: (p, b) => isRemoteAccessGatewayConfig(p, b),
  },
  {
    id: 'CISCO_VPN_DRIFT',
    severity: 'medium',
    description: 'Cisco AnyConnect profile or ASA VPN configuration changed.',
    recommendation:
      'Inspect AnyConnect XML profile changes for ServerList modifications (new VPN gateway addresses), split-tunneling policy changes that could expose corporate traffic to the local network, or certificate store changes that could weaken server authentication; verify ASA .cfg changes to crypto map, tunnel-group, or group-policy settings do not permit weaker authentication methods; and confirm that any new AnyConnect profile additions have been approved by the network security team.',
    match: (p, b) => isCiscoVpnConfig(p, b),
  },
  {
    id: 'SSL_VPN_SERVER_DRIFT',
    severity: 'medium',
    description: 'SSL/PPTP/L2TP VPN server configuration (Pritunl, ocserv, pptpd, xl2tpd) or PPP authentication secrets changed.',
    recommendation:
      'Review pritunl.conf or ocserv.conf for changes to authentication backend settings (RADIUS server, certificate validation), TLS cipher suite restrictions, or client certificate requirements that could downgrade security posture; audit chap-secrets and pap-secrets for newly added or removed credentials — any cleartext password in these files should be treated as compromised; verify pptpd.conf and xl2tpd.conf changes have not enabled legacy MPPE-40 or re-enabled deprecated PPTP authentication methods.',
    match: (p, b) => isSslVpnServerConfig(p, b),
  },
  {
    id: 'VPN_CLIENT_PROFILE_DRIFT',
    severity: 'low',
    description: 'VPN client profile, NetworkManager VPN connection file, or OpenVPN CCD entry changed.',
    recommendation:
      'Verify that NetworkManager .nmconnection files committed to the repository do not contain cleartext VPN passwords or PSK values in the vpn section; confirm that new CCD (Client Configuration Directory) entries reflect authorized clients with correct AllowedIPs push routes; and review committed .ovpn client bundle changes for server address or CA certificate substitution that could redirect client traffic.',
    match: (p, b) => isVpnClientProfile(p, b),
  },
]

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

const SEVERITY_PENALTIES: Record<VpnRemoteAccessSeverity, { per: number; cap: number }> = {
  high:   { per: 15, cap: 45 },
  medium: { per: 8,  cap: 25 },
  low:    { per: 4,  cap: 15 },
}

function computeRiskScore(findings: VpnRemoteAccessDriftFinding[]): number {
  let score = 0
  for (const f of findings) {
    const { per, cap } = SEVERITY_PENALTIES[f.severity]
    score += Math.min(f.matchCount * per, cap)
  }
  return Math.min(score, 100)
}

function computeRiskLevel(score: number): VpnRemoteAccessRiskLevel {
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

export function scanVpnRemoteAccessDrift(changedFiles: string[]): VpnRemoteAccessDriftResult {
  const normalise = (p: string) => p.replace(/\\/g, '/').toLowerCase()

  const findings: VpnRemoteAccessDriftFinding[] = []

  for (const rule of VPN_REMOTE_ACCESS_RULES) {
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
  const ORDER: Record<VpnRemoteAccessSeverity, number> = { high: 0, medium: 1, low: 2 }
  findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity])

  const riskScore   = computeRiskScore(findings)
  const riskLevel   = computeRiskLevel(riskScore)
  const highCount   = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount    = findings.filter((f) => f.severity === 'low').length

  const summary =
    findings.length === 0
      ? 'No VPN or remote access security drift detected.'
      : `${findings.length} VPN/remote access rule${findings.length === 1 ? '' : 's'} triggered ` +
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
