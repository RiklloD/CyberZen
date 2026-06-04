// WS-68 — Network Perimeter & Firewall Configuration Drift Detector:
// pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to network-level access control and firewall configuration files. This
// scanner focuses on the *host/network perimeter layer* — static rules and
// policies that control which traffic reaches services at the OS or proxy level.
//
// DISTINCT from:
//   WS-60  securityConfigDriftResults — application-level security *options*
//                                       (CORS, CSP, TLS settings, WAF config)
//   WS-62  cloudSecurityDriftResults  — cloud IAM/KMS/network security groups
//                                       (Terraform/CDK cloud infrastructure)
//   WS-63  containerHardeningDriftResults — k8s NetworkPolicy, RBAC
//   WS-65  apiSecurityDriftResults    — API rate-limiting, GraphQL security
//   WS-67  runtimeSecurityDriftResults — runtime enforcement (fail2ban, IDS,
//                                        Falco, auditd)
//
// WS-68 vs WS-62: WS-62 covers cloud *infrastructure* security (Terraform
//   SGs, IAM, KMS). WS-68 covers host/OS-level firewall rules and network
//   perimeter configs (iptables, nftables, HAProxy ACLs, UFW, VPN, DNS).
//
// WS-68 vs WS-67: WS-67 covers runtime *detection and response* (fail2ban
//   banning, IDS rules, Falco alerting). WS-68 covers static *access control*
//   rules that define what traffic is allowed or blocked (iptables ACCEPT/
//   DROP rules, HAProxy ACL allow/deny).
//
// Covered rule groups (8 rules):
//
//   IPTABLES_RULES_DRIFT         — iptables / ip6tables rule files
//   NFTABLES_CONFIG_DRIFT        — nftables table/chain configuration
//   HAPROXY_SECURITY_CONFIG_DRIFT — HAProxy frontend/backend ACL config
//   UFW_RULES_DRIFT              — UFW user rules and firewall profiles
//   VPN_SECURITY_CONFIG_DRIFT    — WireGuard/OpenVPN connection configs
//   DNS_SECURITY_DRIFT           — BIND named.conf and DNSSEC configs
//   PROXY_ACCESS_CONFIG_DRIFT    — Squid/nginx proxy ACL configs  ← user contribution
//   FIREWALLD_ZONE_DRIFT         — firewalld zone XML configuration
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Paths inside vendor directories excluded.
//   • Same penalty/cap scoring model as WS-60–67 for consistency.
//   • Dedup-per-rule: one finding per triggered rule.
//   • .nft extension is unambiguous for nftables.
//   • .ovpn extension is unambiguous for OpenVPN configs.
//   • iptables uses exact filenames (rules.v4/rules.v6) to avoid collision
//     with the .rules extension used by WS-67 (auditd/IDS rules).
//   • HAProxy uses .cfg extension gated on basename or haproxy/ directory.
//   • firewalld zone names gated on firewalld/ directory to avoid matching
//     unrelated public.xml/internal.xml files.
//
// Exports:
//   isProxyAccessConfig            — user contribution point (see JSDoc below)
//   NETWORK_FIREWALL_RULES         — readonly rule registry
//   scanNetworkFirewallDrift       — main scanner, returns NetworkFirewallDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type NetworkFirewallRuleId =
  | 'IPTABLES_RULES_DRIFT'
  | 'NFTABLES_CONFIG_DRIFT'
  | 'HAPROXY_SECURITY_CONFIG_DRIFT'
  | 'UFW_RULES_DRIFT'
  | 'VPN_SECURITY_CONFIG_DRIFT'
  | 'DNS_SECURITY_DRIFT'
  | 'PROXY_ACCESS_CONFIG_DRIFT'
  | 'FIREWALLD_ZONE_DRIFT'

export type NetworkFirewallSeverity = 'high' | 'medium' | 'low'
export type NetworkFirewallRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type NetworkFirewallDriftFinding = {
  ruleId: NetworkFirewallRuleId
  severity: NetworkFirewallSeverity
  matchedPath: string
  matchCount: number
  description: string
  recommendation: string
}

export type NetworkFirewallDriftResult = {
  riskScore: number
  riskLevel: NetworkFirewallRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: NetworkFirewallDriftFinding[]
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
// Detection helpers — IPTABLES_RULES_DRIFT
// ---------------------------------------------------------------------------

const IPTABLES_EXACT = new Set([
  'iptables.rules',
  'ip6tables.rules',
  'rules.v4',
  'rules.v6',
  'iptables-save',
  'ip6tables-save',
  'iptables-restore',
])

const IPTABLES_DIRS = ['iptables/', 'netfilter/']

function isIptablesRuleFile(pathLower: string, base: string, ext: string): boolean {
  if (IPTABLES_EXACT.has(base)) return true
  for (const dir of IPTABLES_DIRS) {
    if (pathLower.includes(dir)) {
      if (ext === '.rules' || ext === '.conf' || ext === '' || base.startsWith('iptables')) return true
    }
  }
  // Basename starts with iptables- (e.g. iptables-custom.rules)
  if (base.startsWith('iptables-') || base.startsWith('ip6tables-')) return true
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — NFTABLES_CONFIG_DRIFT
// ---------------------------------------------------------------------------

const NFTABLES_EXACT = new Set(['nftables.conf', 'nftables.nft', 'nftables'])
const NFTABLES_DIRS  = ['nftables/', 'nf/']

function isNftablesConfigFile(pathLower: string, base: string, ext: string): boolean {
  if (ext === '.nft') return true // .nft extension is unambiguous
  if (NFTABLES_EXACT.has(base)) return true
  for (const dir of NFTABLES_DIRS) {
    if (pathLower.includes(dir) && (ext === '.conf' || ext === '.nft' || ext === '')) return true
  }
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — HAPROXY_SECURITY_CONFIG_DRIFT
// ---------------------------------------------------------------------------

const HAPROXY_EXACT = new Set([
  'haproxy.cfg',
  'haproxy.conf',
  'haproxy.yaml',
  'haproxy.yml',
])

const HAPROXY_DIRS  = ['haproxy/']
const HAPROXY_EXTS  = new Set(['.cfg', '.conf'])
const HAPROXY_STEMS = ['haproxy', 'ha-proxy', 'frontend.cfg', 'backend.cfg']

function isHaproxySecurityConfig(pathLower: string, base: string, ext: string): boolean {
  if (HAPROXY_EXACT.has(base)) return true
  for (const stem of HAPROXY_STEMS) {
    if (base.startsWith(stem) && HAPROXY_EXTS.has(ext)) return true
  }
  for (const dir of HAPROXY_DIRS) {
    if (pathLower.includes(dir) && (HAPROXY_EXTS.has(ext) || ext === '.yaml' || ext === '.yml')) return true
  }
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — UFW_RULES_DRIFT
// ---------------------------------------------------------------------------

// These filenames require the ufw/ directory gate to avoid false positives —
// "user.rules", "before.rules" are generic names that could appear anywhere.
const UFW_GATED_EXACT = new Set([
  'user.rules', 'user6.rules',
  'before.rules', 'after.rules',
  'before6.rules', 'after6.rules',
  'before.init', 'after.init',
])

// These are unambiguous standalone — ufw.conf only belongs to UFW.
const UFW_UNGATED_EXACT = new Set(['ufw.conf'])
const UFW_DIRS = ['ufw/']

function isUfwRulesFile(pathLower: string, base: string): boolean {
  if (UFW_UNGATED_EXACT.has(base)) return true
  for (const dir of UFW_DIRS) {
    if (pathLower.includes(dir) && UFW_GATED_EXACT.has(base)) return true
  }
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — VPN_SECURITY_CONFIG_DRIFT
// ---------------------------------------------------------------------------

const WIREGUARD_DIRS = ['wireguard/', 'wg/', 'wg-conf/']
const OPENVPN_DIRS   = ['openvpn/', 'vpn/', 'ovpn/']
const VPN_EXACT      = new Set(['openvpn.conf', 'vpn.conf', 'wireguard.conf'])

function isVpnConfigFile(pathLower: string, base: string, ext: string): boolean {
  if (ext === '.ovpn') return true // .ovpn extension is unambiguous
  if (VPN_EXACT.has(base)) return true
  // WireGuard interface config: wg0.conf, wg1.conf, wg-prod.conf
  if (/^wg\d+\.conf$/.test(base) || (base.startsWith('wg-') && ext === '.conf')) return true
  for (const dir of WIREGUARD_DIRS) {
    if (pathLower.includes(dir) && ext === '.conf') return true
  }
  for (const dir of OPENVPN_DIRS) {
    if (pathLower.includes(dir) && (ext === '.conf' || ext === '.ovpn' || ext === '.key' || ext === '.crt')) return true
  }
  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — DNS_SECURITY_DRIFT
// ---------------------------------------------------------------------------

const NAMED_EXACT = new Set([
  'named.conf',
  'named.conf.local',
  'named.conf.options',
  'named.conf.default-zones',
  'named.conf.log',
  'bind.conf',
  'rndc.conf',
  'rndc.key',
])

const DNS_DIRS    = ['dns/', 'bind/', 'named/', 'dnssec/', 'zones/']
const DNS_EXTENSIONS = new Set(['.zone', '.db'])

function isDnsSecurityFile(pathLower: string, base: string, ext: string): boolean {
  if (NAMED_EXACT.has(base)) return true
  // DNSSEC key files in a dns/dnssec directory (not standalone — .key is too generic)
  for (const dir of DNS_DIRS) {
    if (pathLower.includes(dir)) {
      if (DNS_EXTENSIONS.has(ext)) return true
      if (base.startsWith('named') && ext === '.conf') return true
      if (base === 'bind.conf' || base === 'rndc.conf') return true
      // DNSSEC key/DS-set files inside a dns directory
      if (ext === '.key' || ext === '.private' || base.startsWith('dsset-') || base.startsWith('keyset-')) return true
    }
  }
  return false
}

// ---------------------------------------------------------------------------
// PROXY_ACCESS_CONFIG_DRIFT — user contribution point
// ---------------------------------------------------------------------------

/**
 * isProxyAccessConfig — determines whether a file path is a proxy or
 * HTTP-level access-control configuration file belonging to WS-68.
 *
 * Context: This rule covers Squid proxy configs and nginx/other HTTP
 * proxy configs that specify *who can reach what* (IP whitelists,
 * geo-blocks, access control lists) rather than:
 *   WS-60 — application-level CORS/CSP/TLS options
 *   WS-65 — API rate-limiting (rate-limit.config.* / throttle.yaml)
 *   WS-67 — runtime IDS/fail2ban rules
 *
 * Design trade-offs to consider:
 *
 *   (a) Squid is straightforward: `squid.conf` basename or any file in a
 *       `squid/` directory is unambiguous.
 *
 *   (b) nginx.conf is the hard case. Many repos have nginx.conf files for
 *       serving static assets, TLS termination, or API proxying — those
 *       belong to WS-60/WS-65. Only nginx configs that are specifically
 *       about *access control* (IP blocking, geo-restrictions, allow/deny
 *       lists) belong here. Use a combination of:
 *       - Directory context: file is in `access-control/`, `geo/`, `proxy/`
 *         or has a basename like `access.conf`, `geo-block.conf`
 *       - Keyword in basename: 'blacklist', 'whitelist', 'deny', 'allow',
 *         'geo', 'acl', 'block', 'filter'
 *
 *   (c) Other proxies: HAProxy is handled by HAPROXY_SECURITY_CONFIG_DRIFT.
 *       Traefik middlewares that do IP filtering could qualify here.
 *
 * Implement the function to return true when the path represents a squid,
 * nginx, or other proxy access-control config (not rate-limiting or
 * application security), false otherwise.
 */
export function isProxyAccessConfig(pathLower: string): boolean {
  const base = pathLower.split('/').at(-1) ?? pathLower
  const ext  = base.includes('.') ? `.${base.split('.').at(-1)}` : ''

  // Squid proxy — unambiguous
  if (base === 'squid.conf' || base === 'squid.conf.d' || pathLower.includes('squid/')) return true

  // Access control keyword in the filename (any proxy type)
  const ACCESS_KEYWORDS = [
    'blacklist', 'whitelist', 'deny-list', 'allow-list',
    'ip-block', 'ipblock', 'geo-block', 'geoblock', 'geo-filter',
    'access-control', 'acl', 'block-list', 'blocklist',
  ]
  for (const kw of ACCESS_KEYWORDS) {
    if (base.includes(kw)) return true
  }

  // nginx in an access-control or geo/proxy directory context
  const PROXY_DIRS = ['access-control/', 'geo/', 'proxy-rules/', 'ip-filter/', 'ip-block/']
  const CONFIG_EXTS = new Set(['.conf', '.yaml', '.yml', '.json'])
  for (const dir of PROXY_DIRS) {
    if (pathLower.includes(dir) && CONFIG_EXTS.has(ext)) return true
  }

  // Traefik IP whitelisting middleware files
  if (
    (base.includes('middleware') || base.includes('ipwhitelist') || base.includes('ip-whitelist')) &&
    (pathLower.includes('traefik/') || pathLower.includes('proxy/'))
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — FIREWALLD_ZONE_DRIFT
// ---------------------------------------------------------------------------

// Standard firewalld zone names — require directory gate to avoid matching
// unrelated XML files named public.xml or internal.xml.
const FIREWALLD_ZONE_NAMES = new Set([
  'public.xml', 'internal.xml', 'external.xml', 'work.xml',
  'home.xml', 'dmz.xml', 'trusted.xml', 'block.xml', 'drop.xml',
  'nm-shared.xml',
])

const FIREWALLD_DIRS    = ['firewalld/']
const FIREWALLD_UNGATED = new Set(['firewalld.conf'])

function isFirewalldZoneFile(pathLower: string, base: string, ext: string): boolean {
  if (FIREWALLD_UNGATED.has(base)) return true
  for (const dir of FIREWALLD_DIRS) {
    if (pathLower.includes(dir)) {
      if (ext === '.xml') return true
      if (base === 'firewalld.conf') return true
    }
  }
  // Explicit zone name WITHOUT directory — only match if base is unambiguous
  if (FIREWALLD_ZONE_NAMES.has(base) && pathLower.includes('firewalld')) return true
  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

type NetworkFirewallRule = {
  id: NetworkFirewallRuleId
  severity: NetworkFirewallSeverity
  description: string
  recommendation: string
  matches: (pathLower: string, base: string, ext: string) => boolean
}

export const NETWORK_FIREWALL_RULES: readonly NetworkFirewallRule[] = [
  {
    id: 'IPTABLES_RULES_DRIFT',
    severity: 'high',
    description: 'iptables or ip6tables firewall rule files were modified. Changes can open or close host-level ports and affect all traffic to the host.',
    recommendation: 'Review the diff to confirm no rules were relaxed (e.g. ACCEPT replacing DROP/REJECT). Test against a staging host before merging.',
    matches: (p, b, e) => isIptablesRuleFile(p, b, e),
  },
  {
    id: 'NFTABLES_CONFIG_DRIFT',
    severity: 'high',
    description: 'nftables configuration files were modified. nftables replaces iptables on modern Linux distributions; changes affect host-level packet filtering.',
    recommendation: 'Verify that no ACCEPT rules were added for sensitive ports and that the base policy (DROP/REJECT) is still set for inet filter forward/output chains.',
    matches: (p, b, e) => isNftablesConfigFile(p, b, e),
  },
  {
    id: 'HAPROXY_SECURITY_CONFIG_DRIFT',
    severity: 'high',
    description: 'HAProxy configuration files were modified. HAProxy ACLs and frontend/backend rules control which clients can reach services and under what conditions.',
    recommendation: 'Review ACL additions and default backend changes. Ensure security-sensitive routes still require client authentication or IP restriction where configured.',
    matches: (p, b, e) => isHaproxySecurityConfig(p, b, e),
  },
  {
    id: 'UFW_RULES_DRIFT',
    severity: 'medium',
    description: 'UFW (Uncomplicated Firewall) rule files were modified. UFW manages iptables rules; changes can expose services on the host.',
    recommendation: 'Confirm that newly allowed ports are intentional. Verify the default policy is still "deny incoming" and that no overly broad allow rules (e.g. 0.0.0.0/0 on port 22) were added.',
    matches: (p, b) => isUfwRulesFile(p, b),
  },
  {
    id: 'VPN_SECURITY_CONFIG_DRIFT',
    severity: 'medium',
    description: 'VPN configuration files (WireGuard or OpenVPN) were modified. Changes may affect which peers are allowed to connect or which subnets are accessible over the VPN.',
    recommendation: 'Review added/removed peer blocks (WireGuard) or client/server certificates (OpenVPN). Confirm that AllowedIPs restrictions are maintained and no wildcard routes were added.',
    matches: (p, b, e) => isVpnConfigFile(p, b, e),
  },
  {
    id: 'DNS_SECURITY_DRIFT',
    severity: 'medium',
    description: 'DNS server configuration files (BIND named.conf or DNSSEC keys/zones) were modified. Misconfiguration can enable DNS zone transfers, cache poisoning, or DNSSEC validation bypass.',
    recommendation: 'Verify that zone-transfer ACLs (allow-transfer) have not been relaxed. Confirm DNSSEC signing keys have not been replaced with weaker equivalents.',
    matches: (p, b, e) => isDnsSecurityFile(p, b, e),
  },
  {
    id: 'PROXY_ACCESS_CONFIG_DRIFT',
    severity: 'medium',
    description: 'Proxy or HTTP access-control configuration files (Squid, nginx geo/ACL, Traefik IP filtering) were modified. Changes may affect IP allowlists, geo-blocks, or client access restrictions.',
    recommendation: 'Review removed deny rules or expanded CIDR ranges. Ensure IP allowlisting rules still cover only intended client ranges and that geo-block patterns remain complete.',
    matches: (p) => isProxyAccessConfig(p),
  },
  {
    id: 'FIREWALLD_ZONE_DRIFT',
    severity: 'low',
    description: 'firewalld zone configuration files were modified. Zone changes control which services and ports are accessible from network segments assigned to each zone.',
    recommendation: 'Confirm that no services were added to the "public" zone unintentionally. Review rich-rules for ACCEPT entries that may bypass the default zone policy.',
    matches: (p, b, e) => isFirewalldZoneFile(p, b, e),
  },
]

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

function penaltyFor(sev: NetworkFirewallSeverity, count: number): number {
  switch (sev) {
    case 'high':   return Math.min(count * HIGH_PENALTY_PER, HIGH_PENALTY_CAP)
    case 'medium': return Math.min(count * MED_PENALTY_PER,  MED_PENALTY_CAP)
    case 'low':    return Math.min(count * LOW_PENALTY_PER,  LOW_PENALTY_CAP)
  }
}

function toRiskLevel(score: number): NetworkFirewallRiskLevel {
  if (score === 0)  return 'none'
  if (score < 20)  return 'low'
  if (score < 45)  return 'medium'
  if (score < 70)  return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Main scanner
// ---------------------------------------------------------------------------

export function scanNetworkFirewallDrift(filePaths: string[]): NetworkFirewallDriftResult {
  if (filePaths.length === 0) return emptyResult()

  // Normalize and exclude vendor paths
  const paths = filePaths
    .map((p) => p.replace(/\\/g, '/'))
    .filter((p) => {
      const lower = p.toLowerCase()
      return !VENDOR_DIRS.some((d) => lower.includes(d))
    })

  if (paths.length === 0) return emptyResult()

  // Accumulate matches per rule
  const accumulated = new Map<NetworkFirewallRuleId, { firstPath: string; count: number }>()

  for (const path of paths) {
    const pathLower = path.toLowerCase()
    const base = pathLower.split('/').at(-1) ?? pathLower
    const ext  = base.includes('.') ? `.${base.split('.').at(-1)}` : ''

    for (const rule of NETWORK_FIREWALL_RULES) {
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

  // Build findings ordered high → medium → low
  const SEVERITY_ORDER: Record<NetworkFirewallSeverity, number> = { high: 0, medium: 1, low: 2 }
  const findings: NetworkFirewallDriftFinding[] = []

  for (const rule of NETWORK_FIREWALL_RULES) {
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

  // Compute score
  let rawScore = 0
  for (const finding of findings) {
    rawScore += penaltyFor(finding.severity, finding.matchCount)
  }
  const riskScore = Math.min(rawScore, 100)
  const riskLevel = toRiskLevel(riskScore)

  const summary = buildSummary(riskLevel, highCount, mediumCount, lowCount, findings)

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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function emptyResult(): NetworkFirewallDriftResult {
  return {
    riskScore: 0, riskLevel: 'none',
    totalFindings: 0, highCount: 0, mediumCount: 0, lowCount: 0,
    findings: [], summary: 'No network firewall or perimeter configuration drift detected.',
  }
}

function buildSummary(
  level: NetworkFirewallRiskLevel,
  high: number,
  medium: number,
  low: number,
  findings: NetworkFirewallDriftFinding[],
): string {
  if (level === 'none') return 'No network firewall or perimeter configuration drift detected.'

  const parts: string[] = []
  if (high > 0)   parts.push(`${high} high`)
  if (medium > 0) parts.push(`${medium} medium`)
  if (low > 0)    parts.push(`${low} low`)

  const topRule = findings[0]
  const topLabel = topRule
    ? topRule.ruleId.replace(/_/g, ' ').toLowerCase()
    : 'network perimeter config'

  return `Network firewall drift detected (${parts.join(', ')} finding${findings.length !== 1 ? 's' : ''}). Most prominent: ${topLabel}. Review changes to ensure no access controls were relaxed.`
}
