// WS-88 — DNS Security Configuration Drift Detector:
// pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to DNS server configuration, DNS resolver settings, encrypted DNS proxy
// configuration, and RPKI validation setup.  A modified named.conf can open
// recursive queries to the public internet; a changed dnsmasq.conf can
// redirect resolution to a malicious upstream; an altered Pi-hole config can
// disable the DNS-level ad/malware filter.
//
// DISTINCT from:
//   WS-68  networkFirewallDrift    — DNS_SECURITY_DRIFT in WS-68 covers DNSSEC
//                                   key material (.key/.private files in dns/bind/
//                                   named/dnssec/ dirs); WS-88 covers the DNS
//                                   daemon configuration files themselves
//   WS-72  serviceMeshSecurityDrift — Istio service-discovery configs (not DNS
//                                   server configs); WS-88 is for external/
//                                   authoritative/recursive DNS daemons
//   WS-84  vpnRemoteAccessDrift    — VPN-level DNS split-tunneling; WS-88 covers
//                                   the DNS server/resolver infrastructure itself
//   WS-75  webServerSecurityDrift  — nginx/Apache configs; WS-88 is DNS only
//
// Covered rule groups (8 rules):
//
//   BIND_DNS_CONFIG_DRIFT           — ISC BIND named.conf authoritative/recursive
//                                     DNS server configuration
//   UNBOUND_RESOLVER_DRIFT          — Unbound validating DNS resolver configuration
//   POWERDNS_CONFIG_DRIFT           — PowerDNS authoritative and Recursor configs
//   COREDNS_CONFIG_DRIFT            — CoreDNS Corefile and plugin configuration
//                                     (common in Kubernetes clusters)
//   DNSMASQ_CONFIG_DRIFT            — dnsmasq DNS/DHCP forwarder configuration
//   PIHOLE_CONFIG_DRIFT             — Pi-hole DNS-level ad/malware blocking config
//   DNS_OVER_HTTPS_CONFIG_DRIFT     — Encrypted DNS proxy configuration:
//                                     dnscrypt-proxy, Stubby (DNS-over-TLS)
//   DNS_RPKI_VALIDATION_DRIFT       — RPKI route-origin validation config:
//                                     Routinator, FORT, rpki-client
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Vendor directory exclusion applied to all paths.
//   • Same penalty/cap scoring model as WS-60–87 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (firstPath + matchCount).
//   • named.conf / named-local.conf / named-options.conf are globally unambiguous
//     BIND DNS server configuration filenames — matched without directory gating.
//   • unbound.conf is globally unambiguous for the Unbound DNS resolver.
//   • pdns.conf is globally unambiguous for PowerDNS authoritative server.
//   • "Corefile" (lowercased: "corefile") is globally unambiguous for CoreDNS.
//   • dnsmasq.conf is globally unambiguous for the dnsmasq daemon.
//   • dnscrypt-proxy.toml / stubby.yml are globally unambiguous DoH/DoT configs.
//   • routinator.conf is globally unambiguous for the Routinator RPKI validator.
//   • All ungated Set entries stored lowercase (lesson from WS-83).
//
// Exports:
//   isDnsRpkiValidatorConfig     — user contribution point (see JSDoc below)
//   DNS_SECURITY_RULES           — readonly rule registry
//   scanDnsSecurityDrift         — main scanner, returns DnsSecurityDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type DnsSecurityRuleId =
  | 'BIND_DNS_CONFIG_DRIFT'
  | 'UNBOUND_RESOLVER_DRIFT'
  | 'POWERDNS_CONFIG_DRIFT'
  | 'COREDNS_CONFIG_DRIFT'
  | 'DNSMASQ_CONFIG_DRIFT'
  | 'PIHOLE_CONFIG_DRIFT'
  | 'DNS_OVER_HTTPS_CONFIG_DRIFT'
  | 'DNS_RPKI_VALIDATION_DRIFT'

export type DnsSecuritySeverity = 'high' | 'medium' | 'low'
export type DnsSecurityRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type DnsSecurityDriftFinding = {
  ruleId: DnsSecurityRuleId
  severity: DnsSecuritySeverity
  matchedPath: string
  matchCount: number
  description: string
  recommendation: string
}

export type DnsSecurityDriftResult = {
  riskScore: number
  riskLevel: DnsSecurityRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: DnsSecurityDriftFinding[]
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

const BIND_DIRS      = ['bind/', '.bind/', 'named/', 'bind-config/', 'dns/bind/', 'dns/named/', 'etc/bind/', 'etc/named/']
const UNBOUND_DIRS   = ['unbound/', 'unbound-config/', 'dns/unbound/', 'etc/unbound/', 'unbound.conf.d/']
const POWERDNS_DIRS  = ['powerdns/', 'pdns/', 'dns/powerdns/', 'pdns-recursor/', 'pdns.d/', 'recursor.d/', 'powerdns-recursor/']
const COREDNS_DIRS   = ['coredns/', 'dns/coredns/', 'coredns-config/']
const DNSMASQ_DIRS   = ['dnsmasq/', 'dnsmasq.d/', 'dns/dnsmasq/', 'etc/dnsmasq.d/']
const PIHOLE_DIRS    = ['pihole/', '.pihole/', 'pi-hole/', 'pihole-config/', 'pihole-data/']
const DOH_DIRS       = ['dnscrypt-proxy/', 'dns-crypt/', 'stubby/', 'dns-over-https/', 'dns-over-tls/', 'doh/', 'dot/', 'encrypted-dns/']
const RPKI_DIRS      = ['rpki/', 'routinator/', 'rpki-client/', 'rpki-validator/', 'fort/', 'rpki-config/', 'stayrtr/']

function inAnyDir(pathLower: string, dirs: readonly string[]): boolean {
  return dirs.some((d) => pathLower.includes(d))
}

// ---------------------------------------------------------------------------
// Rule 1: BIND_DNS_CONFIG_DRIFT (high)
// ISC BIND named.conf authoritative/recursive DNS server configuration
// ---------------------------------------------------------------------------

const BIND_UNGATED = new Set([
  'named.conf',               // BIND main configuration — globally unambiguous
  'named-local.conf',         // BIND local zones include — globally unambiguous
  'named-options.conf',       // BIND options include — globally unambiguous
  'named.conf.local',         // Debian/Ubuntu BIND convention
  'named.conf.options',       // Debian/Ubuntu BIND options convention
  'named.conf.default-zones', // Debian/Ubuntu default zones convention
  'named.conf.log',           // BIND logging configuration
  'rndc.conf',                // BIND remote name daemon control config
  'rndc.key',                 // BIND control channel HMAC key
])

function isBindDnsConfig(pathLower: string, base: string): boolean {
  if (BIND_UNGATED.has(base)) return true

  // named.conf.* convention (Debian-style split config)
  if (base.startsWith('named.conf.')) return true

  // BIND config prefix patterns
  if (base.startsWith('named-') && base.endsWith('.conf')) return true
  if (base.startsWith('bind-') && base.endsWith('.conf')) return true

  if (!inAnyDir(pathLower, BIND_DIRS)) return false

  // Zone files and configs in BIND dirs
  // db.<domain> is the canonical BIND zone file naming convention (e.g. db.example.com)
  if (base.startsWith('db.')) return true
  if (
    base.endsWith('.conf') || base.endsWith('.zone') || base.endsWith('.db') ||
    base === 'zones' || base === 'acl.conf' || base === 'logging.conf' ||
    base === 'keys.conf'
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 2: UNBOUND_RESOLVER_DRIFT (high)
// Unbound validating DNS resolver configuration
// ---------------------------------------------------------------------------

const UNBOUND_UNGATED = new Set([
  'unbound.conf',       // Unbound main configuration — globally unambiguous
  'unbound-anchor.conf',// Unbound trust anchor updater config
  'unbound-control.conf', // Unbound control interface config
])

function isUnboundResolverConfig(pathLower: string, base: string): boolean {
  if (UNBOUND_UNGATED.has(base)) return true

  // Unbound config prefix patterns
  if (base.startsWith('unbound-') && base.endsWith('.conf')) return true
  if (base.startsWith('unbound.') && base.endsWith('.conf')) return true

  if (!inAnyDir(pathLower, UNBOUND_DIRS)) return false

  if (base.endsWith('.conf')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 3: POWERDNS_CONFIG_DRIFT (high)
// PowerDNS authoritative and Recursor configuration
// ---------------------------------------------------------------------------

const POWERDNS_UNGATED = new Set([
  'pdns.conf',          // PowerDNS authoritative server — globally unambiguous
  'pdns-recursor.conf', // PowerDNS Recursor — globally unambiguous
  'pdns.d',             // PowerDNS conf.d directory marker
  'recursor.yml',       // PowerDNS Recursor YAML config (v5+)
])

function isPowerDnsConfig(pathLower: string, base: string): boolean {
  if (POWERDNS_UNGATED.has(base)) return true

  // PowerDNS prefix patterns
  if (base.startsWith('pdns-') && base.endsWith('.conf')) return true
  if (base.startsWith('powerdns-') && base.endsWith('.conf')) return true
  if (base.startsWith('pdns.') && base.endsWith('.conf')) return true

  // recursor.conf is gated — too generic ungated
  if (base === 'recursor.conf' && inAnyDir(pathLower, POWERDNS_DIRS)) return true

  if (!inAnyDir(pathLower, POWERDNS_DIRS)) return false

  if (base.endsWith('.conf') || base.endsWith('.yml') || base.endsWith('.yaml')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 4: COREDNS_CONFIG_DRIFT (high)
// CoreDNS Corefile and plugin configuration
// ---------------------------------------------------------------------------

function isCoreDnsConfig(pathLower: string, base: string): boolean {
  // Corefile is the canonical CoreDNS configuration file name — globally unambiguous
  if (base === 'corefile') return true

  // Corefile.* variants (e.g., Corefile.override in some k8s setups)
  if (base.startsWith('corefile.')) return true

  // CoreDNS-specific prefix patterns
  if (base.startsWith('coredns-') && (base.endsWith('.yaml') || base.endsWith('.conf') || base.endsWith('.json'))) return true
  if (base.startsWith('coredns.') && (base.endsWith('.yaml') || base.endsWith('.conf'))) return true

  if (!inAnyDir(pathLower, COREDNS_DIRS)) return false

  if (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.conf') || base.endsWith('.json')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 5: DNSMASQ_CONFIG_DRIFT (medium)
// dnsmasq DNS/DHCP forwarder configuration
// ---------------------------------------------------------------------------

const DNSMASQ_UNGATED = new Set([
  'dnsmasq.conf',       // dnsmasq main configuration — globally unambiguous
  'dnsmasq.d',          // dnsmasq conf.d directory marker
])

function isDnsmasqConfig(pathLower: string, base: string): boolean {
  if (DNSMASQ_UNGATED.has(base)) return true

  // dnsmasq prefix patterns
  if (base.startsWith('dnsmasq-') && base.endsWith('.conf')) return true
  if (base.startsWith('dnsmasq.') && base.endsWith('.conf')) return true

  if (!inAnyDir(pathLower, DNSMASQ_DIRS)) return false

  if (base.endsWith('.conf') || base.endsWith('.list') || base === 'hosts') return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 6: PIHOLE_CONFIG_DRIFT (medium)
// Pi-hole DNS-level ad/malware blocking configuration
// ---------------------------------------------------------------------------

const PIHOLE_UNGATED = new Set([
  'pihole.conf',      // Pi-hole configuration
  'ftl.conf',         // Pi-hole FTL (faster-than-light) config — globally unambiguous
  '.pihole.conf',     // dot-prefixed variant
])

function isPiHoleConfig(pathLower: string, base: string): boolean {
  if (PIHOLE_UNGATED.has(base)) return true

  // Pi-hole prefix patterns
  if (base.startsWith('pihole-') && (base.endsWith('.conf') || base.endsWith('.list') || base.endsWith('.txt'))) return true
  if (base.startsWith('pihole.') && base.endsWith('.conf')) return true

  if (!inAnyDir(pathLower, PIHOLE_DIRS)) return false

  // Pi-hole conventional config files gated on pihole dirs
  if (
    base === 'setupvars.conf'   || base === 'adlists.list'  ||
    base === 'blacklist.txt'    || base === 'whitelist.txt'  ||
    base === 'regex.list'       || base === 'gravity.list'   ||
    base === 'custom.list'      || base === 'dnsmasq.conf'   ||
    base.endsWith('.conf')      || base.endsWith('.list')    ||
    base.endsWith('.txt')
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 7: DNS_OVER_HTTPS_CONFIG_DRIFT (medium)
// Encrypted DNS proxy configuration: dnscrypt-proxy, Stubby (DoT)
// ---------------------------------------------------------------------------

const DOH_UNGATED = new Set([
  'dnscrypt-proxy.toml',  // dnscrypt-proxy main config — globally unambiguous
  'dnscrypt-proxy.yaml',  // YAML variant
  'stubby.yml',           // Stubby DoT resolver config — globally unambiguous
  'stubby.yaml',          // alternative extension
  '.stubby.yml',          // dot-prefixed variant
])

function isDnsOverHttpsConfig(pathLower: string, base: string): boolean {
  if (DOH_UNGATED.has(base)) return true

  // dnscrypt-proxy prefix patterns
  if (base.startsWith('dnscrypt-proxy') && (base.endsWith('.toml') || base.endsWith('.yaml') || base.endsWith('.yml'))) return true
  if (base.startsWith('dnscrypt-') && (base.endsWith('.toml') || base.endsWith('.conf') || base.endsWith('.yaml') || base.endsWith('.yml'))) return true

  // Stubby prefix patterns
  if (base.startsWith('stubby') && (base.endsWith('.yml') || base.endsWith('.yaml') || base.endsWith('.conf'))) return true

  if (!inAnyDir(pathLower, DOH_DIRS)) return false

  if (base.endsWith('.toml') || base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.conf') || base.endsWith('.json')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 8: DNS_RPKI_VALIDATION_DRIFT (low)
// RPKI route-origin validation configuration
// ---------------------------------------------------------------------------

/**
 * Returns true if the given path is an RPKI route-origin validation daemon
 * configuration file.
 *
 * CONTRIBUTION POINT — implement the core detection logic here.
 *
 * Constraints to respect:
 *   • routinator.conf is globally unambiguous (Routinator RPKI validator by
 *     NLnet Labs) — always return true for this basename.
 *   • fort.conf is globally unambiguous for the FORT RPKI validator.
 *   • rpki-client.conf is globally unambiguous.
 *   • Exclude IaC tool directories (terraform/, pulumi/) to avoid false positives
 *     on cloud routing resource configs that mention RPKI.
 *   • stayrtr.conf and gortr.conf are StayRTR / GoRTR RTR-protocol server configs.
 *   • rpki-*.conf prefix and routinator-*.conf prefix patterns are safe ungated.
 *   • Generic names like config.yaml should only match when inside RPKI_DIRS.
 *
 * @param pathLower Normalised (lowercase, forward-slash) file path from repo root.
 * @param base Basename extracted from pathLower (already lowercase).
 * @returns true if this file is an RPKI validation daemon configuration file.
 */
export function isDnsRpkiValidatorConfig(pathLower: string, base: string): boolean {
  // Exclude IaC tool directories
  if (pathLower.includes('terraform/') || pathLower.includes('pulumi/')) return false

  // Globally unambiguous RPKI validator config names
  if (base === 'routinator.conf') return true
  if (base === 'fort.conf') return true
  if (base === 'rpki-client.conf') return true
  if (base === 'stayrtr.conf') return true
  if (base === 'gortr.conf') return true

  // RPKI tool prefix patterns (safe ungated)
  if (base.startsWith('rpki-') && (base.endsWith('.conf') || base.endsWith('.yaml') || base.endsWith('.toml'))) return true
  if (base.startsWith('routinator-') && (base.endsWith('.conf') || base.endsWith('.toml'))) return true
  if (base.startsWith('fort-') && base.endsWith('.conf')) return true

  if (!inAnyDir(pathLower, RPKI_DIRS)) return false

  // Generic config names gated on RPKI dirs
  if (
    base === 'config.toml' || base === 'config.conf' ||
    base === 'config.yaml' || base.endsWith('.conf') ||
    base.endsWith('.toml') || base.endsWith('.yaml')
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

type DnsSecurityRule = {
  id: DnsSecurityRuleId
  severity: DnsSecuritySeverity
  match: (pathLower: string, base: string) => boolean
  description: string
  recommendation: string
}

export const DNS_SECURITY_RULES: readonly DnsSecurityRule[] = [
  {
    id: 'BIND_DNS_CONFIG_DRIFT',
    severity: 'high',
    match: isBindDnsConfig,
    description: 'ISC BIND DNS server configuration was modified. Changes to named.conf can open recursive queries to unauthorized hosts, modify ACLs, disable DNSSEC validation, or redirect zone transfers.',
    recommendation: 'Review ACL changes (allow-recursion, allow-query), DNSSEC validation settings (dnssec-validation), and zone transfer policies (allow-transfer). Ensure RNDC control channel keys are rotated after any config change.',
  },
  {
    id: 'UNBOUND_RESOLVER_DRIFT',
    severity: 'high',
    match: isUnboundResolverConfig,
    description: 'Unbound DNS resolver configuration was modified. Changes can disable DNSSEC validation, alter access control lists, redirect queries to untrusted upstreams, or enable DNS rebinding.',
    recommendation: 'Verify DNSSEC validation remains enabled (val-permissive-mode: no), access-control lists are restricted, and forward-zone upstreams are trusted resolver IPs. Check that do-not-query-localhost is set.',
  },
  {
    id: 'POWERDNS_CONFIG_DRIFT',
    severity: 'high',
    match: isPowerDnsConfig,
    description: 'PowerDNS authoritative or Recursor configuration was modified. Changes can expose zone data to unauthorized hosts, disable DNSSEC signing, or alter API authentication settings.',
    recommendation: 'Review allow-axfr-ips (zone transfer), webserver-allow-from, api-key rotation, and dnssec settings. Ensure the PowerDNS API endpoint is not exposed without authentication.',
  },
  {
    id: 'COREDNS_CONFIG_DRIFT',
    severity: 'high',
    match: isCoreDnsConfig,
    description: 'CoreDNS Corefile or plugin configuration was modified. Changes to CoreDNS (commonly used as Kubernetes cluster DNS) can affect service discovery, forward plugin upstreams, and DNS-based admission control.',
    recommendation: 'Review forward plugin upstream addresses, cache TTL settings, and any rewrite/redirect rules. Ensure the health and metrics plugins do not expose sensitive data externally.',
  },
  {
    id: 'DNSMASQ_CONFIG_DRIFT',
    severity: 'medium',
    match: isDnsmasqConfig,
    description: 'dnsmasq DNS/DHCP forwarder configuration was modified. Changes can redirect DNS queries to malicious upstreams, alter DHCP address assignments, or disable DNS rebinding protection.',
    recommendation: 'Review upstream server addresses (server= directives), rebind-protection setting, and any address= overrides. Ensure local-only-domains are not accidentally exposed.',
  },
  {
    id: 'PIHOLE_CONFIG_DRIFT',
    severity: 'medium',
    match: isPiHoleConfig,
    description: 'Pi-hole DNS-level filtering configuration was modified. Changes can disable malware/ad blocking, alter upstream resolver addresses, or modify the DNS-based filtering blocklists.',
    recommendation: 'Verify upstream DNS servers (PIHOLE_DNS_ settings) remain trusted, DNSSEC is still enabled, and blocklist sources have not been tampered with. Review any whitelist additions.',
  },
  {
    id: 'DNS_OVER_HTTPS_CONFIG_DRIFT',
    severity: 'medium',
    match: isDnsOverHttpsConfig,
    description: 'DNS-over-HTTPS or DNS-over-TLS proxy configuration (dnscrypt-proxy, Stubby) was modified. Changes can redirect encrypted DNS traffic to untrusted resolvers or disable certificate verification.',
    recommendation: 'Verify server_names and resolver endpoints point to known-good DoH/DoT providers, certificate verification is enabled, and no fallback to plaintext DNS is configured.',
  },
  {
    id: 'DNS_RPKI_VALIDATION_DRIFT',
    severity: 'low',
    match: isDnsRpkiValidatorConfig,
    description: 'RPKI route-origin validation daemon configuration (Routinator, FORT, rpki-client) was modified. Changes can disable BGP hijack detection or alter the RPKI trust anchor repositories.',
    recommendation: 'Verify trust anchor URLs point to legitimate RPKI repositories (ARIN/RIPE/APNIC/LACNIC/AFRINIC), that the RTR server port and access controls remain restricted, and that RPKI validation is not disabled.',
  },
]

// ---------------------------------------------------------------------------
// Path normalisation
// ---------------------------------------------------------------------------

function normalise(raw: string): string {
  return raw.replace(/\\/g, '/').toLowerCase()
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

const HIGH_PENALTY   = 15
const MEDIUM_PENALTY = 8
const LOW_PENALTY    = 4
const HIGH_CAP       = 45
const MEDIUM_CAP     = 25
const LOW_CAP        = 15

function computeRiskScore(findings: DnsSecurityDriftFinding[]): number {
  let highRaw = 0, mediumRaw = 0, lowRaw = 0
  for (const f of findings) {
    if (f.severity === 'high')   highRaw   += HIGH_PENALTY
    if (f.severity === 'medium') mediumRaw += MEDIUM_PENALTY
    if (f.severity === 'low')    lowRaw    += LOW_PENALTY
  }
  return Math.min(100, Math.min(highRaw, HIGH_CAP) + Math.min(mediumRaw, MEDIUM_CAP) + Math.min(lowRaw, LOW_CAP))
}

function computeRiskLevel(score: number): DnsSecurityRiskLevel {
  if (score === 0)  return 'none'
  if (score < 15)   return 'low'
  if (score < 45)   return 'medium'
  if (score < 80)   return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

export function scanDnsSecurityDrift(changedFiles: string[]): DnsSecurityDriftResult {
  const findings: DnsSecurityDriftFinding[] = []

  for (const rule of DNS_SECURITY_RULES) {
    let firstPath = ''
    let matchCount = 0

    for (const raw of changedFiles) {
      const pathLower = normalise(raw)
      if (isVendor(pathLower)) continue
      const base = pathLower.split('/').pop() ?? pathLower
      if (!rule.match(pathLower, base)) continue
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
  findings.sort((a, b) => {
    const order = { high: 0, medium: 1, low: 2 }
    return order[a.severity] - order[b.severity]
  })

  const riskScore = computeRiskScore(findings)
  const riskLevel = computeRiskLevel(riskScore)

  const highCount   = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount    = findings.filter((f) => f.severity === 'low').length

  let summary: string
  if (findings.length === 0) {
    summary = 'No DNS security configuration drift detected.'
  } else {
    const parts: string[] = []
    if (highCount > 0)   parts.push(`${highCount} high`)
    if (mediumCount > 0) parts.push(`${mediumCount} medium`)
    if (lowCount > 0)    parts.push(`${lowCount} low`)
    summary = `DNS security drift detected: ${parts.join(', ')} severity finding${findings.length !== 1 ? 's' : ''} across ${findings.length} rule${findings.length !== 1 ? 's' : ''} (risk score ${riskScore}/100).`
  }

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
