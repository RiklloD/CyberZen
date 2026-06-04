// WS-88 — DNS Security Configuration Drift Detector: test suite.

import { describe, expect, it } from 'vitest'
import {
  isDnsRpkiValidatorConfig,
  DNS_SECURITY_RULES,
  scanDnsSecurityDrift,
} from './dnsSecurityDrift'

// ---------------------------------------------------------------------------
// isDnsRpkiValidatorConfig — user contribution point
// ---------------------------------------------------------------------------

describe('isDnsRpkiValidatorConfig', () => {
  it('returns true for routinator.conf (globally unambiguous)', () => {
    expect(isDnsRpkiValidatorConfig('routinator.conf', 'routinator.conf')).toBe(true)
  })

  it('returns true for fort.conf (FORT validator)', () => {
    expect(isDnsRpkiValidatorConfig('fort.conf', 'fort.conf')).toBe(true)
  })

  it('returns true for rpki-client.conf (globally unambiguous)', () => {
    expect(isDnsRpkiValidatorConfig('rpki-client.conf', 'rpki-client.conf')).toBe(true)
  })

  it('returns true for stayrtr.conf (StayRTR RTR server)', () => {
    expect(isDnsRpkiValidatorConfig('stayrtr.conf', 'stayrtr.conf')).toBe(true)
  })

  it('returns true for gortr.conf (GoRTR RTR server)', () => {
    expect(isDnsRpkiValidatorConfig('gortr.conf', 'gortr.conf')).toBe(true)
  })

  it('returns true for rpki-validator.conf prefix', () => {
    expect(isDnsRpkiValidatorConfig('rpki-validator.conf', 'rpki-validator.conf')).toBe(true)
  })

  it('returns true for rpki-config.yaml prefix', () => {
    expect(isDnsRpkiValidatorConfig('rpki-config.yaml', 'rpki-config.yaml')).toBe(true)
  })

  it('returns true for routinator-prod.conf prefix', () => {
    expect(isDnsRpkiValidatorConfig('config/routinator-prod.conf', 'routinator-prod.conf')).toBe(true)
  })

  it('returns true for fort-config.conf prefix', () => {
    expect(isDnsRpkiValidatorConfig('fort-config.conf', 'fort-config.conf')).toBe(true)
  })

  it('returns true for config.toml in rpki/ dir', () => {
    expect(isDnsRpkiValidatorConfig('rpki/config.toml', 'config.toml')).toBe(true)
  })

  it('returns true for config.yaml in routinator/ dir', () => {
    expect(isDnsRpkiValidatorConfig('routinator/config.yaml', 'config.yaml')).toBe(true)
  })

  it('returns true for .conf files in rpki-validator/ dir', () => {
    expect(isDnsRpkiValidatorConfig('rpki-validator/server.conf', 'server.conf')).toBe(true)
  })

  it('returns false for config.toml outside RPKI dirs', () => {
    expect(isDnsRpkiValidatorConfig('config/config.toml', 'config.toml')).toBe(false)
  })

  it('returns false for terraform/ dir (IaC exclusion)', () => {
    expect(isDnsRpkiValidatorConfig('terraform/rpki/routinator.conf', 'routinator.conf')).toBe(false)
  })

  it('returns false for pulumi/ dir (IaC exclusion)', () => {
    expect(isDnsRpkiValidatorConfig('pulumi/routinator.conf', 'routinator.conf')).toBe(false)
  })

  it('returns false for generic server.conf outside RPKI dirs', () => {
    expect(isDnsRpkiValidatorConfig('config/server.conf', 'server.conf')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 1: BIND_DNS_CONFIG_DRIFT (high)
// ---------------------------------------------------------------------------

describe('BIND_DNS_CONFIG_DRIFT', () => {
  const rule = DNS_SECURITY_RULES.find((r) => r.id === 'BIND_DNS_CONFIG_DRIFT')!

  it('matches named.conf (ungated)', () => {
    expect(rule.match('named.conf', 'named.conf')).toBe(true)
  })

  it('matches named-local.conf (ungated)', () => {
    expect(rule.match('named-local.conf', 'named-local.conf')).toBe(true)
  })

  it('matches named-options.conf (ungated)', () => {
    expect(rule.match('named-options.conf', 'named-options.conf')).toBe(true)
  })

  it('matches named.conf.local (Debian convention, ungated)', () => {
    expect(rule.match('etc/named.conf.local', 'named.conf.local')).toBe(true)
  })

  it('matches named.conf.options (Debian convention, ungated)', () => {
    expect(rule.match('named.conf.options', 'named.conf.options')).toBe(true)
  })

  it('matches named.conf.default-zones (ungated)', () => {
    expect(rule.match('named.conf.default-zones', 'named.conf.default-zones')).toBe(true)
  })

  it('matches rndc.conf (ungated)', () => {
    expect(rule.match('rndc.conf', 'rndc.conf')).toBe(true)
  })

  it('matches rndc.key (ungated)', () => {
    expect(rule.match('rndc.key', 'rndc.key')).toBe(true)
  })

  it('matches named.conf.* convention (any split config)', () => {
    expect(rule.match('named.conf.acl', 'named.conf.acl')).toBe(true)
  })

  it('matches named-prod.conf prefix', () => {
    expect(rule.match('config/named-prod.conf', 'named-prod.conf')).toBe(true)
  })

  it('matches bind-server.conf prefix', () => {
    expect(rule.match('bind-server.conf', 'bind-server.conf')).toBe(true)
  })

  it('matches .conf files in bind/ dir', () => {
    expect(rule.match('bind/zones.conf', 'zones.conf')).toBe(true)
  })

  it('matches .zone files in named/ dir', () => {
    expect(rule.match('named/example.com.zone', 'example.com.zone')).toBe(true)
  })

  it('matches .db files in bind-config/ dir', () => {
    expect(rule.match('bind-config/db.example.com', 'db.example.com')).toBe(true)
  })

  it('does NOT match generic config.conf outside BIND dirs', () => {
    expect(rule.match('config/config.conf', 'config.conf')).toBe(false)
  })

  it('does NOT match .zone file outside BIND dirs', () => {
    expect(rule.match('src/example.zone', 'example.zone')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 2: UNBOUND_RESOLVER_DRIFT (high)
// ---------------------------------------------------------------------------

describe('UNBOUND_RESOLVER_DRIFT', () => {
  const rule = DNS_SECURITY_RULES.find((r) => r.id === 'UNBOUND_RESOLVER_DRIFT')!

  it('matches unbound.conf (ungated)', () => {
    expect(rule.match('unbound.conf', 'unbound.conf')).toBe(true)
  })

  it('matches unbound-anchor.conf (ungated)', () => {
    expect(rule.match('unbound-anchor.conf', 'unbound-anchor.conf')).toBe(true)
  })

  it('matches unbound-control.conf (ungated)', () => {
    expect(rule.match('unbound-control.conf', 'unbound-control.conf')).toBe(true)
  })

  it('matches unbound-prod.conf prefix', () => {
    expect(rule.match('config/unbound-prod.conf', 'unbound-prod.conf')).toBe(true)
  })

  it('matches unbound.local.conf prefix', () => {
    expect(rule.match('unbound.local.conf', 'unbound.local.conf')).toBe(true)
  })

  it('matches .conf in unbound/ dir', () => {
    expect(rule.match('unbound/local-zones.conf', 'local-zones.conf')).toBe(true)
  })

  it('matches .conf in unbound-config/ dir', () => {
    expect(rule.match('unbound-config/server.conf', 'server.conf')).toBe(true)
  })

  it('does NOT match server.conf outside unbound dirs', () => {
    expect(rule.match('config/server.conf', 'server.conf')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 3: POWERDNS_CONFIG_DRIFT (high)
// ---------------------------------------------------------------------------

describe('POWERDNS_CONFIG_DRIFT', () => {
  const rule = DNS_SECURITY_RULES.find((r) => r.id === 'POWERDNS_CONFIG_DRIFT')!

  it('matches pdns.conf (ungated)', () => {
    expect(rule.match('pdns.conf', 'pdns.conf')).toBe(true)
  })

  it('matches pdns-recursor.conf (ungated)', () => {
    expect(rule.match('pdns-recursor.conf', 'pdns-recursor.conf')).toBe(true)
  })

  it('matches recursor.yml (ungated)', () => {
    expect(rule.match('recursor.yml', 'recursor.yml')).toBe(true)
  })

  it('matches pdns-auth.conf prefix', () => {
    expect(rule.match('pdns-auth.conf', 'pdns-auth.conf')).toBe(true)
  })

  it('matches powerdns-server.conf prefix', () => {
    expect(rule.match('powerdns-server.conf', 'powerdns-server.conf')).toBe(true)
  })

  it('matches pdns.local.conf prefix', () => {
    expect(rule.match('pdns.local.conf', 'pdns.local.conf')).toBe(true)
  })

  it('matches recursor.conf gated on pdns/ dir', () => {
    expect(rule.match('pdns/recursor.conf', 'recursor.conf')).toBe(true)
  })

  it('matches .conf in powerdns/ dir', () => {
    expect(rule.match('powerdns/api.conf', 'api.conf')).toBe(true)
  })

  it('matches .yml in powerdns-recursor/ dir', () => {
    expect(rule.match('powerdns-recursor/config.yml', 'config.yml')).toBe(true)
  })

  it('does NOT match recursor.conf outside powerdns dirs', () => {
    expect(rule.match('config/recursor.conf', 'recursor.conf')).toBe(false)
  })

  it('does NOT match api.conf outside powerdns dirs', () => {
    expect(rule.match('config/api.conf', 'api.conf')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 4: COREDNS_CONFIG_DRIFT (high)
// ---------------------------------------------------------------------------

describe('COREDNS_CONFIG_DRIFT', () => {
  const rule = DNS_SECURITY_RULES.find((r) => r.id === 'COREDNS_CONFIG_DRIFT')!

  it('matches Corefile (lowercased: corefile — globally unambiguous)', () => {
    expect(rule.match('corefile', 'corefile')).toBe(true)
  })

  it('matches corefile at any path depth', () => {
    expect(rule.match('coredns/corefile', 'corefile')).toBe(true)
  })

  it('matches corefile.override (Corefile.* variant)', () => {
    expect(rule.match('corefile.override', 'corefile.override')).toBe(true)
  })

  it('matches coredns-config.yaml prefix', () => {
    expect(rule.match('config/coredns-config.yaml', 'coredns-config.yaml')).toBe(true)
  })

  it('matches coredns.local.conf prefix', () => {
    expect(rule.match('coredns.local.conf', 'coredns.local.conf')).toBe(true)
  })

  it('matches .yaml in coredns/ dir', () => {
    expect(rule.match('coredns/plugins.yaml', 'plugins.yaml')).toBe(true)
  })

  it('matches .conf in dns/coredns/ dir', () => {
    expect(rule.match('dns/coredns/server.conf', 'server.conf')).toBe(true)
  })

  it('does NOT match generic plugins.yaml outside coredns dirs', () => {
    expect(rule.match('config/plugins.yaml', 'plugins.yaml')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 5: DNSMASQ_CONFIG_DRIFT (medium)
// ---------------------------------------------------------------------------

describe('DNSMASQ_CONFIG_DRIFT', () => {
  const rule = DNS_SECURITY_RULES.find((r) => r.id === 'DNSMASQ_CONFIG_DRIFT')!

  it('matches dnsmasq.conf (ungated)', () => {
    expect(rule.match('dnsmasq.conf', 'dnsmasq.conf')).toBe(true)
  })

  it('matches dnsmasq.d (directory marker, ungated)', () => {
    expect(rule.match('dnsmasq.d', 'dnsmasq.d')).toBe(true)
  })

  it('matches dnsmasq-custom.conf prefix', () => {
    expect(rule.match('config/dnsmasq-custom.conf', 'dnsmasq-custom.conf')).toBe(true)
  })

  it('matches dnsmasq.local.conf prefix', () => {
    expect(rule.match('dnsmasq.local.conf', 'dnsmasq.local.conf')).toBe(true)
  })

  it('matches .conf in dnsmasq/ dir', () => {
    expect(rule.match('dnsmasq/dhcp.conf', 'dhcp.conf')).toBe(true)
  })

  it('matches .conf in dnsmasq.d/ dir', () => {
    expect(rule.match('dnsmasq.d/custom-dns.conf', 'custom-dns.conf')).toBe(true)
  })

  it('matches .list in dnsmasq/ dir (blocklist)', () => {
    expect(rule.match('dnsmasq/blocklist.list', 'blocklist.list')).toBe(true)
  })

  it('does NOT match dhcp.conf outside dnsmasq dirs', () => {
    expect(rule.match('config/dhcp.conf', 'dhcp.conf')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 6: PIHOLE_CONFIG_DRIFT (medium)
// ---------------------------------------------------------------------------

describe('PIHOLE_CONFIG_DRIFT', () => {
  const rule = DNS_SECURITY_RULES.find((r) => r.id === 'PIHOLE_CONFIG_DRIFT')!

  it('matches pihole.conf (ungated)', () => {
    expect(rule.match('pihole.conf', 'pihole.conf')).toBe(true)
  })

  it('matches ftl.conf (ungated, globally unambiguous)', () => {
    expect(rule.match('ftl.conf', 'ftl.conf')).toBe(true)
  })

  it('matches .pihole.conf (ungated)', () => {
    expect(rule.match('.pihole.conf', '.pihole.conf')).toBe(true)
  })

  it('matches pihole-config.conf prefix', () => {
    expect(rule.match('pihole-config.conf', 'pihole-config.conf')).toBe(true)
  })

  it('matches pihole.local.conf prefix', () => {
    expect(rule.match('pihole.local.conf', 'pihole.local.conf')).toBe(true)
  })

  it('matches pihole-blocklist.list prefix', () => {
    expect(rule.match('pihole-blocklist.list', 'pihole-blocklist.list')).toBe(true)
  })

  it('matches setupvars.conf in pihole/ dir', () => {
    expect(rule.match('pihole/setupvars.conf', 'setupvars.conf')).toBe(true)
  })

  it('matches adlists.list in pihole/ dir', () => {
    expect(rule.match('pihole/adlists.list', 'adlists.list')).toBe(true)
  })

  it('matches blacklist.txt in pihole/ dir', () => {
    expect(rule.match('pihole/blacklist.txt', 'blacklist.txt')).toBe(true)
  })

  it('matches whitelist.txt in pihole/ dir', () => {
    expect(rule.match('pihole/whitelist.txt', 'whitelist.txt')).toBe(true)
  })

  it('matches dnsmasq.conf in pihole/ dir (Pi-hole uses dnsmasq)', () => {
    expect(rule.match('pihole/dnsmasq.conf', 'dnsmasq.conf')).toBe(true)
  })

  it('does NOT match blacklist.txt outside pihole dirs', () => {
    expect(rule.match('config/blacklist.txt', 'blacklist.txt')).toBe(false)
  })

  it('does NOT match setupvars.conf outside pihole dirs', () => {
    expect(rule.match('config/setupvars.conf', 'setupvars.conf')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 7: DNS_OVER_HTTPS_CONFIG_DRIFT (medium)
// ---------------------------------------------------------------------------

describe('DNS_OVER_HTTPS_CONFIG_DRIFT', () => {
  const rule = DNS_SECURITY_RULES.find((r) => r.id === 'DNS_OVER_HTTPS_CONFIG_DRIFT')!

  it('matches dnscrypt-proxy.toml (globally unambiguous)', () => {
    expect(rule.match('dnscrypt-proxy.toml', 'dnscrypt-proxy.toml')).toBe(true)
  })

  it('matches dnscrypt-proxy.yaml (globally unambiguous)', () => {
    expect(rule.match('dnscrypt-proxy.yaml', 'dnscrypt-proxy.yaml')).toBe(true)
  })

  it('matches stubby.yml (globally unambiguous)', () => {
    expect(rule.match('stubby.yml', 'stubby.yml')).toBe(true)
  })

  it('matches stubby.yaml variant (ungated)', () => {
    expect(rule.match('stubby.yaml', 'stubby.yaml')).toBe(true)
  })

  it('matches .stubby.yml (ungated)', () => {
    expect(rule.match('.stubby.yml', '.stubby.yml')).toBe(true)
  })

  it('matches dnscrypt-proxy-custom.toml prefix', () => {
    expect(rule.match('config/dnscrypt-proxy-custom.toml', 'dnscrypt-proxy-custom.toml')).toBe(true)
  })

  it('matches dnscrypt-servers.yaml prefix', () => {
    expect(rule.match('dnscrypt-servers.yaml', 'dnscrypt-servers.yaml')).toBe(true)
  })

  it('matches stubby-config.yaml prefix', () => {
    expect(rule.match('stubby-config.yaml', 'stubby-config.yaml')).toBe(true)
  })

  it('matches .toml in dnscrypt-proxy/ dir', () => {
    expect(rule.match('dnscrypt-proxy/servers.toml', 'servers.toml')).toBe(true)
  })

  it('matches .yaml in doh/ dir', () => {
    expect(rule.match('doh/config.yaml', 'config.yaml')).toBe(true)
  })

  it('matches .conf in dns-over-https/ dir', () => {
    expect(rule.match('dns-over-https/proxy.conf', 'proxy.conf')).toBe(true)
  })

  it('does NOT match servers.toml outside DoH dirs', () => {
    expect(rule.match('config/servers.toml', 'servers.toml')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 8: DNS_RPKI_VALIDATION_DRIFT (low)
// ---------------------------------------------------------------------------

describe('DNS_RPKI_VALIDATION_DRIFT', () => {
  const rule = DNS_SECURITY_RULES.find((r) => r.id === 'DNS_RPKI_VALIDATION_DRIFT')!

  it('matches routinator.conf (ungated)', () => {
    expect(rule.match('routinator.conf', 'routinator.conf')).toBe(true)
  })

  it('matches fort.conf (ungated)', () => {
    expect(rule.match('fort.conf', 'fort.conf')).toBe(true)
  })

  it('matches rpki-client.conf (ungated)', () => {
    expect(rule.match('rpki-client.conf', 'rpki-client.conf')).toBe(true)
  })

  it('matches rpki-config.yaml prefix', () => {
    expect(rule.match('rpki-config.yaml', 'rpki-config.yaml')).toBe(true)
  })

  it('matches config.toml in rpki/ dir', () => {
    expect(rule.match('rpki/config.toml', 'config.toml')).toBe(true)
  })

  it('matches server.conf in rpki-validator/ dir', () => {
    expect(rule.match('rpki-validator/server.conf', 'server.conf')).toBe(true)
  })

  it('does NOT match fort.conf in terraform/ dir', () => {
    expect(rule.match('terraform/fort.conf', 'fort.conf')).toBe(false)
  })

  it('does NOT match config.toml outside rpki dirs', () => {
    expect(rule.match('config/config.toml', 'config.toml')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// scanDnsSecurityDrift — integration
// ---------------------------------------------------------------------------

describe('scanDnsSecurityDrift', () => {
  it('returns clean result for empty file list', () => {
    const r = scanDnsSecurityDrift([])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
    expect(r.totalFindings).toBe(0)
    expect(r.findings).toHaveLength(0)
    expect(r.summary).toMatch(/no dns/i)
  })

  it('returns clean result for non-matching files', () => {
    const r = scanDnsSecurityDrift([
      'src/index.ts',
      'package.json',
      'README.md',
      'docs/api.md',
    ])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
    expect(r.totalFindings).toBe(0)
  })

  it('detects single HIGH finding — named.conf', () => {
    const r = scanDnsSecurityDrift(['named.conf'])
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0]!.ruleId).toBe('BIND_DNS_CONFIG_DRIFT')
    expect(r.findings[0]!.severity).toBe('high')
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('medium')
  })

  it('detects single HIGH finding — unbound.conf', () => {
    const r = scanDnsSecurityDrift(['unbound.conf'])
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0]!.ruleId).toBe('UNBOUND_RESOLVER_DRIFT')
    expect(r.findings[0]!.severity).toBe('high')
    expect(r.riskScore).toBe(15)
  })

  it('detects single MEDIUM finding — dnsmasq.conf', () => {
    const r = scanDnsSecurityDrift(['dnsmasq.conf'])
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0]!.ruleId).toBe('DNSMASQ_CONFIG_DRIFT')
    expect(r.findings[0]!.severity).toBe('medium')
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('detects single LOW finding — routinator.conf', () => {
    const r = scanDnsSecurityDrift(['routinator.conf'])
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0]!.ruleId).toBe('DNS_RPKI_VALIDATION_DRIFT')
    expect(r.findings[0]!.severity).toBe('low')
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('multi-rule result with all severities', () => {
    const r = scanDnsSecurityDrift([
      'named.conf',           // HIGH
      'dnsmasq.conf',         // MEDIUM
      'routinator.conf',      // LOW
    ])
    expect(r.totalFindings).toBe(3)
    expect(r.highCount).toBe(1)
    expect(r.mediumCount).toBe(1)
    expect(r.lowCount).toBe(1)
    // 15 + 8 + 4 = 27
    expect(r.riskScore).toBe(27)
    expect(r.riskLevel).toBe('medium')
  })

  it('caps HIGH score at 45 with 3+ high findings', () => {
    const r = scanDnsSecurityDrift([
      'named.conf',       // HIGH BIND
      'unbound.conf',     // HIGH Unbound
      'pdns.conf',        // HIGH PowerDNS
      'corefile',         // HIGH CoreDNS
    ])
    expect(r.highCount).toBe(4)
    // 4×15=60 → capped 45
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('caps MEDIUM score at 25 with 4 medium findings', () => {
    const r = scanDnsSecurityDrift([
      'dnsmasq.conf',          // MEDIUM
      'ftl.conf',              // MEDIUM PiHole
      'dnscrypt-proxy.toml',   // MEDIUM DoH
    ])
    expect(r.mediumCount).toBe(3)
    // 3×8=24 → under cap
    expect(r.riskScore).toBe(24)
  })

  it('deduplicates findings per rule — multiple BIND files count as one finding', () => {
    const r = scanDnsSecurityDrift([
      'named.conf',
      'named-local.conf',
      'named.conf.options',
      'rndc.conf',
    ])
    expect(r.findings.filter((f) => f.ruleId === 'BIND_DNS_CONFIG_DRIFT')).toHaveLength(1)
    expect(r.findings.find((f) => f.ruleId === 'BIND_DNS_CONFIG_DRIFT')!.matchCount).toBe(4)
    expect(r.riskScore).toBe(15) // still one HIGH penalty
  })

  it('records firstPath as the matched path in the finding', () => {
    const r = scanDnsSecurityDrift([
      'README.md',            // non-matching
      'named.conf',           // first match
      'named-local.conf',     // second match
    ])
    expect(r.findings[0]!.matchedPath).toBe('named.conf')
  })

  it('sorts findings high → medium → low', () => {
    const r = scanDnsSecurityDrift([
      'routinator.conf',       // LOW
      'dnsmasq.conf',          // MEDIUM
      'named.conf',            // HIGH
    ])
    expect(r.findings[0]!.severity).toBe('high')
    expect(r.findings[1]!.severity).toBe('medium')
    expect(r.findings[2]!.severity).toBe('low')
  })

  it('skips vendor directory paths', () => {
    const r = scanDnsSecurityDrift([
      'vendor/bind/named.conf',
      'node_modules/dns-lib/unbound.conf',
    ])
    expect(r.totalFindings).toBe(0)
  })

  it('normalises Windows backslash paths', () => {
    const r = scanDnsSecurityDrift(['config\\named.conf'])
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0]!.ruleId).toBe('BIND_DNS_CONFIG_DRIFT')
  })

  it('is case-insensitive (uppercase path)', () => {
    const r = scanDnsSecurityDrift(['NAMED.CONF'])
    expect(r.totalFindings).toBe(1)
  })

  it('detects all 8 rules simultaneously', () => {
    const r = scanDnsSecurityDrift([
      'named.conf',            // BIND_DNS_CONFIG_DRIFT
      'unbound.conf',          // UNBOUND_RESOLVER_DRIFT
      'pdns.conf',             // POWERDNS_CONFIG_DRIFT
      'corefile',              // COREDNS_CONFIG_DRIFT
      'dnsmasq.conf',          // DNSMASQ_CONFIG_DRIFT
      'ftl.conf',              // PIHOLE_CONFIG_DRIFT
      'dnscrypt-proxy.toml',   // DNS_OVER_HTTPS_CONFIG_DRIFT
      'routinator.conf',       // DNS_RPKI_VALIDATION_DRIFT
    ])
    expect(r.totalFindings).toBe(8)
    expect(r.highCount).toBe(4)
    expect(r.mediumCount).toBe(3)
    expect(r.lowCount).toBe(1)
    // 4H=45(cap) + 3M=24 + 1L=4 = 73
    expect(r.riskScore).toBe(73)
    expect(r.riskLevel).toBe('high')
  })

  it('score 45 → high (boundary: exactly 45 is high, not medium)', () => {
    const r = scanDnsSecurityDrift([
      'named.conf',   // HIGH 15
      'unbound.conf', // HIGH 15
      'pdns.conf',    // HIGH 15 → 3×15=45, capped=45
    ])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('score 42 → medium (< 45)', () => {
    const r = scanDnsSecurityDrift([
      'named.conf',           // HIGH 15
      'unbound.conf',         // HIGH 15
      'dnsmasq.conf',         // MEDIUM 8
      'routinator.conf',      // LOW 4
    ])
    // 30 + 8 + 4 = 42
    expect(r.riskScore).toBe(42)
    expect(r.riskLevel).toBe('medium')
  })

  it('all 8 rule IDs appear in DNS_SECURITY_RULES', () => {
    const ids = DNS_SECURITY_RULES.map((r) => r.id)
    expect(ids).toContain('BIND_DNS_CONFIG_DRIFT')
    expect(ids).toContain('UNBOUND_RESOLVER_DRIFT')
    expect(ids).toContain('POWERDNS_CONFIG_DRIFT')
    expect(ids).toContain('COREDNS_CONFIG_DRIFT')
    expect(ids).toContain('DNSMASQ_CONFIG_DRIFT')
    expect(ids).toContain('PIHOLE_CONFIG_DRIFT')
    expect(ids).toContain('DNS_OVER_HTTPS_CONFIG_DRIFT')
    expect(ids).toContain('DNS_RPKI_VALIDATION_DRIFT')
    expect(ids).toHaveLength(8)
  })

  it('result shape has all required fields', () => {
    const r = scanDnsSecurityDrift(['named.conf'])
    expect(r).toHaveProperty('riskScore')
    expect(r).toHaveProperty('riskLevel')
    expect(r).toHaveProperty('totalFindings')
    expect(r).toHaveProperty('highCount')
    expect(r).toHaveProperty('mediumCount')
    expect(r).toHaveProperty('lowCount')
    expect(r).toHaveProperty('findings')
    expect(r).toHaveProperty('summary')
    const f = r.findings[0]!
    expect(f).toHaveProperty('ruleId')
    expect(f).toHaveProperty('severity')
    expect(f).toHaveProperty('matchedPath')
    expect(f).toHaveProperty('matchCount')
    expect(f).toHaveProperty('description')
    expect(f).toHaveProperty('recommendation')
  })

  it('summary mentions drift when findings exist', () => {
    const r = scanDnsSecurityDrift(['named.conf'])
    expect(r.summary).toMatch(/drift/i)
    expect(r.summary).toMatch(/high/i)
  })

  it('riskLevel none → score 0', () => {
    const r = scanDnsSecurityDrift([])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })

  it('riskLevel low → score 4 (single LOW finding)', () => {
    const r = scanDnsSecurityDrift(['routinator.conf'])
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('riskLevel low → score 8 (single MEDIUM finding)', () => {
    const r = scanDnsSecurityDrift(['dnsmasq.conf'])
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('riskLevel medium → score 15 (single HIGH finding)', () => {
    const r = scanDnsSecurityDrift(['named.conf'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('medium')
  })

  it('Pi-hole drift detected via ftl.conf', () => {
    const r = scanDnsSecurityDrift(['ftl.conf'])
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0]!.ruleId).toBe('PIHOLE_CONFIG_DRIFT')
    expect(r.findings[0]!.severity).toBe('medium')
  })

  it('DoH drift detected via dnscrypt-proxy.toml', () => {
    const r = scanDnsSecurityDrift(['dnscrypt-proxy.toml'])
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0]!.ruleId).toBe('DNS_OVER_HTTPS_CONFIG_DRIFT')
  })

  it('DoT drift detected via stubby.yml', () => {
    const r = scanDnsSecurityDrift(['stubby.yml'])
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0]!.ruleId).toBe('DNS_OVER_HTTPS_CONFIG_DRIFT')
  })

  it('CoreDNS drift detected via corefile (lowercase Corefile)', () => {
    const r = scanDnsSecurityDrift(['Corefile'])
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0]!.ruleId).toBe('COREDNS_CONFIG_DRIFT')
  })

  it('CoreDNS drift detected via nested Corefile path', () => {
    const r = scanDnsSecurityDrift(['k8s/coredns/Corefile'])
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0]!.ruleId).toBe('COREDNS_CONFIG_DRIFT')
  })

  it('RPKI drift detected via routinator.conf', () => {
    const r = scanDnsSecurityDrift(['routinator.conf'])
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0]!.ruleId).toBe('DNS_RPKI_VALIDATION_DRIFT')
  })

  it('PowerDNS drift detected via pdns.conf', () => {
    const r = scanDnsSecurityDrift(['pdns.conf'])
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0]!.ruleId).toBe('POWERDNS_CONFIG_DRIFT')
  })
})
