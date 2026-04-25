import { describe, expect, it } from 'vitest'
import {
  isProxyAccessConfig,
  NETWORK_FIREWALL_RULES,
  scanNetworkFirewallDrift,
} from './networkFirewallDrift'

const scan = scanNetworkFirewallDrift

function ruleIds(r: ReturnType<typeof scan>) {
  return r.findings.map((f) => f.ruleId)
}

// ---------------------------------------------------------------------------
// Trivial inputs
// ---------------------------------------------------------------------------

describe('trivial inputs', () => {
  it('returns none for empty array', () => {
    const r = scan([])
    expect(r.riskLevel).toBe('none')
    expect(r.riskScore).toBe(0)
    expect(r.totalFindings).toBe(0)
    expect(r.findings).toHaveLength(0)
  })

  it('returns none for vendor-only paths', () => {
    const r = scan([
      'node_modules/some-pkg/iptables.rules',
      '.git/COMMIT_EDITMSG',
      'vendor/bin/wg0.conf',
      'dist/proxy.conf',
    ])
    expect(r.riskLevel).toBe('none')
    expect(r.findings).toHaveLength(0)
  })

  it('normalises Windows backslash paths', () => {
    const r = scan(['etc\\iptables\\rules.v4'])
    expect(ruleIds(r)).toContain('IPTABLES_RULES_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// IPTABLES_RULES_DRIFT
// ---------------------------------------------------------------------------

describe('IPTABLES_RULES_DRIFT', () => {
  it('detects iptables.rules', () => {
    expect(ruleIds(scan(['etc/iptables.rules']))).toContain('IPTABLES_RULES_DRIFT')
  })

  it('detects ip6tables.rules', () => {
    expect(ruleIds(scan(['etc/ip6tables.rules']))).toContain('IPTABLES_RULES_DRIFT')
  })

  it('detects rules.v4', () => {
    expect(ruleIds(scan(['etc/iptables/rules.v4']))).toContain('IPTABLES_RULES_DRIFT')
  })

  it('detects rules.v6', () => {
    expect(ruleIds(scan(['etc/iptables/rules.v6']))).toContain('IPTABLES_RULES_DRIFT')
  })

  it('detects iptables-save', () => {
    expect(ruleIds(scan(['scripts/iptables-save']))).toContain('IPTABLES_RULES_DRIFT')
  })

  it('detects basename starting with iptables- prefix', () => {
    expect(ruleIds(scan(['config/iptables-custom.rules']))).toContain('IPTABLES_RULES_DRIFT')
  })

  it('detects file inside iptables/ directory', () => {
    expect(ruleIds(scan(['infra/iptables/custom.conf']))).toContain('IPTABLES_RULES_DRIFT')
  })

  it('does not trigger on unrelated .rules in non-iptables dir', () => {
    // audit.rules belongs to WS-67
    const r = scan(['etc/audit/audit.rules'])
    expect(ruleIds(r)).not.toContain('IPTABLES_RULES_DRIFT')
  })

  it('does not trigger on generic rules.txt', () => {
    expect(ruleIds(scan(['docs/rules.txt']))).not.toContain('IPTABLES_RULES_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// NFTABLES_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('NFTABLES_CONFIG_DRIFT', () => {
  it('detects .nft extension', () => {
    expect(ruleIds(scan(['etc/nftables/filter.nft']))).toContain('NFTABLES_CONFIG_DRIFT')
  })

  it('detects nftables.conf basename', () => {
    expect(ruleIds(scan(['etc/nftables.conf']))).toContain('NFTABLES_CONFIG_DRIFT')
  })

  it('detects nftables.nft basename', () => {
    expect(ruleIds(scan(['infra/nftables.nft']))).toContain('NFTABLES_CONFIG_DRIFT')
  })

  it('detects file in nftables/ directory with .conf extension', () => {
    expect(ruleIds(scan(['config/nftables/rules.conf']))).toContain('NFTABLES_CONFIG_DRIFT')
  })

  it('does not trigger on arbitrary .conf outside nftables dir', () => {
    expect(ruleIds(scan(['etc/nginx/nginx.conf']))).not.toContain('NFTABLES_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// HAPROXY_SECURITY_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('HAPROXY_SECURITY_CONFIG_DRIFT', () => {
  it('detects haproxy.cfg basename', () => {
    expect(ruleIds(scan(['etc/haproxy/haproxy.cfg']))).toContain('HAPROXY_SECURITY_CONFIG_DRIFT')
  })

  it('detects haproxy.conf basename', () => {
    expect(ruleIds(scan(['haproxy.conf']))).toContain('HAPROXY_SECURITY_CONFIG_DRIFT')
  })

  it('detects haproxy.yaml basename', () => {
    expect(ruleIds(scan(['deploy/haproxy.yaml']))).toContain('HAPROXY_SECURITY_CONFIG_DRIFT')
  })

  it('detects haproxy-prod.cfg (prefix match)', () => {
    expect(ruleIds(scan(['haproxy-prod.cfg']))).toContain('HAPROXY_SECURITY_CONFIG_DRIFT')
  })

  it('detects .cfg file in haproxy/ directory', () => {
    expect(ruleIds(scan(['infra/haproxy/frontend.cfg']))).toContain('HAPROXY_SECURITY_CONFIG_DRIFT')
  })

  it('does not trigger on unrelated .cfg file', () => {
    expect(ruleIds(scan(['app/config.cfg']))).not.toContain('HAPROXY_SECURITY_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// UFW_RULES_DRIFT
// ---------------------------------------------------------------------------

describe('UFW_RULES_DRIFT', () => {
  it('detects ufw.conf (ungated)', () => {
    expect(ruleIds(scan(['etc/ufw/ufw.conf']))).toContain('UFW_RULES_DRIFT')
  })

  it('detects user.rules inside ufw/ directory', () => {
    expect(ruleIds(scan(['etc/ufw/user.rules']))).toContain('UFW_RULES_DRIFT')
  })

  it('detects before.rules inside ufw/ directory', () => {
    expect(ruleIds(scan(['etc/ufw/before.rules']))).toContain('UFW_RULES_DRIFT')
  })

  it('detects user6.rules inside ufw/ directory', () => {
    expect(ruleIds(scan(['etc/ufw/user6.rules']))).toContain('UFW_RULES_DRIFT')
  })

  it('does NOT detect user.rules outside ufw/ directory (false positive guard)', () => {
    // user.rules is too generic without directory context
    expect(ruleIds(scan(['src/user.rules']))).not.toContain('UFW_RULES_DRIFT')
  })

  it('does NOT detect before.rules outside ufw/ directory', () => {
    expect(ruleIds(scan(['hooks/before.rules']))).not.toContain('UFW_RULES_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// VPN_SECURITY_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('VPN_SECURITY_CONFIG_DRIFT', () => {
  it('detects .ovpn extension (unambiguous)', () => {
    expect(ruleIds(scan(['clients/prod.ovpn']))).toContain('VPN_SECURITY_CONFIG_DRIFT')
  })

  it('detects wg0.conf (WireGuard interface pattern)', () => {
    expect(ruleIds(scan(['etc/wireguard/wg0.conf']))).toContain('VPN_SECURITY_CONFIG_DRIFT')
  })

  it('detects wg1.conf', () => {
    expect(ruleIds(scan(['wireguard/wg1.conf']))).toContain('VPN_SECURITY_CONFIG_DRIFT')
  })

  it('detects wg-prod.conf (wg- prefix)', () => {
    expect(ruleIds(scan(['wg/wg-prod.conf']))).toContain('VPN_SECURITY_CONFIG_DRIFT')
  })

  it('detects openvpn.conf (exact)', () => {
    expect(ruleIds(scan(['openvpn.conf']))).toContain('VPN_SECURITY_CONFIG_DRIFT')
  })

  it('detects .conf file in openvpn/ directory', () => {
    expect(ruleIds(scan(['etc/openvpn/server.conf']))).toContain('VPN_SECURITY_CONFIG_DRIFT')
  })

  it('detects .conf file in wireguard/ directory', () => {
    expect(ruleIds(scan(['infra/wireguard/peers.conf']))).toContain('VPN_SECURITY_CONFIG_DRIFT')
  })

  it('does not trigger on generic server.conf outside vpn dir', () => {
    expect(ruleIds(scan(['app/server.conf']))).not.toContain('VPN_SECURITY_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// DNS_SECURITY_DRIFT
// ---------------------------------------------------------------------------

describe('DNS_SECURITY_DRIFT', () => {
  it('detects named.conf (exact)', () => {
    expect(ruleIds(scan(['etc/named.conf']))).toContain('DNS_SECURITY_DRIFT')
  })

  it('detects named.conf.local', () => {
    expect(ruleIds(scan(['etc/bind/named.conf.local']))).toContain('DNS_SECURITY_DRIFT')
  })

  it('detects named.conf.options', () => {
    expect(ruleIds(scan(['etc/bind/named.conf.options']))).toContain('DNS_SECURITY_DRIFT')
  })

  it('detects bind.conf', () => {
    expect(ruleIds(scan(['infra/bind.conf']))).toContain('DNS_SECURITY_DRIFT')
  })

  it('detects rndc.key', () => {
    expect(ruleIds(scan(['etc/bind/rndc.key']))).toContain('DNS_SECURITY_DRIFT')
  })

  it('detects .zone file inside dns/ directory', () => {
    expect(ruleIds(scan(['dns/example.com.zone']))).toContain('DNS_SECURITY_DRIFT')
  })

  it('detects .key file inside dnssec/ directory', () => {
    expect(ruleIds(scan(['dnssec/Kexample.com.+008+12345.key']))).toContain('DNS_SECURITY_DRIFT')
  })

  it('detects dsset- files inside dns directory', () => {
    expect(ruleIds(scan(['dns/dsset-example.com.']))).toContain('DNS_SECURITY_DRIFT')
  })

  it('does NOT detect generic .key file outside dns directory', () => {
    // .key outside dns dirs is too generic (ssl keys, etc.)
    expect(ruleIds(scan(['certs/server.key']))).not.toContain('DNS_SECURITY_DRIFT')
  })

  it('does NOT detect .zone outside dns directory', () => {
    expect(ruleIds(scan(['app/public.zone']))).not.toContain('DNS_SECURITY_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// PROXY_ACCESS_CONFIG_DRIFT (user contribution point)
// ---------------------------------------------------------------------------

describe('isProxyAccessConfig', () => {
  it('detects squid.conf', () => {
    expect(isProxyAccessConfig('etc/squid/squid.conf')).toBe(true)
  })

  it('detects file in squid/ directory', () => {
    expect(isProxyAccessConfig('proxy/squid/acl.conf')).toBe(true)
  })

  it('detects blacklist keyword in basename', () => {
    expect(isProxyAccessConfig('nginx/blacklist.conf')).toBe(true)
  })

  it('detects whitelist keyword in basename', () => {
    expect(isProxyAccessConfig('conf/ip-whitelist.yaml')).toBe(true)
  })

  it('detects geo-block keyword', () => {
    expect(isProxyAccessConfig('nginx/geo-block.conf')).toBe(true)
  })

  it('detects geoblock keyword', () => {
    expect(isProxyAccessConfig('conf/geoblock.conf')).toBe(true)
  })

  it('detects acl keyword in basename', () => {
    expect(isProxyAccessConfig('proxy/acl.conf')).toBe(true)
  })

  it('detects ip-block keyword', () => {
    expect(isProxyAccessConfig('nginx/ip-block.conf')).toBe(true)
  })

  it('detects file in access-control/ directory', () => {
    expect(isProxyAccessConfig('nginx/access-control/rules.conf')).toBe(true)
  })

  it('detects Traefik ip-whitelist middleware in proxy/ dir', () => {
    expect(isProxyAccessConfig('proxy/middleware-ipwhitelist.yaml')).toBe(true)
  })

  it('does NOT detect generic nginx.conf (not in access-control dir)', () => {
    expect(isProxyAccessConfig('nginx/nginx.conf')).toBe(false)
  })

  it('does NOT detect rate-limit.config.ts (belongs to WS-65)', () => {
    expect(isProxyAccessConfig('config/rate-limit.config.ts')).toBe(false)
  })
})

describe('PROXY_ACCESS_CONFIG_DRIFT scanner integration', () => {
  it('triggers for squid.conf', () => {
    expect(ruleIds(scan(['etc/squid/squid.conf']))).toContain('PROXY_ACCESS_CONFIG_DRIFT')
  })

  it('triggers for blocklist.conf in proxy dir', () => {
    expect(ruleIds(scan(['nginx/blocklist.conf']))).toContain('PROXY_ACCESS_CONFIG_DRIFT')
  })

  it('does not trigger for generic nginx.conf', () => {
    // generic nginx.conf is not a proxy access config
    const r = scan(['etc/nginx/nginx.conf'])
    expect(ruleIds(r)).not.toContain('PROXY_ACCESS_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// FIREWALLD_ZONE_DRIFT
// ---------------------------------------------------------------------------

describe('FIREWALLD_ZONE_DRIFT', () => {
  it('detects firewalld.conf (ungated)', () => {
    expect(ruleIds(scan(['etc/firewalld/firewalld.conf']))).toContain('FIREWALLD_ZONE_DRIFT')
  })

  it('detects .xml file in firewalld/ directory', () => {
    expect(ruleIds(scan(['etc/firewalld/zones/public.xml']))).toContain('FIREWALLD_ZONE_DRIFT')
  })

  it('detects internal.xml in firewalld directory', () => {
    expect(ruleIds(scan(['infra/firewalld/internal.xml']))).toContain('FIREWALLD_ZONE_DRIFT')
  })

  it('detects dmz.xml in firewalld directory', () => {
    expect(ruleIds(scan(['firewalld/zones/dmz.xml']))).toContain('FIREWALLD_ZONE_DRIFT')
  })

  it('does NOT detect public.xml outside firewalld dir', () => {
    // public.xml is a generic filename
    expect(ruleIds(scan(['src/assets/public.xml']))).not.toContain('FIREWALLD_ZONE_DRIFT')
  })

  it('does NOT detect generic config.xml in firewalld-unrelated path', () => {
    expect(ruleIds(scan(['app/config.xml']))).not.toContain('FIREWALLD_ZONE_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scoring model', () => {
  it('score is 0 for no findings', () => {
    expect(scan([]).riskScore).toBe(0)
  })

  it('single high finding scores 15', () => {
    const r = scan(['iptables.rules'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('low')
  })

  it('3 high findings score 45 (cap)', () => {
    // 3 files all trigger IPTABLES — penalty = 3×15=45, capped at 45
    const r = scan(['iptables.rules', 'ip6tables.rules', 'rules.v4'])
    expect(r.riskScore).toBe(45)
    // 45 is medium threshold — riskLevel should be medium (score 45 → high since high threshold is < 70 but ≥ 45)
    // Let's check: none<20, low<20, medium<45, high<70, critical≥70
    // 45 is not < 45, so it's >= 45 → high
    expect(r.riskLevel).toBe('high')
  })

  it('single medium finding scores 8', () => {
    const r = scan(['etc/ufw/ufw.conf'])
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('single low finding scores 4', () => {
    const r = scan(['etc/firewalld/firewalld.conf'])
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('2 high + 3 medium scores correctly', () => {
    // 2 high rules triggered (1 file each) = 2×15 = 30
    // 3 medium rules triggered (1 file each) = 3×8 = 24
    // total = 54 → clamped at 54 (< 100), riskLevel = high (≥ 45, < 70)
    const r = scan([
      'iptables.rules',          // IPTABLES_RULES_DRIFT high
      'nftables.conf',           // NFTABLES_CONFIG_DRIFT high
      'etc/ufw/ufw.conf',        // UFW_RULES_DRIFT medium
      'client.ovpn',             // VPN_SECURITY_CONFIG_DRIFT medium
      'etc/named.conf',          // DNS_SECURITY_DRIFT medium
    ])
    expect(r.riskScore).toBe(54)
    expect(r.riskLevel).toBe('high')
  })

  it('3 high + 4 medium reaches critical', () => {
    // 3 high rules each triggered once: 3 × 15 = 45
    // 4 medium rules each triggered once: 4 × 8 = 32
    // total = 77 → critical (penalty cap is per-rule per matchCount, not across rules)
    const r = scan([
      'iptables.rules',
      'nftables.conf',
      'haproxy.cfg',
      'etc/ufw/ufw.conf',
      'client.ovpn',
      'etc/named.conf',
      'etc/squid/squid.conf',
    ])
    expect(r.riskScore).toBe(77)
    expect(r.riskLevel).toBe('critical')
  })

  it('score is capped at 100', () => {
    // Flood with many different paths triggering all 8 rules multiple times
    const r = scan([
      'iptables.rules', 'ip6tables.rules', 'rules.v4', 'rules.v6', 'iptables-save',
      'nftables.conf', 'filter.nft',
      'haproxy.cfg', 'haproxy-prod.cfg', 'infra/haproxy/frontend.cfg',
      'etc/ufw/ufw.conf', 'etc/ufw/user.rules', 'etc/ufw/before.rules',
      'client.ovpn', 'wg0.conf', 'wg1.conf',
      'named.conf', 'named.conf.local', 'named.conf.options',
      'etc/squid/squid.conf',
      'etc/firewalld/firewalld.conf', 'firewalld/zones/public.xml',
    ])
    expect(r.riskScore).toBeLessThanOrEqual(100)
  })
})

// ---------------------------------------------------------------------------
// Risk level boundaries
// ---------------------------------------------------------------------------

describe('risk level boundaries', () => {
  it('0 → none', () => expect(scan([]).riskLevel).toBe('none'))

  it('4 → low', () => {
    const r = scan(['etc/firewalld/firewalld.conf'])
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('8 → low', () => {
    const r = scan(['etc/ufw/ufw.conf'])
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('15 → low', () => {
    const r = scan(['iptables.rules'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('low')
  })

  it('45 → high', () => {
    // 3 high-severity files for 1 rule = cap 45 → high (≥ 45)
    const r = scan(['iptables.rules', 'ip6tables.rules', 'rules.v4'])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('70 → critical', () => {
    // 3 files for IPTABLES rule → 3×15=45 (= HIGH_PENALTY_CAP)
    // 4 files for UFW rule → 4×8=32 capped at MED_PENALTY_CAP=25
    // total = 45 + 25 = 70 → critical
    const r = scan([
      'iptables.rules', 'ip6tables.rules', 'rules.v4',               // IPTABLES × 3 → cap 45
      'etc/ufw/ufw.conf', 'etc/ufw/user.rules',                      // UFW × 2 → 16
      'etc/ufw/before.rules', 'etc/ufw/after.rules',                 // UFW × 4 total → cap 25
    ])
    expect(r.riskScore).toBe(70)
    expect(r.riskLevel).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// Counts and deduplication
// ---------------------------------------------------------------------------

describe('counts', () => {
  it('counts high/medium/low correctly', () => {
    const r = scan([
      'iptables.rules',        // high
      'haproxy.cfg',           // high
      'etc/ufw/ufw.conf',      // medium
      'firewalld/zones/dmz.xml', // low
    ])
    expect(r.highCount).toBe(2)
    expect(r.mediumCount).toBe(1)
    expect(r.lowCount).toBe(1)
    expect(r.totalFindings).toBe(4)
  })

  it('deduplicates: same rule fired by multiple paths → 1 finding, matchCount > 1', () => {
    const r = scan(['iptables.rules', 'ip6tables.rules'])
    const f = r.findings.find((x) => x.ruleId === 'IPTABLES_RULES_DRIFT')
    expect(f).toBeDefined()
    expect(f!.matchCount).toBe(2)
    expect(r.highCount).toBe(1) // still just 1 finding
  })

  it('records first matched path', () => {
    const r = scan(['iptables.rules', 'rules.v4'])
    const f = r.findings.find((x) => x.ruleId === 'IPTABLES_RULES_DRIFT')
    // first path is iptables.rules (original, not lowercased for display)
    expect(f!.matchedPath).toBe('iptables.rules')
  })
})

// ---------------------------------------------------------------------------
// Finding ordering (high first)
// ---------------------------------------------------------------------------

describe('finding ordering', () => {
  it('high severity findings appear before medium and low', () => {
    const r = scan([
      'etc/firewalld/firewalld.conf', // low
      'etc/ufw/ufw.conf',             // medium
      'iptables.rules',               // high
    ])
    expect(r.findings[0].severity).toBe('high')
    expect(r.findings.at(-1)!.severity).toBe('low')
  })
})

// ---------------------------------------------------------------------------
// Summary text
// ---------------------------------------------------------------------------

describe('summary', () => {
  it('returns clean summary for no findings', () => {
    expect(scan([]).summary).toContain('No network firewall')
  })

  it('summary mentions finding count and severity', () => {
    const r = scan(['iptables.rules'])
    expect(r.summary).toContain('1 high')
    expect(r.summary.toLowerCase()).toContain('iptables rules drift')
  })

  it('summary mentions multiple severities', () => {
    const r = scan(['iptables.rules', 'etc/ufw/ufw.conf'])
    expect(r.summary).toContain('1 high')
    expect(r.summary).toContain('1 medium')
  })
})

// ---------------------------------------------------------------------------
// Windows path normalisation
// ---------------------------------------------------------------------------

describe('Windows path normalisation', () => {
  it('normalises backslashes before matching', () => {
    const r = scan(['etc\\iptables\\rules.v4'])
    expect(ruleIds(r)).toContain('IPTABLES_RULES_DRIFT')
  })

  it('normalises backslashes for firewalld zone', () => {
    const r = scan(['etc\\firewalld\\zones\\public.xml'])
    expect(ruleIds(r)).toContain('FIREWALLD_ZONE_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Multi-rule scenarios
// ---------------------------------------------------------------------------

describe('multi-rule scenarios', () => {
  it('full network perimeter audit — all 8 rules fire', () => {
    const r = scan([
      'etc/iptables/rules.v4',          // IPTABLES_RULES_DRIFT
      'etc/nftables.conf',              // NFTABLES_CONFIG_DRIFT
      'haproxy.cfg',                    // HAPROXY_SECURITY_CONFIG_DRIFT
      'etc/ufw/ufw.conf',               // UFW_RULES_DRIFT
      'wg0.conf',                       // VPN_SECURITY_CONFIG_DRIFT
      'etc/named.conf',                 // DNS_SECURITY_DRIFT
      'proxy/squid/squid.conf',         // PROXY_ACCESS_CONFIG_DRIFT
      'etc/firewalld/firewalld.conf',   // FIREWALLD_ZONE_DRIFT
    ])
    expect(r.totalFindings).toBe(8)
    expect(r.highCount).toBe(3)
    expect(r.mediumCount).toBe(4)
    expect(r.lowCount).toBe(1)
  })

  it('only firewall rules changed — single high finding', () => {
    const r = scan(['infra/iptables/custom.conf'])
    expect(r.totalFindings).toBe(1)
    expect(ruleIds(r)).toEqual(['IPTABLES_RULES_DRIFT'])
  })
})

// ---------------------------------------------------------------------------
// Rule registry completeness
// ---------------------------------------------------------------------------

describe('rule registry', () => {
  it('has exactly 8 rules', () => {
    expect(NETWORK_FIREWALL_RULES).toHaveLength(8)
  })

  it('all rule IDs are unique', () => {
    const ids = NETWORK_FIREWALL_RULES.map((r) => r.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it('all rules have non-empty description and recommendation', () => {
    for (const rule of NETWORK_FIREWALL_RULES) {
      expect(rule.description.length).toBeGreaterThan(10)
      expect(rule.recommendation.length).toBeGreaterThan(10)
    }
  })

  it('severity distribution: 3 high, 4 medium, 1 low', () => {
    const high   = NETWORK_FIREWALL_RULES.filter((r) => r.severity === 'high').length
    const medium = NETWORK_FIREWALL_RULES.filter((r) => r.severity === 'medium').length
    const low    = NETWORK_FIREWALL_RULES.filter((r) => r.severity === 'low').length
    expect(high).toBe(3)
    expect(medium).toBe(4)
    expect(low).toBe(1)
  })
})
