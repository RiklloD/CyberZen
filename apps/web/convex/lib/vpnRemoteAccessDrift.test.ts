import { describe, expect, it } from 'vitest'
import {
  isVpnPkiCredential,
  scanVpnRemoteAccessDrift,
  VPN_REMOTE_ACCESS_RULES,
} from './vpnRemoteAccessDrift'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const scan = (files: string[]) => scanVpnRemoteAccessDrift(files)
const triggeredRules = (files: string[]) => scan(files).findings.map((f) => f.ruleId)

// ---------------------------------------------------------------------------
// Rule 1: OPENVPN_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('OPENVPN_CONFIG_DRIFT', () => {
  it('matches openvpn.conf (ungated)', () => {
    expect(triggeredRules(['openvpn.conf'])).toContain('OPENVPN_CONFIG_DRIFT')
  })
  it('matches ta.key (ungated TLS auth key)', () => {
    expect(triggeredRules(['ta.key'])).toContain('OPENVPN_CONFIG_DRIFT')
  })
  it('matches tls-auth.key (ungated)', () => {
    expect(triggeredRules(['tls-auth.key'])).toContain('OPENVPN_CONFIG_DRIFT')
  })
  it('matches tls-crypt.key (ungated)', () => {
    expect(triggeredRules(['tls-crypt.key'])).toContain('OPENVPN_CONFIG_DRIFT')
  })
  it('matches dh.pem (ungated DH params)', () => {
    expect(triggeredRules(['dh.pem'])).toContain('OPENVPN_CONFIG_DRIFT')
  })
  it('matches dh2048.pem (ungated)', () => {
    expect(triggeredRules(['dh2048.pem'])).toContain('OPENVPN_CONFIG_DRIFT')
  })
  it('matches dh4096.pem (ungated)', () => {
    expect(triggeredRules(['dh4096.pem'])).toContain('OPENVPN_CONFIG_DRIFT')
  })
  it('matches any .ovpn file (ungated extension)', () => {
    expect(triggeredRules(['corporate.ovpn'])).toContain('OPENVPN_CONFIG_DRIFT')
  })
  it('matches .ovpn in subdirectory (ungated extension)', () => {
    expect(triggeredRules(['vpn-profiles/office.ovpn'])).toContain('OPENVPN_CONFIG_DRIFT')
  })
  it('matches openvpn-server.conf via prefix', () => {
    expect(triggeredRules(['openvpn-server.conf'])).toContain('OPENVPN_CONFIG_DRIFT')
  })
  it('matches openvpn-client.conf via prefix', () => {
    expect(triggeredRules(['openvpn-client.conf'])).toContain('OPENVPN_CONFIG_DRIFT')
  })
  it('matches server.conf inside openvpn/ dir', () => {
    expect(triggeredRules(['openvpn/server.conf'])).toContain('OPENVPN_CONFIG_DRIFT')
  })
  it('matches client.conf inside .openvpn/ dir', () => {
    expect(triggeredRules(['.openvpn/client.conf'])).toContain('OPENVPN_CONFIG_DRIFT')
  })
  it('matches ca.crt inside openvpn/ dir', () => {
    expect(triggeredRules(['openvpn/ca.crt'])).toContain('OPENVPN_CONFIG_DRIFT')
  })
  it('matches server.crt inside openvpn-config/ dir', () => {
    expect(triggeredRules(['openvpn-config/server.crt'])).toContain('OPENVPN_CONFIG_DRIFT')
  })
  it('does NOT match server.conf outside openvpn dirs', () => {
    expect(triggeredRules(['config/server.conf'])).not.toContain('OPENVPN_CONFIG_DRIFT')
  })
  it('does NOT match vendor path', () => {
    expect(triggeredRules(['vendor/openvpn/ta.key'])).not.toContain('OPENVPN_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 2: WIREGUARD_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('WIREGUARD_CONFIG_DRIFT', () => {
  it('matches wg0.conf (ungated canonical)', () => {
    expect(triggeredRules(['wg0.conf'])).toContain('WIREGUARD_CONFIG_DRIFT')
  })
  it('matches wg1.conf (ungated)', () => {
    expect(triggeredRules(['wg1.conf'])).toContain('WIREGUARD_CONFIG_DRIFT')
  })
  it('matches wg10.conf (ungated multi-digit)', () => {
    expect(triggeredRules(['wg10.conf'])).toContain('WIREGUARD_CONFIG_DRIFT')
  })
  it('matches wireguard.conf (ungated)', () => {
    expect(triggeredRules(['wireguard.conf'])).toContain('WIREGUARD_CONFIG_DRIFT')
  })
  it('matches wg-server.conf via wg- prefix', () => {
    expect(triggeredRules(['wg-server.conf'])).toContain('WIREGUARD_CONFIG_DRIFT')
  })
  it('matches wg-client.conf via wg- prefix', () => {
    expect(triggeredRules(['wg-client.conf'])).toContain('WIREGUARD_CONFIG_DRIFT')
  })
  it('matches wireguard-prod.conf via wireguard- prefix', () => {
    expect(triggeredRules(['wireguard-prod.conf'])).toContain('WIREGUARD_CONFIG_DRIFT')
  })
  it('matches wireguard-server.toml via wireguard- prefix', () => {
    expect(triggeredRules(['wireguard-server.toml'])).toContain('WIREGUARD_CONFIG_DRIFT')
  })
  it('matches privatekey inside wireguard/ dir', () => {
    expect(triggeredRules(['wireguard/privatekey'])).toContain('WIREGUARD_CONFIG_DRIFT')
  })
  it('matches publickey inside .wireguard/ dir', () => {
    expect(triggeredRules(['.wireguard/publickey'])).toContain('WIREGUARD_CONFIG_DRIFT')
  })
  it('matches presharedkey inside wg/ dir', () => {
    expect(triggeredRules(['wg/presharedkey'])).toContain('WIREGUARD_CONFIG_DRIFT')
  })
  it('matches server.conf inside wireguard/ dir', () => {
    expect(triggeredRules(['wireguard/server.conf'])).toContain('WIREGUARD_CONFIG_DRIFT')
  })
  it('does NOT match config.conf outside wireguard dirs', () => {
    expect(triggeredRules(['config/config.conf'])).not.toContain('WIREGUARD_CONFIG_DRIFT')
  })
  it('does NOT match wgN pattern without .conf extension', () => {
    expect(triggeredRules(['wg0.yaml'])).not.toContain('WIREGUARD_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 3: IPSEC_STRONGSWAN_DRIFT
// ---------------------------------------------------------------------------

describe('IPSEC_STRONGSWAN_DRIFT', () => {
  it('matches ipsec.conf (ungated)', () => {
    expect(triggeredRules(['ipsec.conf'])).toContain('IPSEC_STRONGSWAN_DRIFT')
  })
  it('matches ipsec.secrets (ungated PSK/RSA file)', () => {
    expect(triggeredRules(['ipsec.secrets'])).toContain('IPSEC_STRONGSWAN_DRIFT')
  })
  it('matches strongswan.conf (ungated)', () => {
    expect(triggeredRules(['strongswan.conf'])).toContain('IPSEC_STRONGSWAN_DRIFT')
  })
  it('matches ipsec-prod.conf via prefix', () => {
    expect(triggeredRules(['ipsec-prod.conf'])).toContain('IPSEC_STRONGSWAN_DRIFT')
  })
  it('matches strongswan-server.yaml via prefix', () => {
    expect(triggeredRules(['strongswan-server.yaml'])).toContain('IPSEC_STRONGSWAN_DRIFT')
  })
  it('matches charon.conf inside strongswan/ dir', () => {
    expect(triggeredRules(['strongswan/charon.conf'])).toContain('IPSEC_STRONGSWAN_DRIFT')
  })
  it('matches swanctl.conf inside ipsec/ dir', () => {
    expect(triggeredRules(['ipsec/swanctl.conf'])).toContain('IPSEC_STRONGSWAN_DRIFT')
  })
  it('matches any .secrets file inside ipsec/ dir', () => {
    expect(triggeredRules(['ipsec/ipsec.secrets'])).toContain('IPSEC_STRONGSWAN_DRIFT')
  })
  it('matches any .conf inside libreswan/ dir', () => {
    expect(triggeredRules(['libreswan/site-to-site.conf'])).toContain('IPSEC_STRONGSWAN_DRIFT')
  })
  it('does NOT match config.conf outside ipsec dirs', () => {
    expect(triggeredRules(['app/config.conf'])).not.toContain('IPSEC_STRONGSWAN_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 4: VPN_PKI_CREDENTIAL_DRIFT (user contribution: isVpnPkiCredential)
// ---------------------------------------------------------------------------

describe('VPN_PKI_CREDENTIAL_DRIFT', () => {
  it('matches ca.key inside openvpn/ dir', () => {
    expect(triggeredRules(['openvpn/ca.key'])).toContain('VPN_PKI_CREDENTIAL_DRIFT')
  })
  it('matches server.pem inside vpn/ dir', () => {
    expect(triggeredRules(['vpn/server.pem'])).toContain('VPN_PKI_CREDENTIAL_DRIFT')
  })
  it('matches client.crt inside wireguard/ dir', () => {
    expect(triggeredRules(['wireguard/client.crt'])).toContain('VPN_PKI_CREDENTIAL_DRIFT')
  })
  it('matches client.p12 inside vpn-keys/ dir', () => {
    expect(triggeredRules(['vpn-keys/client.p12'])).toContain('VPN_PKI_CREDENTIAL_DRIFT')
  })
  it('matches cert.pfx inside vpn-certs/ dir', () => {
    expect(triggeredRules(['vpn-certs/cert.pfx'])).toContain('VPN_PKI_CREDENTIAL_DRIFT')
  })
  it('matches revoked.crl inside strongswan/ dir', () => {
    expect(triggeredRules(['strongswan/revoked.crl'])).toContain('VPN_PKI_CREDENTIAL_DRIFT')
  })
  it('does NOT match ta.key (already caught by OPENVPN rule)', () => {
    const result = scan(['ta.key'])
    const vpnPkiFindings = result.findings.filter((f) => f.ruleId === 'VPN_PKI_CREDENTIAL_DRIFT')
    expect(vpnPkiFindings).toHaveLength(0)
  })
  it('does NOT match ipsec.secrets (already caught by IPSEC rule)', () => {
    const result = scan(['ipsec.secrets'])
    const vpnPkiFindings = result.findings.filter((f) => f.ruleId === 'VPN_PKI_CREDENTIAL_DRIFT')
    expect(vpnPkiFindings).toHaveLength(0)
  })
  it('does NOT match cert.pem inside letsencrypt/ dir', () => {
    expect(triggeredRules(['letsencrypt/live/example.com/cert.pem'])).not.toContain('VPN_PKI_CREDENTIAL_DRIFT')
  })
  it('does NOT match cert.pem inside certbot/ dir', () => {
    expect(triggeredRules(['certbot/certs/cert.pem'])).not.toContain('VPN_PKI_CREDENTIAL_DRIFT')
  })
  it('does NOT match cert.pem in generic certs/ dir', () => {
    expect(triggeredRules(['certs/server.pem'])).not.toContain('VPN_PKI_CREDENTIAL_DRIFT')
  })
})

describe('isVpnPkiCredential unit tests', () => {
  it('returns true for ca.key in openvpn dir', () => {
    expect(isVpnPkiCredential('openvpn/ca.key', 'ca.key')).toBe(true)
  })
  it('returns true for server.pem in vpn dir', () => {
    expect(isVpnPkiCredential('vpn/server.pem', 'server.pem')).toBe(true)
  })
  it('returns true for client.p12 in wireguard dir', () => {
    expect(isVpnPkiCredential('wireguard/client.p12', 'client.p12')).toBe(true)
  })
  it('returns false for ta.key (excluded — OPENVPN rule handles it)', () => {
    expect(isVpnPkiCredential('openvpn/ta.key', 'ta.key')).toBe(false)
  })
  it('returns false for dh.pem (excluded — OPENVPN rule handles it)', () => {
    expect(isVpnPkiCredential('openvpn/dh.pem', 'dh.pem')).toBe(false)
  })
  it('returns false for ipsec.secrets (excluded — IPSEC rule handles it)', () => {
    expect(isVpnPkiCredential('ipsec/ipsec.secrets', 'ipsec.secrets')).toBe(false)
  })
  it('returns false for cert.pem in letsencrypt dir', () => {
    expect(isVpnPkiCredential('letsencrypt/live/example.com/cert.pem', 'cert.pem')).toBe(false)
  })
  it('returns false for cert.pem in certbot dir', () => {
    expect(isVpnPkiCredential('certbot/certs/cert.pem', 'cert.pem')).toBe(false)
  })
  it('returns false for cert.pem in cert-manager dir', () => {
    expect(isVpnPkiCredential('cert-manager/certs/cert.pem', 'cert.pem')).toBe(false)
  })
  it('returns false for cert.pem outside any VPN dir', () => {
    expect(isVpnPkiCredential('config/certs/cert.pem', 'cert.pem')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 5: REMOTE_ACCESS_GATEWAY_DRIFT
// ---------------------------------------------------------------------------

describe('REMOTE_ACCESS_GATEWAY_DRIFT', () => {
  it('matches guacamole.properties (ungated)', () => {
    expect(triggeredRules(['guacamole.properties'])).toContain('REMOTE_ACCESS_GATEWAY_DRIFT')
  })
  it('matches teleport.yaml (ungated)', () => {
    expect(triggeredRules(['teleport.yaml'])).toContain('REMOTE_ACCESS_GATEWAY_DRIFT')
  })
  it('matches teleport.toml (ungated)', () => {
    expect(triggeredRules(['teleport.toml'])).toContain('REMOTE_ACCESS_GATEWAY_DRIFT')
  })
  it('matches guacamole-config.conf via prefix', () => {
    expect(triggeredRules(['guacamole-config.conf'])).toContain('REMOTE_ACCESS_GATEWAY_DRIFT')
  })
  it('matches teleport-auth.yaml via prefix', () => {
    expect(triggeredRules(['teleport-auth.yaml'])).toContain('REMOTE_ACCESS_GATEWAY_DRIFT')
  })
  it('matches user-mapping.xml inside guacamole/ dir', () => {
    expect(triggeredRules(['guacamole/user-mapping.xml'])).toContain('REMOTE_ACCESS_GATEWAY_DRIFT')
  })
  it('matches logback.xml inside .guacamole/ dir', () => {
    expect(triggeredRules(['.guacamole/logback.xml'])).toContain('REMOTE_ACCESS_GATEWAY_DRIFT')
  })
  it('matches config.yaml inside teleport/ dir', () => {
    expect(triggeredRules(['teleport/config.yaml'])).toContain('REMOTE_ACCESS_GATEWAY_DRIFT')
  })
  it('matches config.json inside bastion/ dir', () => {
    expect(triggeredRules(['bastion/config.json'])).toContain('REMOTE_ACCESS_GATEWAY_DRIFT')
  })
  it('matches config.yaml inside jumpserver/ dir', () => {
    expect(triggeredRules(['jumpserver/config.yaml'])).toContain('REMOTE_ACCESS_GATEWAY_DRIFT')
  })
  it('does NOT match user-mapping.xml outside guacamole dirs', () => {
    expect(triggeredRules(['config/user-mapping.xml'])).not.toContain('REMOTE_ACCESS_GATEWAY_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 6: CISCO_VPN_DRIFT
// ---------------------------------------------------------------------------

describe('CISCO_VPN_DRIFT', () => {
  it('matches anyconnect.xml (ungated)', () => {
    expect(triggeredRules(['anyconnect.xml'])).toContain('CISCO_VPN_DRIFT')
  })
  it('matches anyconnect-profile.xml via prefix', () => {
    expect(triggeredRules(['anyconnect-profile.xml'])).toContain('CISCO_VPN_DRIFT')
  })
  it('matches anyconnect_corp.xml via prefix', () => {
    expect(triggeredRules(['anyconnect_corp.xml'])).toContain('CISCO_VPN_DRIFT')
  })
  it('matches cisco-vpn-config.conf via prefix', () => {
    expect(triggeredRules(['cisco-vpn-config.conf'])).toContain('CISCO_VPN_DRIFT')
  })
  it('matches profile.xml inside anyconnect/ dir', () => {
    expect(triggeredRules(['anyconnect/profile.xml'])).toContain('CISCO_VPN_DRIFT')
  })
  it('matches vpn-profile.xml inside cisco-vpn/ dir', () => {
    expect(triggeredRules(['cisco-vpn/vpn-profile.xml'])).toContain('CISCO_VPN_DRIFT')
  })
  it('matches policy.cfg inside asa/ dir', () => {
    expect(triggeredRules(['asa/policy.cfg'])).toContain('CISCO_VPN_DRIFT')
  })
  it('matches preferences.xml inside cisco-anyconnect/ dir', () => {
    expect(triggeredRules(['cisco-anyconnect/preferences.xml'])).toContain('CISCO_VPN_DRIFT')
  })
  it('does NOT match profile.xml outside cisco dirs', () => {
    expect(triggeredRules(['config/profile.xml'])).not.toContain('CISCO_VPN_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 7: SSL_VPN_SERVER_DRIFT
// ---------------------------------------------------------------------------

describe('SSL_VPN_SERVER_DRIFT', () => {
  it('matches pritunl.conf (ungated)', () => {
    expect(triggeredRules(['pritunl.conf'])).toContain('SSL_VPN_SERVER_DRIFT')
  })
  it('matches ocserv.conf (ungated OpenConnect server)', () => {
    expect(triggeredRules(['ocserv.conf'])).toContain('SSL_VPN_SERVER_DRIFT')
  })
  it('matches pptpd.conf (ungated PPTP daemon)', () => {
    expect(triggeredRules(['pptpd.conf'])).toContain('SSL_VPN_SERVER_DRIFT')
  })
  it('matches xl2tpd.conf (ungated L2TP daemon)', () => {
    expect(triggeredRules(['xl2tpd.conf'])).toContain('SSL_VPN_SERVER_DRIFT')
  })
  it('matches chap-secrets (ungated PPP auth)', () => {
    expect(triggeredRules(['chap-secrets'])).toContain('SSL_VPN_SERVER_DRIFT')
  })
  it('matches pap-secrets (ungated PPP auth)', () => {
    expect(triggeredRules(['pap-secrets'])).toContain('SSL_VPN_SERVER_DRIFT')
  })
  it('matches pritunl-config.json via prefix', () => {
    expect(triggeredRules(['pritunl-config.json'])).toContain('SSL_VPN_SERVER_DRIFT')
  })
  it('matches ocserv-tls.conf via prefix', () => {
    expect(triggeredRules(['ocserv-tls.conf'])).toContain('SSL_VPN_SERVER_DRIFT')
  })
  it('matches settings.json inside pritunl/ dir', () => {
    expect(triggeredRules(['pritunl/settings.json'])).toContain('SSL_VPN_SERVER_DRIFT')
  })
  it('matches config.conf inside ocserv/ dir', () => {
    expect(triggeredRules(['ocserv/config.conf'])).toContain('SSL_VPN_SERVER_DRIFT')
  })
  it('matches server.yaml inside ssl-vpn/ dir', () => {
    expect(triggeredRules(['ssl-vpn/server.yaml'])).toContain('SSL_VPN_SERVER_DRIFT')
  })
  it('does NOT match config.conf outside ssl vpn dirs', () => {
    expect(triggeredRules(['app/config.conf'])).not.toContain('SSL_VPN_SERVER_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 8: VPN_CLIENT_PROFILE_DRIFT
// ---------------------------------------------------------------------------

describe('VPN_CLIENT_PROFILE_DRIFT', () => {
  it('matches .nmconnection extension files (ungated NetworkManager)', () => {
    expect(triggeredRules(['corporate-vpn.nmconnection'])).toContain('VPN_CLIENT_PROFILE_DRIFT')
  })
  it('matches .nmconnection in subdirectory', () => {
    expect(triggeredRules(['network-manager/vpn.nmconnection'])).toContain('VPN_CLIENT_PROFILE_DRIFT')
  })
  it('matches vpn-client-config.conf via prefix', () => {
    expect(triggeredRules(['vpn-client-config.conf'])).toContain('VPN_CLIENT_PROFILE_DRIFT')
  })
  it('matches vpn-client-prod.ovpn via prefix', () => {
    expect(triggeredRules(['vpn-client-prod.ovpn'])).toContain('VPN_CLIENT_PROFILE_DRIFT')
  })
  it('matches vpn-config.json inside vpn-clients/ dir', () => {
    expect(triggeredRules(['vpn-clients/vpn-config.json'])).toContain('VPN_CLIENT_PROFILE_DRIFT')
  })
  it('matches vpn-settings.yaml inside client-vpn/ dir', () => {
    expect(triggeredRules(['client-vpn/vpn-settings.yaml'])).toContain('VPN_CLIENT_PROFILE_DRIFT')
  })
  it('matches corporate.yaml inside vpn-profiles/ dir', () => {
    expect(triggeredRules(['vpn-profiles/corporate.yaml'])).toContain('VPN_CLIENT_PROFILE_DRIFT')
  })
  it('matches bare CN filename inside ccd/ dir (OpenVPN CCD entry)', () => {
    expect(triggeredRules(['ccd/client1'])).toContain('VPN_CLIENT_PROFILE_DRIFT')
  })
  it('matches client.conf inside vpn-clients/ dir', () => {
    expect(triggeredRules(['vpn-clients/client.conf'])).toContain('VPN_CLIENT_PROFILE_DRIFT')
  })
  it('does NOT match config.json outside vpn client dirs', () => {
    expect(triggeredRules(['config/config.json'])).not.toContain('VPN_CLIENT_PROFILE_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Vendor exclusion
// ---------------------------------------------------------------------------

describe('vendor exclusion', () => {
  it('skips node_modules path', () => {
    expect(triggeredRules(['node_modules/openvpn/openvpn.conf'])).toHaveLength(0)
  })
  it('skips vendor path', () => {
    expect(triggeredRules(['vendor/vpn/ipsec.conf'])).toHaveLength(0)
  })
  it('skips .git path', () => {
    expect(triggeredRules(['.git/hooks/wg0.conf'])).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Windows path normalisation
// ---------------------------------------------------------------------------

describe('Windows path normalisation', () => {
  it('normalises backslashes for openvpn.conf', () => {
    expect(triggeredRules(['openvpn\\openvpn.conf'])).toContain('OPENVPN_CONFIG_DRIFT')
  })
  it('normalises backslashes for wg0.conf', () => {
    expect(triggeredRules(['wireguard\\wg0.conf'])).toContain('WIREGUARD_CONFIG_DRIFT')
  })
  it('normalises backslashes for ipsec.secrets in ipsec dir', () => {
    expect(triggeredRules(['ipsec\\ipsec.secrets'])).toContain('IPSEC_STRONGSWAN_DRIFT')
  })
  it('normalises backslashes for ca.key in openvpn dir', () => {
    expect(triggeredRules(['openvpn\\ca.key'])).toContain('VPN_PKI_CREDENTIAL_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

describe('deduplication', () => {
  it('produces a single finding per triggered rule', () => {
    const result = scan(['openvpn.conf', 'openvpn.conf', 'ta.key'])
    const openvpnFindings = result.findings.filter((f) => f.ruleId === 'OPENVPN_CONFIG_DRIFT')
    expect(openvpnFindings).toHaveLength(1)
  })
  it('records matchCount for multiple files matching same rule', () => {
    const result = scan(['openvpn.conf', 'ta.key', 'dh.pem'])
    const finding = result.findings.find((f) => f.ruleId === 'OPENVPN_CONFIG_DRIFT')
    expect(finding?.matchCount).toBe(3)
  })
  it('produces separate findings for different rules', () => {
    const result = scan(['openvpn.conf', 'wg0.conf', 'ipsec.conf', 'ipsec.secrets'])
    const ruleIds = result.findings.map((f) => f.ruleId)
    expect(ruleIds).toEqual(expect.arrayContaining([
      'OPENVPN_CONFIG_DRIFT',
      'WIREGUARD_CONFIG_DRIFT',
      'IPSEC_STRONGSWAN_DRIFT',
    ]))
  })
  it('records firstPath as the first matched file', () => {
    const result = scan(['wg0.conf', 'wg1.conf'])
    const finding = result.findings.find((f) => f.ruleId === 'WIREGUARD_CONFIG_DRIFT')
    expect(finding?.matchedPath).toBe('wg0.conf')
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scoring model', () => {
  it('1 high finding → score 15', () => {
    expect(scan(['openvpn.conf']).riskScore).toBe(15)
  })
  it('2 high findings → score 30', () => {
    expect(scan(['openvpn.conf', 'wg0.conf']).riskScore).toBe(30)
  })
  it('3 high findings → score 45', () => {
    expect(scan(['openvpn.conf', 'wg0.conf', 'ipsec.conf']).riskScore).toBe(45)
  })
  it('4 high findings → score 60', () => {
    expect(scan(['openvpn.conf', 'wg0.conf', 'ipsec.conf', 'openvpn/ca.key']).riskScore).toBe(60)
  })
  it('1 medium finding → score 8', () => {
    expect(scan(['guacamole.properties']).riskScore).toBe(8)
  })
  it('1 low finding → score 4', () => {
    expect(scan(['corporate-vpn.nmconnection']).riskScore).toBe(4)
  })
  it('4 high + 1 medium → score 68', () => {
    expect(
      scan(['openvpn.conf', 'wg0.conf', 'ipsec.conf', 'openvpn/ca.key', 'guacamole.properties']).riskScore,
    ).toBe(68)
  })
  it('4 high + 2 medium → score 76', () => {
    expect(
      scan(['openvpn.conf', 'wg0.conf', 'ipsec.conf', 'openvpn/ca.key', 'guacamole.properties', 'anyconnect.xml']).riskScore,
    ).toBe(76)
  })
  it('HIGH penalty caps at 45 per rule (3 matched files for same rule)', () => {
    const result = scan(['openvpn.conf', 'ta.key', 'dh.pem', 'tls-auth.key', 'dh2048.pem'])
    const finding = result.findings.find((f) => f.ruleId === 'OPENVPN_CONFIG_DRIFT')
    expect(finding?.matchCount).toBe(5)
    // penalty: min(5 × 15, 45) = 45
    expect(result.riskScore).toBe(45)
  })
  it('total score capped at 100 when all 8 rules fire', () => {
    const result = scan([
      'openvpn.conf', 'wg0.conf', 'ipsec.conf', 'openvpn/ca.key',
      'guacamole.properties', 'anyconnect.xml', 'pritunl.conf',
      'corporate-vpn.nmconnection',
    ])
    expect(result.riskScore).toBeLessThanOrEqual(100)
  })
})

// ---------------------------------------------------------------------------
// Risk level boundaries
// ---------------------------------------------------------------------------

describe('risk level boundaries', () => {
  it('score 0 → none', () => {
    expect(scan([]).riskLevel).toBe('none')
  })
  it('score 15 (1 high) → low', () => {
    expect(scan(['openvpn.conf']).riskLevel).toBe('low')
  })
  it('score 30 (2 high) → medium', () => {
    expect(scan(['openvpn.conf', 'wg0.conf']).riskLevel).toBe('medium')
  })
  it('score 45 (3 high) → high (45 is NOT < 45)', () => {
    expect(scan(['openvpn.conf', 'wg0.conf', 'ipsec.conf']).riskLevel).toBe('high')
  })
  it('score 60 (4 high) → high', () => {
    expect(scan(['openvpn.conf', 'wg0.conf', 'ipsec.conf', 'openvpn/ca.key']).riskLevel).toBe('high')
  })
  it('score 68 (4 high + 1 medium) → high', () => {
    expect(
      scan(['openvpn.conf', 'wg0.conf', 'ipsec.conf', 'openvpn/ca.key', 'guacamole.properties']).riskLevel,
    ).toBe('high')
  })
  it('score 76 (4 high + 2 medium) → critical', () => {
    expect(
      scan(['openvpn.conf', 'wg0.conf', 'ipsec.conf', 'openvpn/ca.key', 'guacamole.properties', 'anyconnect.xml']).riskLevel,
    ).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// Severity ordering in findings
// ---------------------------------------------------------------------------

describe('severity ordering', () => {
  it('high findings appear before medium', () => {
    const result = scan(['guacamole.properties', 'openvpn.conf'])
    const severities = result.findings.map((f) => f.severity)
    const highIdx   = severities.indexOf('high')
    const mediumIdx = severities.indexOf('medium')
    expect(highIdx).toBeLessThan(mediumIdx)
  })
  it('medium findings appear before low', () => {
    const result = scan(['corporate-vpn.nmconnection', 'guacamole.properties'])
    const severities = result.findings.map((f) => f.severity)
    const mediumIdx = severities.indexOf('medium')
    const lowIdx    = severities.indexOf('low')
    expect(mediumIdx).toBeLessThan(lowIdx)
  })
})

// ---------------------------------------------------------------------------
// Result shape
// ---------------------------------------------------------------------------

describe('result shape', () => {
  it('returns zero counts and empty findings for clean repo', () => {
    const result = scan([])
    expect(result.totalFindings).toBe(0)
    expect(result.highCount).toBe(0)
    expect(result.mediumCount).toBe(0)
    expect(result.lowCount).toBe(0)
    expect(result.findings).toHaveLength(0)
  })
  it('finding contains all required fields', () => {
    const result = scan(['openvpn.conf'])
    const f = result.findings[0]
    expect(f).toHaveProperty('ruleId')
    expect(f).toHaveProperty('severity')
    expect(f).toHaveProperty('matchedPath')
    expect(f).toHaveProperty('matchCount')
    expect(f).toHaveProperty('description')
    expect(f).toHaveProperty('recommendation')
  })
  it('summary mentions no drift when clean', () => {
    expect(scan([]).summary).toContain('No VPN')
  })
  it('summary mentions count and score when findings exist', () => {
    const result = scan(['openvpn.conf'])
    expect(result.summary).toContain('1')
    expect(result.summary).toContain('15')
  })
  it('matchedPath preserves original casing', () => {
    const result = scan(['OpenVPN/server.conf'])
    const finding = result.findings.find((f) => f.ruleId === 'OPENVPN_CONFIG_DRIFT')
    expect(finding?.matchedPath).toBe('OpenVPN/server.conf')
  })
})

// ---------------------------------------------------------------------------
// Multi-rule scenarios
// ---------------------------------------------------------------------------

describe('multi-rule scenarios', () => {
  it('openvpn.conf and guacamole.properties trigger two separate rules', () => {
    const result = scan(['openvpn.conf', 'guacamole.properties'])
    expect(result.totalFindings).toBe(2)
    expect(result.highCount).toBe(1)
    expect(result.mediumCount).toBe(1)
  })
  it('can trigger all 4 HIGH rules simultaneously', () => {
    const result = scan(['openvpn.conf', 'wg0.conf', 'ipsec.conf', 'openvpn/ca.key'])
    expect(result.highCount).toBe(4)
  })
  it('ta.key triggers OPENVPN but not VPN_PKI (excluded from PKI rule)', () => {
    const result = scan(['ta.key'])
    expect(result.findings.map((f) => f.ruleId)).toContain('OPENVPN_CONFIG_DRIFT')
    expect(result.findings.map((f) => f.ruleId)).not.toContain('VPN_PKI_CREDENTIAL_DRIFT')
  })
  it('ipsec.secrets triggers IPSEC but not VPN_PKI (excluded from PKI rule)', () => {
    const result = scan(['ipsec.secrets'])
    expect(result.findings.map((f) => f.ruleId)).toContain('IPSEC_STRONGSWAN_DRIFT')
    expect(result.findings.map((f) => f.ruleId)).not.toContain('VPN_PKI_CREDENTIAL_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule registry completeness
// ---------------------------------------------------------------------------

describe('rule registry', () => {
  it('exports exactly 8 rules', () => {
    expect(VPN_REMOTE_ACCESS_RULES).toHaveLength(8)
  })
  it('covers all expected rule IDs', () => {
    const ids = VPN_REMOTE_ACCESS_RULES.map((r) => r.id)
    expect(ids).toEqual(expect.arrayContaining([
      'OPENVPN_CONFIG_DRIFT',
      'WIREGUARD_CONFIG_DRIFT',
      'IPSEC_STRONGSWAN_DRIFT',
      'VPN_PKI_CREDENTIAL_DRIFT',
      'REMOTE_ACCESS_GATEWAY_DRIFT',
      'CISCO_VPN_DRIFT',
      'SSL_VPN_SERVER_DRIFT',
      'VPN_CLIENT_PROFILE_DRIFT',
    ]))
  })
  it('has 4 HIGH, 3 MEDIUM, 1 LOW rules', () => {
    const severities = VPN_REMOTE_ACCESS_RULES.map((r) => r.severity)
    expect(severities.filter((s) => s === 'high')).toHaveLength(4)
    expect(severities.filter((s) => s === 'medium')).toHaveLength(3)
    expect(severities.filter((s) => s === 'low')).toHaveLength(1)
  })
})
