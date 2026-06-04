import { describe, expect, it } from 'vitest'
import {
  isWirelessControllerConfig,
  WIRELESS_RADIUS_RULES,
  scanWirelessRadiusDrift,
} from './wirelessRadiusDrift'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function rule(id: string) {
  const r = WIRELESS_RADIUS_RULES.find((x) => x.id === id)
  if (!r) throw new Error(`Rule ${id} not found`)
  return r
}

function match(ruleId: string, path: string): boolean {
  const r         = rule(ruleId)
  const pathLower = path.toLowerCase()
  const base      = pathLower.split('/').pop() ?? pathLower
  return r.match(pathLower, base)
}

// ---------------------------------------------------------------------------
// HOSTAPD_AP_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('HOSTAPD_AP_CONFIG_DRIFT', () => {
  it('matches hostapd.conf', () => {
    expect(match('HOSTAPD_AP_CONFIG_DRIFT', 'etc/hostapd/hostapd.conf')).toBe(true)
  })
  it('matches hostapd.conf at root', () => {
    expect(match('HOSTAPD_AP_CONFIG_DRIFT', 'hostapd.conf')).toBe(true)
  })
  it('matches hostapd.wpa_psk', () => {
    expect(match('HOSTAPD_AP_CONFIG_DRIFT', 'hostapd.wpa_psk')).toBe(true)
  })
  it('matches hostapd.eap_user', () => {
    expect(match('HOSTAPD_AP_CONFIG_DRIFT', 'hostapd.eap_user')).toBe(true)
  })
  it('matches hostapd.accept MAC allowlist', () => {
    expect(match('HOSTAPD_AP_CONFIG_DRIFT', 'hostapd.accept')).toBe(true)
  })
  it('matches hostapd.deny MAC blocklist', () => {
    expect(match('HOSTAPD_AP_CONFIG_DRIFT', 'hostapd.deny')).toBe(true)
  })
  it('matches hostapd-wpa3.conf prefix', () => {
    expect(match('HOSTAPD_AP_CONFIG_DRIFT', 'hostapd-wpa3.conf')).toBe(true)
  })
  it('matches hostapd-5ghz.conf prefix', () => {
    expect(match('HOSTAPD_AP_CONFIG_DRIFT', 'wireless/hostapd-5ghz.conf')).toBe(true)
  })
  it('matches hostapd.conf.j2 template', () => {
    expect(match('HOSTAPD_AP_CONFIG_DRIFT', 'hostapd.conf.j2')).toBe(true)
  })
  it('matches .conf in hostapd/ dir', () => {
    expect(match('HOSTAPD_AP_CONFIG_DRIFT', 'hostapd/custom.conf')).toBe(true)
  })
  it('matches .conf in wifi/ dir', () => {
    expect(match('HOSTAPD_AP_CONFIG_DRIFT', 'wifi/ap.conf')).toBe(true)
  })
  it('matches .conf in wireless/ dir', () => {
    expect(match('HOSTAPD_AP_CONFIG_DRIFT', 'wireless/ap.conf')).toBe(true)
  })
  it('matches .psk in hostapd/ dir', () => {
    expect(match('HOSTAPD_AP_CONFIG_DRIFT', 'hostapd/wpa.psk')).toBe(true)
  })
  it('does not match generic nginx.conf', () => {
    expect(match('HOSTAPD_AP_CONFIG_DRIFT', 'nginx.conf')).toBe(false)
  })
  it('does not match .conf outside hostapd dirs', () => {
    expect(match('HOSTAPD_AP_CONFIG_DRIFT', 'config/server.conf')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// WPA_SUPPLICANT_DRIFT
// ---------------------------------------------------------------------------

describe('WPA_SUPPLICANT_DRIFT', () => {
  it('matches wpa_supplicant.conf', () => {
    expect(match('WPA_SUPPLICANT_DRIFT', 'etc/wpa_supplicant/wpa_supplicant.conf')).toBe(true)
  })
  it('matches wpa_supplicant.conf at root', () => {
    expect(match('WPA_SUPPLICANT_DRIFT', 'wpa_supplicant.conf')).toBe(true)
  })
  it('matches wpa_supplicant-wlan0.conf interface-specific', () => {
    expect(match('WPA_SUPPLICANT_DRIFT', 'etc/wpa_supplicant/wpa_supplicant-wlan0.conf')).toBe(true)
  })
  it('matches wpa_supplicant-wlp2s0.conf', () => {
    expect(match('WPA_SUPPLICANT_DRIFT', 'wpa_supplicant-wlp2s0.conf')).toBe(true)
  })
  it('matches wpa-supplicant.conf dash variant', () => {
    expect(match('WPA_SUPPLICANT_DRIFT', 'wpa-supplicant.conf')).toBe(true)
  })
  it('matches wpa_supplicant.conf.j2 template', () => {
    expect(match('WPA_SUPPLICANT_DRIFT', 'templates/wpa_supplicant.conf.j2')).toBe(true)
  })
  it('matches wpa_supplicant.conf-backup', () => {
    expect(match('WPA_SUPPLICANT_DRIFT', 'wpa_supplicant.conf-backup')).toBe(true)
  })
  it('matches .conf in wpa_supplicant/ dir', () => {
    expect(match('WPA_SUPPLICANT_DRIFT', 'wpa_supplicant/networks.conf')).toBe(true)
  })
  it('matches .conf in etc/wpa_supplicant/', () => {
    expect(match('WPA_SUPPLICANT_DRIFT', 'etc/wpa_supplicant/custom.conf')).toBe(true)
  })
  it('does not match sshd_config', () => {
    expect(match('WPA_SUPPLICANT_DRIFT', 'etc/ssh/sshd_config')).toBe(false)
  })
  it('does not match generic .conf outside wpa dirs', () => {
    expect(match('WPA_SUPPLICANT_DRIFT', 'config/network.conf')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// FREERADIUS_SERVER_DRIFT
// ---------------------------------------------------------------------------

describe('FREERADIUS_SERVER_DRIFT', () => {
  it('matches radiusd.conf', () => {
    expect(match('FREERADIUS_SERVER_DRIFT', 'etc/freeradius/radiusd.conf')).toBe(true)
  })
  it('matches radiusd.conf at root', () => {
    expect(match('FREERADIUS_SERVER_DRIFT', 'radiusd.conf')).toBe(true)
  })
  it('matches freeradius.conf', () => {
    expect(match('FREERADIUS_SERVER_DRIFT', 'freeradius.conf')).toBe(true)
  })
  it('matches radiusd.conf.j2 template', () => {
    expect(match('FREERADIUS_SERVER_DRIFT', 'templates/radiusd.conf.j2')).toBe(true)
  })
  it('matches clients.conf in freeradius/ dir', () => {
    expect(match('FREERADIUS_SERVER_DRIFT', 'etc/freeradius/clients.conf')).toBe(true)
  })
  it('matches clients.conf in raddb/ dir', () => {
    expect(match('FREERADIUS_SERVER_DRIFT', 'etc/raddb/clients.conf')).toBe(true)
  })
  it('matches users in raddb/ dir', () => {
    expect(match('FREERADIUS_SERVER_DRIFT', 'etc/raddb/users')).toBe(true)
  })
  it('matches huntgroups in freeradius/ dir', () => {
    expect(match('FREERADIUS_SERVER_DRIFT', 'freeradius/huntgroups')).toBe(true)
  })
  it('matches dictionary in radius/ dir', () => {
    expect(match('FREERADIUS_SERVER_DRIFT', 'radius/dictionary')).toBe(true)
  })
  it('matches .conf in freeradius/ dir', () => {
    expect(match('FREERADIUS_SERVER_DRIFT', 'freeradius/inner-tunnel.conf')).toBe(true)
  })
  it('does not match clients.conf outside radius dirs', () => {
    expect(match('FREERADIUS_SERVER_DRIFT', 'config/clients.conf')).toBe(false)
  })
  it('does not match users outside radius dirs', () => {
    expect(match('FREERADIUS_SERVER_DRIFT', 'app/users')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// TACACS_PLUS_DRIFT
// ---------------------------------------------------------------------------

describe('TACACS_PLUS_DRIFT', () => {
  it('matches tac_plus.conf', () => {
    expect(match('TACACS_PLUS_DRIFT', 'etc/tacacs/tac_plus.conf')).toBe(true)
  })
  it('matches tac_plus.conf at root', () => {
    expect(match('TACACS_PLUS_DRIFT', 'tac_plus.conf')).toBe(true)
  })
  it('matches tac_plus.cfg', () => {
    expect(match('TACACS_PLUS_DRIFT', 'tac_plus.cfg')).toBe(true)
  })
  it('matches tacacs.conf', () => {
    expect(match('TACACS_PLUS_DRIFT', 'tacacs.conf')).toBe(true)
  })
  it('matches tacacs+.conf', () => {
    expect(match('TACACS_PLUS_DRIFT', 'tacacs+.conf')).toBe(true)
  })
  it('matches tac_plus-admin.conf prefix', () => {
    expect(match('TACACS_PLUS_DRIFT', 'tac_plus-admin.conf')).toBe(true)
  })
  it('matches tacacs-routers.conf prefix', () => {
    expect(match('TACACS_PLUS_DRIFT', 'tacacs-routers.conf')).toBe(true)
  })
  it('matches .conf in tacacs/ dir', () => {
    expect(match('TACACS_PLUS_DRIFT', 'tacacs/settings.conf')).toBe(true)
  })
  it('matches .conf in aaa/ dir', () => {
    expect(match('TACACS_PLUS_DRIFT', 'aaa/tacacs.conf')).toBe(true)
  })
  it('matches users in tac_plus/ dir', () => {
    expect(match('TACACS_PLUS_DRIFT', 'tac_plus/users')).toBe(true)
  })
  it('does not match unrelated .conf', () => {
    expect(match('TACACS_PLUS_DRIFT', 'config/app.conf')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// WIRELESS_CONTROLLER_DRIFT (isWirelessControllerConfig)
// ---------------------------------------------------------------------------

describe('WIRELESS_CONTROLLER_DRIFT', () => {
  it('matches config.gateway.json in unifi/ dir', () => {
    expect(match('WIRELESS_CONTROLLER_DRIFT', 'unifi/config.gateway.json')).toBe(true)
  })
  it('matches config.system.json in unifi/ dir', () => {
    expect(match('WIRELESS_CONTROLLER_DRIFT', 'unifi/sites/default/config.system.json')).toBe(true)
  })
  it('matches config.properties in unifi/ dir', () => {
    expect(match('WIRELESS_CONTROLLER_DRIFT', 'unifi/config.properties')).toBe(true)
  })
  it('matches .json in wifi-controller/ dir', () => {
    expect(match('WIRELESS_CONTROLLER_DRIFT', 'wifi-controller/settings.json')).toBe(true)
  })
  it('matches .yaml in wireless-controller/ dir', () => {
    expect(match('WIRELESS_CONTROLLER_DRIFT', 'wireless-controller/ssid-policy.yaml')).toBe(true)
  })
  it('matches .conf in aruba/ dir', () => {
    expect(match('WIRELESS_CONTROLLER_DRIFT', 'aruba/controller.conf')).toBe(true)
  })
  it('matches wlc-* prefix with .conf', () => {
    expect(match('WIRELESS_CONTROLLER_DRIFT', 'wlc-primary.conf')).toBe(true)
  })
  it('matches aruba-* prefix with .yaml', () => {
    expect(match('WIRELESS_CONTROLLER_DRIFT', 'aruba-controller.yaml')).toBe(true)
  })
  it('matches unifi-* prefix with .json', () => {
    expect(match('WIRELESS_CONTROLLER_DRIFT', 'unifi-site-config.json')).toBe(true)
  })
  it('matches .cfg in wlc/ dir', () => {
    expect(match('WIRELESS_CONTROLLER_DRIFT', 'wlc/site.cfg')).toBe(true)
  })
  it('does not match unrelated json outside wc dirs', () => {
    expect(match('WIRELESS_CONTROLLER_DRIFT', 'src/config.json')).toBe(false)
  })
  it('does not match random .yaml outside wc dirs', () => {
    expect(match('WIRELESS_CONTROLLER_DRIFT', 'k8s/deployment.yaml')).toBe(false)
  })
})

describe('isWirelessControllerConfig direct', () => {
  it('returns true for config.gateway.json in unifi/ dir', () => {
    expect(isWirelessControllerConfig('unifi/config.gateway.json', 'config.gateway.json')).toBe(true)
  })
  it('returns false for random json outside wc dirs', () => {
    expect(isWirelessControllerConfig('src/app.json', 'app.json')).toBe(false)
  })
  it('returns true for wlc- prefix .conf', () => {
    expect(isWirelessControllerConfig('wlc-backup.conf', 'wlc-backup.conf')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// RADIUS_POLICY_DRIFT
// ---------------------------------------------------------------------------

describe('RADIUS_POLICY_DRIFT', () => {
  it('matches proxy.conf in freeradius/ dir', () => {
    expect(match('RADIUS_POLICY_DRIFT', 'etc/freeradius/proxy.conf')).toBe(true)
  })
  it('matches proxy.conf in raddb/ dir', () => {
    expect(match('RADIUS_POLICY_DRIFT', 'etc/raddb/proxy.conf')).toBe(true)
  })
  it('matches file in sites-enabled/ inside freeradius/ dir', () => {
    expect(match('RADIUS_POLICY_DRIFT', 'etc/freeradius/sites-enabled/default')).toBe(true)
  })
  it('matches file in sites-available/ inside raddb/', () => {
    expect(match('RADIUS_POLICY_DRIFT', 'etc/raddb/sites-available/inner-tunnel')).toBe(true)
  })
  it('matches .conf in policy.d/ inside freeradius/', () => {
    expect(match('RADIUS_POLICY_DRIFT', 'freeradius/policy.d/accounting.conf')).toBe(true)
  })
  it('matches file in mods-enabled/ inside freeradius/', () => {
    expect(match('RADIUS_POLICY_DRIFT', 'etc/freeradius/mods-enabled/eap')).toBe(true)
  })
  it('matches file in mods-available/ inside raddb/', () => {
    expect(match('RADIUS_POLICY_DRIFT', 'raddb/mods-available/sql')).toBe(true)
  })
  it('matches policy.conf in freeradius/', () => {
    expect(match('RADIUS_POLICY_DRIFT', 'freeradius/policy.conf')).toBe(true)
  })
  it('matches filter.conf in radius/', () => {
    expect(match('RADIUS_POLICY_DRIFT', 'radius/filter.conf')).toBe(true)
  })
  it('matches sql.conf in freeradius/', () => {
    expect(match('RADIUS_POLICY_DRIFT', 'freeradius3/sql.conf')).toBe(true)
  })
  it('does not match sites-enabled outside radius dirs', () => {
    expect(match('RADIUS_POLICY_DRIFT', 'apache/sites-enabled/000-default')).toBe(false)
  })
  it('does not match proxy.conf outside radius dirs', () => {
    expect(match('RADIUS_POLICY_DRIFT', 'nginx/proxy.conf')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// DOT1X_EAP_PROFILE_DRIFT
// ---------------------------------------------------------------------------

describe('DOT1X_EAP_PROFILE_DRIFT', () => {
  it('matches eapol.conf', () => {
    expect(match('DOT1X_EAP_PROFILE_DRIFT', 'eapol.conf')).toBe(true)
  })
  it('matches eapol_test.conf', () => {
    expect(match('DOT1X_EAP_PROFILE_DRIFT', 'eapol_test.conf')).toBe(true)
  })
  it('matches eap-tls.conf prefix', () => {
    expect(match('DOT1X_EAP_PROFILE_DRIFT', 'eap-tls.conf')).toBe(true)
  })
  it('matches eap-peap.conf prefix', () => {
    expect(match('DOT1X_EAP_PROFILE_DRIFT', 'eap-peap.conf')).toBe(true)
  })
  it('matches eap_ttls.conf prefix', () => {
    expect(match('DOT1X_EAP_PROFILE_DRIFT', 'eap_ttls.conf')).toBe(true)
  })
  it('matches eap.conf in freeradius/ dir', () => {
    expect(match('DOT1X_EAP_PROFILE_DRIFT', 'freeradius/eap.conf')).toBe(true)
  })
  it('matches eap.conf in hostapd/ dir', () => {
    expect(match('DOT1X_EAP_PROFILE_DRIFT', 'hostapd/eap.conf')).toBe(true)
  })
  it('matches .conf in dot1x/ dir', () => {
    expect(match('DOT1X_EAP_PROFILE_DRIFT', 'dot1x/supplicant.conf')).toBe(true)
  })
  it('matches .conf in 802.1x/ dir', () => {
    expect(match('DOT1X_EAP_PROFILE_DRIFT', '802.1x/profile.conf')).toBe(true)
  })
  it('matches .pem in eap/ dir', () => {
    expect(match('DOT1X_EAP_PROFILE_DRIFT', 'eap/client.pem')).toBe(true)
  })
  it('matches .crt in network-auth/ dir', () => {
    expect(match('DOT1X_EAP_PROFILE_DRIFT', 'network-auth/ca.crt')).toBe(true)
  })
  it('does not match eap.conf outside radius/hostapd dirs', () => {
    expect(match('DOT1X_EAP_PROFILE_DRIFT', 'config/eap.conf')).toBe(false)
  })
  it('does not match random .conf outside dot1x dirs', () => {
    expect(match('DOT1X_EAP_PROFILE_DRIFT', 'config/server.conf')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// CAPTIVE_PORTAL_DRIFT
// ---------------------------------------------------------------------------

describe('CAPTIVE_PORTAL_DRIFT', () => {
  it('matches nodogsplash.conf', () => {
    expect(match('CAPTIVE_PORTAL_DRIFT', 'etc/nodogsplash/nodogsplash.conf')).toBe(true)
  })
  it('matches nodogsplash.conf at root', () => {
    expect(match('CAPTIVE_PORTAL_DRIFT', 'nodogsplash.conf')).toBe(true)
  })
  it('matches chillispot.conf', () => {
    expect(match('CAPTIVE_PORTAL_DRIFT', 'chillispot.conf')).toBe(true)
  })
  it('matches chilli.conf', () => {
    expect(match('CAPTIVE_PORTAL_DRIFT', 'chilli.conf')).toBe(true)
  })
  it('matches coova-chilli.conf', () => {
    expect(match('CAPTIVE_PORTAL_DRIFT', 'coova-chilli.conf')).toBe(true)
  })
  it('matches nodogsplash-custom.conf prefix', () => {
    expect(match('CAPTIVE_PORTAL_DRIFT', 'nodogsplash-custom.conf')).toBe(true)
  })
  it('matches chilli-hotspot.conf prefix', () => {
    expect(match('CAPTIVE_PORTAL_DRIFT', 'chilli-hotspot.conf')).toBe(true)
  })
  it('matches coova-radius.conf prefix', () => {
    expect(match('CAPTIVE_PORTAL_DRIFT', 'coova-radius.conf')).toBe(true)
  })
  it('matches .conf in captive-portal/ dir', () => {
    expect(match('CAPTIVE_PORTAL_DRIFT', 'captive-portal/settings.conf')).toBe(true)
  })
  it('matches .json in portal/ dir', () => {
    expect(match('CAPTIVE_PORTAL_DRIFT', 'portal/config.json')).toBe(true)
  })
  it('matches .conf in hotspot/ dir', () => {
    expect(match('CAPTIVE_PORTAL_DRIFT', 'hotspot/portal.conf')).toBe(true)
  })
  it('does not match unrelated .conf', () => {
    expect(match('CAPTIVE_PORTAL_DRIFT', 'config/app.conf')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// scanWirelessRadiusDrift integration
// ---------------------------------------------------------------------------

describe('scanWirelessRadiusDrift', () => {
  it('returns clean result for empty input', () => {
    const r = scanWirelessRadiusDrift([])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
    expect(r.totalFindings).toBe(0)
    expect(r.summary).toMatch(/no wireless/i)
  })

  it('returns clean result for unrelated files', () => {
    const r = scanWirelessRadiusDrift(['src/app.ts', 'package.json', 'README.md'])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })

  it('detects hostapd.conf as high finding', () => {
    const r = scanWirelessRadiusDrift(['etc/hostapd/hostapd.conf'])
    expect(r.highCount).toBe(1)
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('medium')
    expect(r.findings[0]?.ruleId).toBe('HOSTAPD_AP_CONFIG_DRIFT')
  })

  it('detects wpa_supplicant.conf as high finding', () => {
    const r = scanWirelessRadiusDrift(['wpa_supplicant.conf'])
    expect(r.highCount).toBe(1)
    expect(r.findings[0]?.ruleId).toBe('WPA_SUPPLICANT_DRIFT')
  })

  it('detects radiusd.conf as high finding', () => {
    const r = scanWirelessRadiusDrift(['etc/freeradius/radiusd.conf'])
    expect(r.highCount).toBe(1)
    expect(r.findings[0]?.ruleId).toBe('FREERADIUS_SERVER_DRIFT')
  })

  it('detects tac_plus.conf as high finding', () => {
    const r = scanWirelessRadiusDrift(['tac_plus.conf'])
    expect(r.highCount).toBe(1)
    expect(r.findings[0]?.ruleId).toBe('TACACS_PLUS_DRIFT')
  })

  it('detects wireless controller config as medium finding', () => {
    const r = scanWirelessRadiusDrift(['unifi/config.gateway.json'])
    expect(r.mediumCount).toBe(1)
    expect(r.findings[0]?.ruleId).toBe('WIRELESS_CONTROLLER_DRIFT')
  })

  it('detects RADIUS policy file as medium finding', () => {
    const r = scanWirelessRadiusDrift(['etc/freeradius/sites-enabled/default'])
    expect(r.mediumCount).toBe(1)
    expect(r.findings[0]?.ruleId).toBe('RADIUS_POLICY_DRIFT')
  })

  it('detects eapol.conf as medium finding', () => {
    const r = scanWirelessRadiusDrift(['eapol.conf'])
    expect(r.mediumCount).toBe(1)
    expect(r.findings[0]?.ruleId).toBe('DOT1X_EAP_PROFILE_DRIFT')
  })

  it('detects nodogsplash.conf as low finding', () => {
    const r = scanWirelessRadiusDrift(['nodogsplash.conf'])
    expect(r.lowCount).toBe(1)
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
    expect(r.findings[0]?.ruleId).toBe('CAPTIVE_PORTAL_DRIFT')
  })

  it('skips vendor directory paths', () => {
    const r = scanWirelessRadiusDrift([
      'vendor/wifi/wpa_supplicant.conf',
      'node_modules/hostapd/hostapd.conf',
    ])
    expect(r.totalFindings).toBe(0)
  })

  it('accumulates matchCount for multiple files same rule', () => {
    const r = scanWirelessRadiusDrift([
      'etc/freeradius/radiusd.conf',
      'etc/freeradius/clients.conf',
      'etc/raddb/users',
    ])
    const f = r.findings.find((x) => x.ruleId === 'FREERADIUS_SERVER_DRIFT')
    expect(f?.matchCount).toBe(3)
    expect(f?.matchedPath).toBe('etc/freeradius/radiusd.conf')
  })

  it('only one finding per rule', () => {
    const r = scanWirelessRadiusDrift([
      'hostapd.conf',
      'hostapd-wpa3.conf',
      'wifi/custom.conf',
    ])
    expect(r.findings.filter((f) => f.ruleId === 'HOSTAPD_AP_CONFIG_DRIFT')).toHaveLength(1)
  })

  it('scores two high findings at 30', () => {
    const r = scanWirelessRadiusDrift(['hostapd.conf', 'wpa_supplicant.conf'])
    expect(r.riskScore).toBe(30)
    expect(r.riskLevel).toBe('medium')
  })

  it('scores all four high findings at cap 45 → high', () => {
    const r = scanWirelessRadiusDrift([
      'hostapd.conf',
      'wpa_supplicant.conf',
      'radiusd.conf',
      'tac_plus.conf',
    ])
    // 4 × 15 = 60, capped at 45; 45 is not < 45 → 'high'
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('scores all 8 rules', () => {
    const r = scanWirelessRadiusDrift([
      'hostapd.conf',
      'wpa_supplicant.conf',
      'radiusd.conf',
      'tac_plus.conf',
      'unifi/config.gateway.json',
      'etc/freeradius/sites-enabled/default',
      'eapol.conf',
      'nodogsplash.conf',
    ])
    // HIGH: min(4×15, 45)=45; MEDIUM: min(3×8, 25)=24; LOW: min(1×4, 15)=4 → 73
    expect(r.riskScore).toBe(73)
    expect(r.riskLevel).toBe('high')
    expect(r.totalFindings).toBe(8)
  })

  it('summary includes risk score and level', () => {
    const r = scanWirelessRadiusDrift(['hostapd.conf', 'wpa_supplicant.conf'])
    expect(r.summary).toMatch(/30\/100/)
    expect(r.summary).toMatch(/medium/i)
  })

  it('handles Windows-style backslash paths', () => {
    const r = scanWirelessRadiusDrift(['etc\\hostapd\\hostapd.conf'])
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0]?.ruleId).toBe('HOSTAPD_AP_CONFIG_DRIFT')
  })

  it('matchedPath preserves original casing', () => {
    const r = scanWirelessRadiusDrift(['Etc/FreeRADIUS/radiusd.conf'])
    expect(r.findings[0]?.matchedPath).toBe('Etc/FreeRADIUS/radiusd.conf')
  })
})

// ---------------------------------------------------------------------------
// Risk level boundary tests
// ---------------------------------------------------------------------------

describe('risk level boundaries', () => {
  it('score 0 → none', () => {
    expect(scanWirelessRadiusDrift([]).riskLevel).toBe('none')
  })

  it('score 4 (1 LOW) → low', () => {
    const r = scanWirelessRadiusDrift(['nodogsplash.conf'])
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('score 15 (1 HIGH) → medium', () => {
    const r = scanWirelessRadiusDrift(['hostapd.conf'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('medium')
  })

  it('score 45 (3 HIGH) → high (45 is not < 45)', () => {
    const r = scanWirelessRadiusDrift(['hostapd.conf', 'wpa_supplicant.conf', 'radiusd.conf'])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('score 53 (2 HIGH + 2 MEDIUM + 1 LOW) → high', () => {
    const r = scanWirelessRadiusDrift([
      'hostapd.conf',
      'wpa_supplicant.conf',
      'unifi/config.gateway.json',
      'etc/freeradius/sites-enabled/default',
      'nodogsplash.conf',
    ])
    // HIGH: min(2×15,45)=30; MEDIUM: min(2×8,25)=16; LOW: min(1×4,15)=4 → 50
    expect(r.riskScore).toBe(50)
    expect(r.riskLevel).toBe('high')
  })

  it('score 73 (all 8 rules) → high', () => {
    const r = scanWirelessRadiusDrift([
      'hostapd.conf',
      'wpa_supplicant.conf',
      'radiusd.conf',
      'tac_plus.conf',
      'unifi/config.gateway.json',
      'etc/freeradius/sites-enabled/default',
      'eapol.conf',
      'nodogsplash.conf',
    ])
    expect(r.riskScore).toBe(73)
    expect(r.riskLevel).toBe('high')
  })
})
