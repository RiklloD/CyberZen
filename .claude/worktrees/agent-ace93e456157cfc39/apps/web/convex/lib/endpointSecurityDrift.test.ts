import { describe, it, expect } from 'vitest'
import {
  scanEndpointSecurityDrift,
  isMdmDevicePolicyFile,
} from './endpointSecurityDrift'

// ---------------------------------------------------------------------------
// Rule 1: CROWDSTRIKE_FALCON_DRIFT (high)
// ---------------------------------------------------------------------------

describe('CROWDSTRIKE_FALCON_DRIFT', () => {
  describe('ungated exact names', () => {
    it.each([
      'falcon.cfg',
      'falcon-sensor.cfg',
      'falcon-agent.conf',
      'cs.conf',
      'crowdstrike.conf',
      'falcon.conf',
      'falcon-sensor.conf',
      'falcon-prevention.json',
      'crowdstrike-policy.json',
      'crowdstrike-config.json',
    ])('matches %s', (file) => {
      const r = scanEndpointSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'CROWDSTRIKE_FALCON_DRIFT')).toBe(true)
    })
  })

  describe('prefix-ungated', () => {
    it.each([
      'crowdstrike-custom.yaml',
      'crowdstrike-settings.conf',
      'falcon-prevention-policy.json',
      'falcon-detection.yml',
    ])('matches %s', (file) => {
      const r = scanEndpointSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'CROWDSTRIKE_FALCON_DRIFT')).toBe(true)
    })

    it('falcon-policy.toml does NOT match (toml not in prefix allowlist)', () => {
      const r = scanEndpointSecurityDrift(['falcon-policy.toml'])
      expect(r.findings.some((f) => f.ruleId === 'CROWDSTRIKE_FALCON_DRIFT')).toBe(false)
    })
  })

  describe('directory-based', () => {
    it.each([
      'crowdstrike/sensor.conf',
      'falcon/prevention.yaml',
      'falcon-sensor/agent.json',
      'cs-agent/policy.conf',
      'edr/crowdstrike/config.toml',
    ])('matches %s', (file) => {
      const r = scanEndpointSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'CROWDSTRIKE_FALCON_DRIFT')).toBe(true)
    })

    it('crowdstrike/binary.js does NOT match (js not in allowlist)', () => {
      const r = scanEndpointSecurityDrift(['crowdstrike/binary.js'])
      expect(r.findings.some((f) => f.ruleId === 'CROWDSTRIKE_FALCON_DRIFT')).toBe(false)
    })
  })

  it('vendor path excluded', () => {
    const r = scanEndpointSecurityDrift(['vendor/falcon.cfg'])
    expect(r.findings.some((f) => f.ruleId === 'CROWDSTRIKE_FALCON_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 2: SENTINELONE_POLICY_DRIFT (high)
// ---------------------------------------------------------------------------

describe('SENTINELONE_POLICY_DRIFT', () => {
  describe('ungated exact names', () => {
    it.each([
      'sentinelone.conf',
      'sentinelone.json',
      's1.conf',
      's1-agent.conf',
      's1-policy.json',
      'sentinelone-policy.json',
      'sentinelone-config.json',
      'sentinelone-agent.conf',
    ])('matches %s', (file) => {
      const r = scanEndpointSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'SENTINELONE_POLICY_DRIFT')).toBe(true)
    })
  })

  describe('prefix-ungated', () => {
    it.each([
      'sentinelone-detection.yaml',
      'sentinelone-custom.cfg',
      's1-exclusions.conf',
      's1-network-policy.json',
    ])('matches %s', (file) => {
      const r = scanEndpointSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'SENTINELONE_POLICY_DRIFT')).toBe(true)
    })
  })

  describe('directory-based', () => {
    it.each([
      'sentinelone/agent.yaml',
      's1/policy.conf',
      's1-agent/settings.json',
      'edr/sentinelone/config.toml',
      'sentinel-one/agent.conf',
    ])('matches %s', (file) => {
      const r = scanEndpointSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'SENTINELONE_POLICY_DRIFT')).toBe(true)
    })
  })

  it('vendor path excluded', () => {
    const r = scanEndpointSecurityDrift(['node_modules/sentinelone.conf'])
    expect(r.findings.some((f) => f.ruleId === 'SENTINELONE_POLICY_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 3: DEFENDER_ENDPOINT_DRIFT (high)
// ---------------------------------------------------------------------------

describe('DEFENDER_ENDPOINT_DRIFT', () => {
  describe('ungated exact names', () => {
    it.each([
      'mdatp-managed.json',
      'mdatp.conf',
      'mdatp-config.json',
      'wdav-config.json',
      'wdavcfg',
      'defender-atp.json',
      'defender-policy.json',
      'mde-config.json',
      'mdatp-managed.yaml',
      'defender-for-endpoint.json',
    ])('matches %s', (file) => {
      const r = scanEndpointSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'DEFENDER_ENDPOINT_DRIFT')).toBe(true)
    })
  })

  describe('prefix-ungated', () => {
    it.each([
      'mdatp-settings.yaml',
      'mdatp-custom.conf',
      'defender-exclusions.json',
      'defender-settings.yml',
      'mde-policy.conf',
    ])('matches %s', (file) => {
      const r = scanEndpointSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'DEFENDER_ENDPOINT_DRIFT')).toBe(true)
    })
  })

  describe('directory-based', () => {
    it.each([
      'mdatp/settings.conf',
      'defender/config.yaml',
      'microsoft-defender/policy.json',
      'mde/agent.conf',
      'wdav/config.toml',
    ])('matches %s', (file) => {
      const r = scanEndpointSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'DEFENDER_ENDPOINT_DRIFT')).toBe(true)
    })
  })

  it('vendor path excluded', () => {
    const r = scanEndpointSecurityDrift(['.git/mdatp-managed.json'])
    expect(r.findings.some((f) => f.ruleId === 'DEFENDER_ENDPOINT_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 4: EDR_EXCLUSION_LIST_DRIFT (high)
// ---------------------------------------------------------------------------

describe('EDR_EXCLUSION_LIST_DRIFT', () => {
  describe('ungated exact names', () => {
    it.each([
      'edr-exclusions.json',
      'av-exclusions.conf',
      'defender-exclusions.json',
      'edr-exclusions.yaml',
      'av-exclusions.json',
      'security-exclusions.json',
      'exclusion-list.json',
      'scan-exclusions.json',
      'endpoint-exclusions.yaml',
      'av-exclusions.yaml',
      'edr-exclusions.yml',
      'av-whitelist.conf',
      'antivirus-exclusions.json',
      'edr-whitelist.json',
    ])('matches %s', (file) => {
      const r = scanEndpointSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'EDR_EXCLUSION_LIST_DRIFT')).toBe(true)
    })
  })

  describe('prefix-ungated', () => {
    it.each([
      'edr-exclusion-prod.yaml',
      'av-exclusions-custom.txt',
      'defender-exclusion-servers.json',
      'endpoint-exclusions-windows.yml',
      'antivirus-exclusion-paths.conf',
    ])('matches %s', (file) => {
      const r = scanEndpointSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'EDR_EXCLUSION_LIST_DRIFT')).toBe(true)
    })
  })

  describe('directory-based', () => {
    it.each([
      'edr-exclusions/windows.json',
      'av-exclusions/linux.yaml',
      'edr-config/exclusions.conf',
      'endpoint-security/exclusions.txt',
      'exclusions/custom.json',
    ])('matches %s', (file) => {
      const r = scanEndpointSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'EDR_EXCLUSION_LIST_DRIFT')).toBe(true)
    })
  })

  it('vendor path excluded', () => {
    const r = scanEndpointSecurityDrift(['vendor/edr-exclusions.json'])
    expect(r.findings.some((f) => f.ruleId === 'EDR_EXCLUSION_LIST_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// isMdmDevicePolicyFile unit tests (exported)
// ---------------------------------------------------------------------------

describe('isMdmDevicePolicyFile', () => {
  describe('.mobileconfig extension (globally unambiguous)', () => {
    it.each([
      ['profile.mobileconfig', 'profile.mobileconfig'],
      ['wifi-policy.mobileconfig', 'wifi-policy.mobileconfig'],
      ['jamf/enrollment.mobileconfig', 'enrollment.mobileconfig'],
      ['any/path/vpn.mobileconfig', 'vpn.mobileconfig'],
    ])('%s → true', (path, base) => {
      expect(isMdmDevicePolicyFile(path, base)).toBe(true)
    })
  })

  describe('ungated exact names', () => {
    it.each([
      ['jamf.conf', 'jamf.conf'],
      ['jamf.json', 'jamf.json'],
      ['jamf-config.json', 'jamf-config.json'],
      ['intune-policy.json', 'intune-policy.json'],
      ['intune-compliance.json', 'intune-compliance.json'],
      ['intune-config.json', 'intune-config.json'],
      ['sccm-config.xml', 'sccm-config.xml'],
      ['mecm-config.xml', 'mecm-config.xml'],
    ])('%s → true', (path, base) => {
      expect(isMdmDevicePolicyFile(path, base)).toBe(true)
    })
  })

  describe('gated names — rejected at root', () => {
    it.each([
      ['enrollment.json', 'enrollment.json'],
      ['device-policy.json', 'device-policy.json'],
      ['compliance.json', 'compliance.json'],
      ['device-compliance.json', 'device-compliance.json'],
      ['enrollment.xml', 'enrollment.xml'],
    ])('%s at root → false', (path, base) => {
      expect(isMdmDevicePolicyFile(path, base)).toBe(false)
    })
  })

  describe('gated names — accepted in MDM dirs', () => {
    it.each([
      ['mdm/enrollment.json', 'enrollment.json'],
      ['jamf/device-policy.json', 'device-policy.json'],
      ['intune/compliance.json', 'compliance.json'],
      ['sccm/device-compliance.json', 'device-compliance.json'],
      ['device-management/enrollment.xml', 'enrollment.xml'],
    ])('%s → true', (path, base) => {
      expect(isMdmDevicePolicyFile(path, base)).toBe(true)
    })
  })

  describe('prefix matching', () => {
    it.each([
      ['jamf-policy.conf', 'jamf-policy.conf'],
      ['jamf-enrollment.json', 'jamf-enrollment.json'],
      ['intune-device.yaml', 'intune-device.yaml'],
      ['mdm-settings.xml', 'mdm-settings.xml'],
      ['sccm-baseline.conf', 'sccm-baseline.conf'],
      ['mecm-deployment.yaml', 'mecm-deployment.yaml'],
    ])('%s → true', (path, base) => {
      expect(isMdmDevicePolicyFile(path, base)).toBe(true)
    })

    it('mdm-settings.js does NOT match (js not in prefix allowlist)', () => {
      expect(isMdmDevicePolicyFile('mdm-settings.js', 'mdm-settings.js')).toBe(false)
    })
  })

  describe('directory-based', () => {
    it.each([
      ['jamf/settings.json', 'settings.json'],
      ['intune/config.yaml', 'config.yaml'],
      ['uem/policy.conf', 'policy.conf'],
      ['device-management/baseline.xml', 'baseline.xml'],
      ['mdm-config/enrollment.plist', 'enrollment.plist'],
    ])('%s → true', (path, base) => {
      expect(isMdmDevicePolicyFile(path, base)).toBe(true)
    })
  })
})

// ---------------------------------------------------------------------------
// Rule 5: MDM_DEVICE_POLICY_DRIFT (medium) — scanner tests
// ---------------------------------------------------------------------------

describe('MDM_DEVICE_POLICY_DRIFT', () => {
  it('matches .mobileconfig profile', () => {
    const r = scanEndpointSecurityDrift(['wifi-policy.mobileconfig'])
    expect(r.findings.some((f) => f.ruleId === 'MDM_DEVICE_POLICY_DRIFT')).toBe(true)
  })

  it('matches ungated jamf.conf', () => {
    const r = scanEndpointSecurityDrift(['jamf.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MDM_DEVICE_POLICY_DRIFT')).toBe(true)
  })

  it('matches intune-policy.json', () => {
    const r = scanEndpointSecurityDrift(['intune-policy.json'])
    expect(r.findings.some((f) => f.ruleId === 'MDM_DEVICE_POLICY_DRIFT')).toBe(true)
  })

  it('enrollment.json at root does NOT match', () => {
    const r = scanEndpointSecurityDrift(['enrollment.json'])
    expect(r.findings.some((f) => f.ruleId === 'MDM_DEVICE_POLICY_DRIFT')).toBe(false)
  })

  it('mdm/enrollment.json matches (gated by dir)', () => {
    const r = scanEndpointSecurityDrift(['mdm/enrollment.json'])
    expect(r.findings.some((f) => f.ruleId === 'MDM_DEVICE_POLICY_DRIFT')).toBe(true)
  })

  it('vendor path excluded', () => {
    const r = scanEndpointSecurityDrift(['vendor/jamf.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MDM_DEVICE_POLICY_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 6: CARBON_BLACK_SOPHOS_DRIFT (medium)
// ---------------------------------------------------------------------------

describe('CARBON_BLACK_SOPHOS_DRIFT', () => {
  describe('ungated exact names', () => {
    it.each([
      'cbagent.cfg',
      'cb.conf',
      'cbrespond.conf',
      'cbdaemon.conf',
      'carbon_black.conf',
      'carbon-black.conf',
      'cbc.conf',
      'sophos.conf',
      'savdi.conf',
      'sav-linux.conf',
      'sep.conf',
      'symantec-endpoint.conf',
    ])('matches %s', (file) => {
      const r = scanEndpointSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'CARBON_BLACK_SOPHOS_DRIFT')).toBe(true)
    })
  })

  describe('prefix-ungated', () => {
    it.each([
      'carbonblack-custom.conf',
      'cb-defense-policy.json',
      'cb-response-settings.yaml',
      'sophos-settings.conf',
      'symantec-policy.yaml',
    ])('matches %s', (file) => {
      const r = scanEndpointSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'CARBON_BLACK_SOPHOS_DRIFT')).toBe(true)
    })
  })

  describe('directory-based', () => {
    it.each([
      'carbon-black/agent.conf',
      'carbonblack/policy.yaml',
      'cb-defense/config.json',
      'sophos/savdi.conf',
      'sep/policy.xml',
    ])('matches %s', (file) => {
      const r = scanEndpointSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'CARBON_BLACK_SOPHOS_DRIFT')).toBe(true)
    })
  })

  it('vendor path excluded', () => {
    const r = scanEndpointSecurityDrift(['.venv/sophos.conf'])
    expect(r.findings.some((f) => f.ruleId === 'CARBON_BLACK_SOPHOS_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 7: VULNERABILITY_SCANNER_DRIFT (medium)
// ---------------------------------------------------------------------------

describe('VULNERABILITY_SCANNER_DRIFT', () => {
  describe('ungated exact names', () => {
    it.each([
      'nessus.conf',
      'nessud.conf',
      'nessusd.conf',
      'openvas.conf',
      'openvassd.conf',
      'gvm.conf',
      'gvmd.conf',
      'openvasmd.conf',
      'qualys-cloud-agent.conf',
      'qualys-agent.conf',
      'tenable-agent.conf',
      'tenable.conf',
      'tenablesc.conf',
      'rapid7-agent.conf',
      'nexpose.conf',
    ])('matches %s', (file) => {
      const r = scanEndpointSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'VULNERABILITY_SCANNER_DRIFT')).toBe(true)
    })
  })

  describe('prefix-ungated', () => {
    it.each([
      'nessus-custom.conf',
      'openvas-settings.yaml',
      'qualys-scanner.json',
      'tenable-agent-linux.conf',
      'rapid7-insight.yaml',
    ])('matches %s', (file) => {
      const r = scanEndpointSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'VULNERABILITY_SCANNER_DRIFT')).toBe(true)
    })
  })

  describe('directory-based', () => {
    it.each([
      'nessus/daemon.conf',
      'openvas/scanner.yaml',
      'gvm/manager.conf',
      'qualys/agent.json',
      'vulnerability-scanner/config.conf',
      'rapid7/scan-targets.xml',
    ])('matches %s', (file) => {
      const r = scanEndpointSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'VULNERABILITY_SCANNER_DRIFT')).toBe(true)
    })
  })

  it('vendor path excluded', () => {
    const r = scanEndpointSecurityDrift(['node_modules/nessus.conf'])
    expect(r.findings.some((f) => f.ruleId === 'VULNERABILITY_SCANNER_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 8: TANIUM_ENDPOINT_MGMT_DRIFT (low)
// ---------------------------------------------------------------------------

describe('TANIUM_ENDPOINT_MGMT_DRIFT', () => {
  describe('ungated exact names', () => {
    it.each([
      'tanium.conf',
      'tanium-client.conf',
      'tanium-config.json',
      'taniumclient.conf',
      'bigfix.conf',
      'bigfix-config.json',
      'besclient.conf',
      'besclient.cfg',
      'manageengine.conf',
      'me-agent.conf',
    ])('matches %s', (file) => {
      const r = scanEndpointSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'TANIUM_ENDPOINT_MGMT_DRIFT')).toBe(true)
    })
  })

  describe('prefix-ungated', () => {
    it.each([
      'tanium-settings.yaml',
      'tanium-policy.conf',
      'bigfix-patch.json',
      'manageengine-agent.yaml',
      'besclient-config.conf',
    ])('matches %s', (file) => {
      const r = scanEndpointSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'TANIUM_ENDPOINT_MGMT_DRIFT')).toBe(true)
    })
  })

  describe('directory-based', () => {
    it.each([
      'tanium/client.conf',
      'bigfix/agent.yaml',
      'manageengine/config.json',
      'endpoint-management/settings.conf',
      'ibm-bigfix/policy.xml',
    ])('matches %s', (file) => {
      const r = scanEndpointSecurityDrift([file])
      expect(r.findings.some((f) => f.ruleId === 'TANIUM_ENDPOINT_MGMT_DRIFT')).toBe(true)
    })
  })

  it('vendor path excluded', () => {
    const r = scanEndpointSecurityDrift(['build/tanium.conf'])
    expect(r.findings.some((f) => f.ruleId === 'TANIUM_ENDPOINT_MGMT_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Integration: scanner behaviour
// ---------------------------------------------------------------------------

describe('scanEndpointSecurityDrift — integration', () => {
  it('returns none risk for empty list', () => {
    const r = scanEndpointSecurityDrift([])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
    expect(r.totalFindings).toBe(0)
    expect(r.summary).toBe('No endpoint security or EDR configuration changes detected.')
  })

  it('ignores non-config paths', () => {
    const r = scanEndpointSecurityDrift([
      'src/index.ts',
      'README.md',
      'package.json',
      'Makefile',
    ])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })

  it('score 15 → riskLevel medium (15 is not < 15)', () => {
    // 1 HIGH finding = 1 × 15 = 15 → medium
    const r = scanEndpointSecurityDrift(['falcon.cfg'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('medium')
  })

  it('score 45 → riskLevel high (45 is not < 45)', () => {
    // 3 HIGH findings = min(3×15, 45) = 45 → high
    const r = scanEndpointSecurityDrift([
      'falcon.cfg',            // CROWDSTRIKE_FALCON_DRIFT
      'sentinelone.conf',      // SENTINELONE_POLICY_DRIFT
      'mdatp-managed.json',    // DEFENDER_ENDPOINT_DRIFT
    ])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('4H+3M+1L across all 8 rules → score 73 → high', () => {
    const r = scanEndpointSecurityDrift([
      // 4 HIGH rules
      'falcon.cfg',               // CROWDSTRIKE_FALCON_DRIFT
      'sentinelone.conf',         // SENTINELONE_POLICY_DRIFT
      'mdatp-managed.json',       // DEFENDER_ENDPOINT_DRIFT
      'edr-exclusions.json',      // EDR_EXCLUSION_LIST_DRIFT
      // 3 MEDIUM rules
      'jamf.conf',                // MDM_DEVICE_POLICY_DRIFT
      'sophos.conf',              // CARBON_BLACK_SOPHOS_DRIFT
      'nessus.conf',              // VULNERABILITY_SCANNER_DRIFT
      // 1 LOW rule
      'tanium.conf',              // TANIUM_ENDPOINT_MGMT_DRIFT
    ])
    // min(4×15, 45) + min(3×8, 25) + min(1×4, 15) = 45 + 24 + 4 = 73
    expect(r.riskScore).toBe(73)
    expect(r.riskLevel).toBe('high')
    expect(r.highCount).toBe(4)
    expect(r.mediumCount).toBe(3)
    expect(r.lowCount).toBe(1)
    expect(r.totalFindings).toBe(8)
  })

  it('deduplicates: multiple files for same rule → one finding', () => {
    const r = scanEndpointSecurityDrift([
      'falcon.cfg',
      'crowdstrike-config.json',
      'crowdstrike/sensor.yaml',
    ])
    const findings = r.findings.filter((f) => f.ruleId === 'CROWDSTRIKE_FALCON_DRIFT')
    expect(findings).toHaveLength(1)
    expect(findings[0].matchCount).toBe(3)
  })

  it('matchedPath is the first matching path', () => {
    const r = scanEndpointSecurityDrift([
      'falcon.cfg',
      'crowdstrike-config.json',
    ])
    const f = r.findings.find((f) => f.ruleId === 'CROWDSTRIKE_FALCON_DRIFT')!
    expect(f.matchedPath).toBe('falcon.cfg')
    expect(f.matchCount).toBe(2)
  })

  it('normalises Windows-style backslash paths', () => {
    const r = scanEndpointSecurityDrift(['.\\falcon\\sensor.conf'])
    expect(r.findings.some((f) => f.ruleId === 'CROWDSTRIKE_FALCON_DRIFT')).toBe(true)
  })

  it('summary references count and score for non-empty result', () => {
    const r = scanEndpointSecurityDrift(['falcon.cfg'])
    expect(r.summary).toContain('1 endpoint security configuration file modified')
    expect(r.summary).toContain('/100')
  })

  it('summary uses plural for multiple findings', () => {
    const r = scanEndpointSecurityDrift(['falcon.cfg', 'sophos.conf'])
    expect(r.summary).toContain('files modified')
  })

  it('all vendor dirs excluded', () => {
    const files = [
      'node_modules/falcon.cfg',
      'vendor/sentinelone.conf',
      '.git/mdatp-managed.json',
      'dist/edr-exclusions.json',
      'build/jamf.conf',
    ]
    const r = scanEndpointSecurityDrift(files)
    expect(r.riskScore).toBe(0)
    expect(r.totalFindings).toBe(0)
  })

  it('dedup-per-rule: 4 files for one HIGH rule → 1 finding, score 15', () => {
    // All 4 files trigger CROWDSTRIKE_FALCON_DRIFT — dedup produces one finding
    const r = scanEndpointSecurityDrift([
      'falcon.cfg',
      'crowdstrike.conf',
      'cs.conf',
      'falcon-prevention.json',
    ])
    expect(r.riskScore).toBe(15)
    expect(r.highCount).toBe(1)
    const f = r.findings.find((f) => f.ruleId === 'CROWDSTRIKE_FALCON_DRIFT')!
    expect(f.matchCount).toBe(4)
  })

  it('HIGH severity cap: 3 distinct HIGH rules → score capped at 45', () => {
    const r = scanEndpointSecurityDrift([
      'falcon.cfg',         // CROWDSTRIKE_FALCON_DRIFT (HIGH ×15)
      'sentinelone.conf',   // SENTINELONE_POLICY_DRIFT (HIGH ×15)
      'mdatp-managed.json', // DEFENDER_ENDPOINT_DRIFT  (HIGH ×15)
    ])
    expect(r.riskScore).toBe(45)
    expect(r.highCount).toBe(3)
  })

  it('finding contains description and recommendation fields', () => {
    const r = scanEndpointSecurityDrift(['falcon.cfg'])
    const f = r.findings[0]
    expect(f.description).toBeTruthy()
    expect(f.recommendation).toBeTruthy()
    expect(f.severity).toBe('high')
    expect(f.ruleId).toBe('CROWDSTRIKE_FALCON_DRIFT')
  })
})
