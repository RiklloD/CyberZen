/**
 * WS-48 — License Compliance & Risk Scanner: pure library tests.
 */
import { describe, expect, it } from 'vitest'
import {
  LICENSE_DATABASE,
  SPDX_ALIASES,
  computeLicenseCompliance,
} from './licenseComplianceScanner'
import type { LicenseScanInput } from './licenseComplianceScanner'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function pkg(
  name: string,
  license?: string | null,
  ecosystem = 'npm',
  version = '1.0.0',
): LicenseScanInput {
  return { name, ecosystem, version, license }
}

// ---------------------------------------------------------------------------
// LICENSE_DATABASE integrity
// ---------------------------------------------------------------------------

describe('LICENSE_DATABASE integrity', () => {
  it('has at least 60 entries', () => {
    expect(Object.keys(LICENSE_DATABASE).length).toBeGreaterThanOrEqual(60)
  })

  it('every entry has a valid licenseType', () => {
    const valid = new Set(['permissive', 'weak_copyleft', 'strong_copyleft', 'proprietary', 'unknown'])
    for (const [key, entry] of Object.entries(LICENSE_DATABASE)) {
      expect(valid.has(entry.type), `${key} has invalid type: ${entry.type}`).toBe(true)
    }
  })

  it('every entry has a valid riskLevel', () => {
    const valid = new Set(['none', 'low', 'medium', 'high', 'critical'])
    for (const [key, entry] of Object.entries(LICENSE_DATABASE)) {
      expect(valid.has(entry.riskLevel), `${key} has invalid riskLevel: ${entry.riskLevel}`).toBe(
        true,
      )
    }
  })

  it('all permissive entries have riskLevel none or low', () => {
    for (const [key, entry] of Object.entries(LICENSE_DATABASE)) {
      if (entry.type === 'permissive') {
        expect(
          ['none', 'low'].includes(entry.riskLevel),
          `permissive ${key} has unexpected riskLevel ${entry.riskLevel}`,
        ).toBe(true)
      }
    }
  })

  it('all strong_copyleft entries have riskLevel critical', () => {
    for (const [key, entry] of Object.entries(LICENSE_DATABASE)) {
      if (entry.type === 'strong_copyleft') {
        expect(entry.riskLevel, `strong_copyleft ${key}`).toBe('critical')
      }
    }
  })

  it('all weak_copyleft entries have riskLevel high', () => {
    for (const [key, entry] of Object.entries(LICENSE_DATABASE)) {
      if (entry.type === 'weak_copyleft') {
        expect(entry.riskLevel, `weak_copyleft ${key}`).toBe('high')
      }
    }
  })

  it('includes MIT, Apache-2.0, BSD-3-Clause (permissive)', () => {
    expect(LICENSE_DATABASE['MIT']?.riskLevel).toBe('none')
    expect(LICENSE_DATABASE['Apache-2.0']?.riskLevel).toBe('none')
    expect(LICENSE_DATABASE['BSD-3-Clause']?.riskLevel).toBe('none')
  })

  it('includes GPL-2.0, GPL-3.0, AGPL-3.0 (strong copyleft → critical)', () => {
    expect(LICENSE_DATABASE['GPL-2.0']?.riskLevel).toBe('critical')
    expect(LICENSE_DATABASE['GPL-3.0']?.riskLevel).toBe('critical')
    expect(LICENSE_DATABASE['AGPL-3.0']?.riskLevel).toBe('critical')
  })

  it('includes LGPL-2.1, LGPL-3.0, MPL-2.0 (weak copyleft → high)', () => {
    expect(LICENSE_DATABASE['LGPL-2.1']?.riskLevel).toBe('high')
    expect(LICENSE_DATABASE['LGPL-3.0']?.riskLevel).toBe('high')
    expect(LICENSE_DATABASE['MPL-2.0']?.riskLevel).toBe('high')
  })

  it('includes BUSL-1.1 and Elastic-2.0 (proprietary → high)', () => {
    expect(LICENSE_DATABASE['BUSL-1.1']?.riskLevel).toBe('high')
    expect(LICENSE_DATABASE['Elastic-2.0']?.riskLevel).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// SPDX_ALIASES
// ---------------------------------------------------------------------------

describe('SPDX_ALIASES', () => {
  it('maps gplv2 to GPL-2.0', () => {
    expect(SPDX_ALIASES['gplv2']).toBe('GPL-2.0')
  })

  it('maps apache 2.0 to Apache-2.0', () => {
    expect(SPDX_ALIASES['apache 2.0']).toBe('Apache-2.0')
  })

  it('all alias values are keys in LICENSE_DATABASE', () => {
    for (const [alias, target] of Object.entries(SPDX_ALIASES)) {
      expect(
        target in LICENSE_DATABASE,
        `alias "${alias}" points to "${target}" which is not in LICENSE_DATABASE`,
      ).toBe(true)
    }
  })
})

// ---------------------------------------------------------------------------
// Empty input
// ---------------------------------------------------------------------------

describe('empty component list', () => {
  const result = computeLicenseCompliance([])

  it('findings is empty', () => {
    expect(result.findings).toHaveLength(0)
  })

  it('totalScanned = 0', () => {
    expect(result.totalScanned).toBe(0)
  })

  it('all counts are 0', () => {
    expect(result.criticalCount).toBe(0)
    expect(result.highCount).toBe(0)
    expect(result.mediumCount).toBe(0)
    expect(result.lowCount).toBe(0)
  })

  it('overallRisk = none', () => {
    expect(result.overallRisk).toBe('none')
  })

  it('summary mentions no components', () => {
    expect(result.summary.toLowerCase()).toMatch(/no sbom|no .* found|skip/)
  })
})

// ---------------------------------------------------------------------------
// All-permissive input (no findings)
// ---------------------------------------------------------------------------

describe('all-permissive input (MIT, Apache-2.0, BSD-3-Clause)', () => {
  const components: LicenseScanInput[] = [
    pkg('lodash', 'MIT'),
    pkg('react', 'MIT'),
    pkg('express', 'MIT'),
    pkg('aws-sdk', 'Apache-2.0'),
    pkg('uuid', 'BSD-3-Clause'),
  ]
  const result = computeLicenseCompliance(components)

  it('findings is empty', () => {
    expect(result.findings).toHaveLength(0)
  })

  it('criticalCount = 0', () => {
    expect(result.criticalCount).toBe(0)
  })

  it('overallRisk = none', () => {
    expect(result.overallRisk).toBe('none')
  })

  it('totalScanned = 5', () => {
    expect(result.totalScanned).toBe(5)
  })

  it('unknownLicenseCount = 0', () => {
    expect(result.unknownLicenseCount).toBe(0)
  })

  it('summary says no issues found', () => {
    expect(result.summary).toMatch(/no license compliance issues|no .* issues found/i)
  })

  it('licenseBreakdown counts MIT as 3', () => {
    expect(result.licenseBreakdown['MIT']).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// Strong copyleft detection (critical)
// ---------------------------------------------------------------------------

describe('GPL-2.0 dependency', () => {
  const result = computeLicenseCompliance([pkg('linux-headers', 'GPL-2.0')])
  const finding = result.findings[0]!

  it('produces one critical finding', () => {
    expect(result.criticalCount).toBe(1)
    expect(finding.riskLevel).toBe('critical')
  })

  it('licenseType is strong_copyleft', () => {
    expect(finding.licenseType).toBe('strong_copyleft')
  })

  it('riskSignal is strong_copyleft', () => {
    expect(finding.riskSignal).toBe('strong_copyleft')
  })

  it('spdxId is GPL-2.0', () => {
    expect(finding.spdxId).toBe('GPL-2.0')
  })

  it('overallRisk is critical', () => {
    expect(result.overallRisk).toBe('critical')
  })
})

describe('GPL-3.0 dependency', () => {
  it('riskLevel is critical', () => {
    const r = computeLicenseCompliance([pkg('some-lib', 'GPL-3.0')])
    expect(r.criticalCount).toBe(1)
    expect(r.findings[0]!.riskLevel).toBe('critical')
  })
})

describe('AGPL-3.0 dependency (SaaS copyleft trap)', () => {
  const result = computeLicenseCompliance([pkg('mongodb-driver', 'AGPL-3.0')])

  it('riskLevel is critical', () => {
    expect(result.criticalCount).toBe(1)
  })

  it('licenseType is strong_copyleft', () => {
    expect(result.findings[0]!.licenseType).toBe('strong_copyleft')
  })

  it('description warns about legal review', () => {
    expect(result.findings[0]!.description).toMatch(/legal review/i)
  })
})

describe('SSPL-1.0 dependency (MongoDB original license)', () => {
  it('riskLevel is critical', () => {
    const r = computeLicenseCompliance([pkg('mongodb-server', 'SSPL-1.0')])
    expect(r.criticalCount).toBe(1)
  })
})

describe('OSL-3.0 dependency', () => {
  it('riskLevel is critical', () => {
    const r = computeLicenseCompliance([pkg('some-osl-lib', 'OSL-3.0')])
    expect(r.criticalCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// Weak copyleft detection (high)
// ---------------------------------------------------------------------------

describe('LGPL-2.1 dependency', () => {
  const result = computeLicenseCompliance([pkg('glib', 'LGPL-2.1')])
  const finding = result.findings[0]!

  it('produces one high finding', () => {
    expect(result.highCount).toBe(1)
    expect(finding.riskLevel).toBe('high')
  })

  it('licenseType is weak_copyleft', () => {
    expect(finding.licenseType).toBe('weak_copyleft')
  })

  it('riskSignal is weak_copyleft', () => {
    expect(finding.riskSignal).toBe('weak_copyleft')
  })
})

describe('MPL-2.0 dependency', () => {
  it('riskLevel is high, licenseType is weak_copyleft', () => {
    const r = computeLicenseCompliance([pkg('firefox-lib', 'MPL-2.0')])
    expect(r.highCount).toBe(1)
    expect(r.findings[0]!.licenseType).toBe('weak_copyleft')
  })
})

describe('EPL-2.0 dependency', () => {
  it('riskLevel is high', () => {
    const r = computeLicenseCompliance([pkg('eclipse-core', 'EPL-2.0')])
    expect(r.highCount).toBe(1)
  })
})

describe('LGPL-3.0-or-later', () => {
  it('riskLevel is high (LGPL variant)', () => {
    const r = computeLicenseCompliance([pkg('qtlib', 'LGPL-3.0-or-later')])
    expect(r.highCount).toBe(1)
    expect(r.findings[0]!.spdxId).toBe('LGPL-3.0-or-later')
  })
})

// ---------------------------------------------------------------------------
// Proprietary / restricted
// ---------------------------------------------------------------------------

describe('BUSL-1.1 dependency (HashiCorp, Terraform etc)', () => {
  const result = computeLicenseCompliance([pkg('vault-sdk', 'BUSL-1.1')])
  const finding = result.findings[0]!

  it('produces one high finding', () => {
    expect(result.highCount).toBe(1)
    expect(finding.riskLevel).toBe('high')
  })

  it('licenseType is proprietary', () => {
    expect(finding.licenseType).toBe('proprietary')
  })

  it('riskSignal is proprietary_restricted', () => {
    expect(finding.riskSignal).toBe('proprietary_restricted')
  })
})

describe('Elastic-2.0 dependency', () => {
  it('riskLevel is high, licenseType is proprietary', () => {
    const r = computeLicenseCompliance([pkg('elasticsearch', 'Elastic-2.0')])
    expect(r.highCount).toBe(1)
    expect(r.findings[0]!.licenseType).toBe('proprietary')
  })
})

// ---------------------------------------------------------------------------
// Unknown / missing license
// ---------------------------------------------------------------------------

describe('component with no license (null)', () => {
  const result = computeLicenseCompliance([pkg('mystery-pkg', null)])
  const finding = result.findings[0]!

  it('produces one medium finding', () => {
    expect(result.mediumCount).toBe(1)
    expect(finding.riskLevel).toBe('medium')
  })

  it('riskSignal is unknown_license', () => {
    expect(finding.riskSignal).toBe('unknown_license')
  })

  it('spdxId is unknown', () => {
    expect(finding.spdxId).toBe('unknown')
  })

  it('unknownLicenseCount = 1', () => {
    expect(result.unknownLicenseCount).toBe(1)
  })
})

describe('component with empty string license', () => {
  const result = computeLicenseCompliance([pkg('mystery-pkg', '')])

  it('treated as missing license (medium risk)', () => {
    expect(result.mediumCount).toBe(1)
    expect(result.findings[0]!.riskSignal).toBe('unknown_license')
  })
})

describe('component with unrecognised custom license string', () => {
  const result = computeLicenseCompliance([pkg('bespoke-lib', 'Custom Corporate License v1')])
  const finding = result.findings[0]!

  it('produces one medium finding', () => {
    expect(result.mediumCount).toBe(1)
    expect(finding.riskLevel).toBe('medium')
  })

  it('riskSignal is unrecognized_license', () => {
    expect(finding.riskSignal).toBe('unrecognized_license')
  })

  it('unknownLicenseCount = 1', () => {
    expect(result.unknownLicenseCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// Multi-license expressions
// ---------------------------------------------------------------------------

describe('compound license expressions', () => {
  it('"MIT AND Apache-2.0" → overallRisk none (both permissive)', () => {
    const r = computeLicenseCompliance([pkg('dual-permissive', 'MIT AND Apache-2.0')])
    expect(r.overallRisk).toBe('none')
    expect(r.findings).toHaveLength(0)
  })

  it('"MIT AND GPL-3.0" → critical (worst wins)', () => {
    const r = computeLicenseCompliance([pkg('mixed-lib', 'MIT AND GPL-3.0')])
    expect(r.criticalCount).toBe(1)
    expect(r.overallRisk).toBe('critical')
  })

  it('"MIT OR GPL-3.0" → critical (conservative: worst wins)', () => {
    const r = computeLicenseCompliance([pkg('choice-lib', 'MIT OR GPL-3.0')])
    expect(r.criticalCount).toBe(1)
  })

  it('"Apache-2.0 WITH LLVM-exception" → treated as Apache-2.0 (permissive)', () => {
    const r = computeLicenseCompliance([pkg('llvm-lib', 'Apache-2.0 WITH LLVM-exception')])
    expect(r.overallRisk).toBe('none')
    expect(r.findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Case insensitivity
// ---------------------------------------------------------------------------

describe('case-insensitive matching', () => {
  it('"gpl-3.0" (lowercase) → critical', () => {
    const r = computeLicenseCompliance([pkg('case-test', 'gpl-3.0')])
    expect(r.criticalCount).toBe(1)
  })

  it('"mit" (lowercase) → permissive, no finding', () => {
    const r = computeLicenseCompliance([pkg('case-test', 'mit')])
    expect(r.findings).toHaveLength(0)
  })

  it('"Apache-2.0" (exact case) → permissive', () => {
    const r = computeLicenseCompliance([pkg('case-test', 'Apache-2.0')])
    expect(r.findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Alias resolution
// ---------------------------------------------------------------------------

describe('SPDX alias resolution', () => {
  it('"GPLv2" → GPL-2.0 → critical', () => {
    const r = computeLicenseCompliance([pkg('alias-test', 'GPLv2')])
    expect(r.criticalCount).toBe(1)
    expect(r.findings[0]!.spdxId).toBe('GPL-2.0')
  })

  it('"GPLv3" → GPL-3.0 → critical', () => {
    const r = computeLicenseCompliance([pkg('alias-test', 'GPLv3')])
    expect(r.criticalCount).toBe(1)
  })

  it('"MIT License" → MIT → permissive', () => {
    const r = computeLicenseCompliance([pkg('alias-test', 'MIT License')])
    expect(r.findings).toHaveLength(0)
  })

  it('"Apache 2.0" → Apache-2.0 → permissive', () => {
    const r = computeLicenseCompliance([pkg('alias-test', 'Apache 2.0')])
    expect(r.findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Sorting
// ---------------------------------------------------------------------------

describe('findings sorted by severity (critical → high → medium → low)', () => {
  const components: LicenseScanInput[] = [
    pkg('medium-pkg', null),                // medium (unknown_license)
    pkg('lgpl-pkg', 'LGPL-2.1'),           // high
    pkg('gpl-pkg', 'GPL-3.0'),             // critical
    pkg('deprecated-pkg', 'Apache-1.1'),   // low
  ]
  const result = computeLicenseCompliance(components)

  it('first finding is critical', () => {
    expect(result.findings[0]!.riskLevel).toBe('critical')
  })

  it('second finding is high', () => {
    expect(result.findings[1]!.riskLevel).toBe('high')
  })

  it('third finding is medium', () => {
    expect(result.findings[2]!.riskLevel).toBe('medium')
  })

  it('fourth finding is low', () => {
    expect(result.findings[3]!.riskLevel).toBe('low')
  })
})

// ---------------------------------------------------------------------------
// Aggregate counts
// ---------------------------------------------------------------------------

describe('aggregate counts (mixed input)', () => {
  const components: LicenseScanInput[] = [
    pkg('gpl-a', 'GPL-3.0'),          // critical
    pkg('gpl-b', 'AGPL-3.0'),         // critical
    pkg('lgpl-a', 'LGPL-2.1'),        // high
    pkg('mpl-a', 'MPL-2.0'),          // high
    pkg('unknown-a', null),            // medium (unknown)
    pkg('custom-a', 'Proprietary v2'), // medium (unrecognized)
    pkg('apache-a', 'Apache-1.1'),     // low
    pkg('mit-a', 'MIT'),               // none (no finding)
  ]
  const result = computeLicenseCompliance(components)

  it('criticalCount = 2', () => {
    expect(result.criticalCount).toBe(2)
  })

  it('highCount = 2', () => {
    expect(result.highCount).toBe(2)
  })

  it('mediumCount = 2', () => {
    expect(result.mediumCount).toBe(2)
  })

  it('lowCount = 1', () => {
    expect(result.lowCount).toBe(1)
  })

  it('totalScanned = 8', () => {
    expect(result.totalScanned).toBe(8)
  })

  it('unknownLicenseCount = 2', () => {
    expect(result.unknownLicenseCount).toBe(2)
  })

  it('overallRisk = critical', () => {
    expect(result.overallRisk).toBe('critical')
  })

  it('totalActions = sum of all counts (7 findings)', () => {
    expect(result.findings).toHaveLength(7)
  })
})

// ---------------------------------------------------------------------------
// licenseBreakdown
// ---------------------------------------------------------------------------

describe('licenseBreakdown', () => {
  it('counts MIT packages correctly', () => {
    const r = computeLicenseCompliance([pkg('a', 'MIT'), pkg('b', 'MIT'), pkg('c', 'Apache-2.0')])
    expect(r.licenseBreakdown['MIT']).toBe(2)
    expect(r.licenseBreakdown['Apache-2.0']).toBe(1)
  })

  it('groups unknown licenses under "unknown"', () => {
    const r = computeLicenseCompliance([pkg('a', null), pkg('b', ''), pkg('c', 'Weird License')])
    expect(r.licenseBreakdown['unknown']).toBeGreaterThanOrEqual(2)
  })

  it('maps GPL-3.0 packages to spdxId GPL-3.0', () => {
    const r = computeLicenseCompliance([pkg('a', 'GPL-3.0'), pkg('b', 'MIT')])
    expect(r.licenseBreakdown['GPL-3.0']).toBe(1)
    expect(r.licenseBreakdown['MIT']).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// overallRisk
// ---------------------------------------------------------------------------

describe('overallRisk escalation', () => {
  it('no findings → none', () => {
    const r = computeLicenseCompliance([pkg('a', 'MIT')])
    expect(r.overallRisk).toBe('none')
  })

  it('only low → low', () => {
    const r = computeLicenseCompliance([pkg('a', 'Apache-1.1')])
    expect(r.overallRisk).toBe('low')
  })

  it('medium + low → medium', () => {
    const r = computeLicenseCompliance([pkg('a', null), pkg('b', 'Apache-1.1')])
    expect(r.overallRisk).toBe('medium')
  })

  it('high + medium → high', () => {
    const r = computeLicenseCompliance([pkg('a', 'LGPL-2.1'), pkg('b', null)])
    expect(r.overallRisk).toBe('high')
  })

  it('critical + high + medium → critical', () => {
    const r = computeLicenseCompliance([
      pkg('a', 'GPL-3.0'),
      pkg('b', 'LGPL-2.1'),
      pkg('c', null),
    ])
    expect(r.overallRisk).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// Summary text
// ---------------------------------------------------------------------------

describe('summary text', () => {
  it('clean → mentions permissive and no issues', () => {
    const r = computeLicenseCompliance([pkg('a', 'MIT'), pkg('b', 'ISC')])
    expect(r.summary).toMatch(/permissive|no license compliance/i)
  })

  it('critical → mentions critical and copyleft', () => {
    const r = computeLicenseCompliance([pkg('a', 'GPL-3.0')])
    expect(r.summary).toMatch(/critical/i)
    expect(r.summary).toMatch(/copyleft|legal review/i)
  })

  it('high only → mentions high', () => {
    const r = computeLicenseCompliance([pkg('a', 'LGPL-3.0')])
    expect(r.summary).toMatch(/high/i)
  })

  it('unknown licenses only (no other risk) → mentions unknown license', () => {
    const r = computeLicenseCompliance([pkg('a', null), pkg('b', 'MIT')])
    expect(r.summary).toMatch(/no declared license|unknown/i)
  })

  it('mixed → mentions total scanned count', () => {
    const r = computeLicenseCompliance([
      pkg('a', 'GPL-3.0'),
      pkg('b', 'LGPL-2.1'),
      pkg('c', 'MIT'),
    ])
    expect(r.summary).toMatch(/3/)
  })
})

// ---------------------------------------------------------------------------
// packageName / ecosystem / version propagated to findings
// ---------------------------------------------------------------------------

describe('finding metadata propagation', () => {
  it('packageName, ecosystem, version are preserved in findings', () => {
    const r = computeLicenseCompliance([
      { name: 'leftpad', ecosystem: 'npm', version: '2.3.0', license: 'GPL-3.0' },
    ])
    const f = r.findings[0]!
    expect(f.packageName).toBe('leftpad')
    expect(f.ecosystem).toBe('npm')
    expect(f.version).toBe('2.3.0')
  })
})
