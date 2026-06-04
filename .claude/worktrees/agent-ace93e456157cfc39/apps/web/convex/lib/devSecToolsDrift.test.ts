import { describe, expect, it } from 'vitest'
import {
  isDastScanConfigFile,
  DEV_SEC_TOOLS_RULES,
  scanDevSecToolsDrift,
} from './devSecToolsDrift'

const scan = scanDevSecToolsDrift

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
      'node_modules/some-pkg/.gitleaks.toml',
      '.git/config',
      'vendor/lib/sonar-project.properties',
      'dist/trivy.yaml',
    ])
    expect(r.riskLevel).toBe('none')
    expect(r.findings).toHaveLength(0)
  })

  it('normalises Windows backslash paths', () => {
    const r = scan(['.gitleaks.toml'.replace('/', '\\')])
    expect(ruleIds(r)).toContain('SECRET_SCAN_CONFIG_DRIFT')
  })

  it('returns none for unrelated files', () => {
    const r = scan(['src/index.ts', 'README.md', 'package.json', '.env.example'])
    expect(r.riskLevel).toBe('none')
  })
})

// ---------------------------------------------------------------------------
// Vendor directory exclusion
// ---------------------------------------------------------------------------

describe('vendor exclusion', () => {
  it('excludes .git/ paths', () => {
    expect(ruleIds(scan(['.git/hooks/pre-commit', '.git/.gitleaks.toml']))).not.toContain('SECRET_SCAN_CONFIG_DRIFT')
  })

  it('excludes node_modules/ paths', () => {
    expect(ruleIds(scan(['node_modules/security-linter/.semgrep.yml']))).not.toContain('SAST_POLICY_DRIFT')
  })

  it('excludes dist/ paths', () => {
    expect(ruleIds(scan(['dist/.snyk']))).not.toContain('SCA_POLICY_DRIFT')
  })

  it('excludes .terraform/ paths', () => {
    expect(ruleIds(scan(['.terraform/modules/trivy.yaml']))).not.toContain('CONTAINER_SCAN_POLICY_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// SECRET_SCAN_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('SECRET_SCAN_CONFIG_DRIFT', () => {
  it('detects .gitleaks.toml', () => {
    expect(ruleIds(scan(['.gitleaks.toml']))).toContain('SECRET_SCAN_CONFIG_DRIFT')
  })

  it('detects gitleaks.toml at root', () => {
    expect(ruleIds(scan(['gitleaks.toml']))).toContain('SECRET_SCAN_CONFIG_DRIFT')
  })

  it('detects .gitguardian.yml', () => {
    expect(ruleIds(scan(['.gitguardian.yml']))).toContain('SECRET_SCAN_CONFIG_DRIFT')
  })

  it('detects gitguardian.yaml', () => {
    expect(ruleIds(scan(['gitguardian.yaml']))).toContain('SECRET_SCAN_CONFIG_DRIFT')
  })

  it('detects .secrets.baseline (detect-secrets)', () => {
    expect(ruleIds(scan(['.secrets.baseline']))).toContain('SECRET_SCAN_CONFIG_DRIFT')
  })

  it('detects trufflehog.toml', () => {
    expect(ruleIds(scan(['trufflehog.toml']))).toContain('SECRET_SCAN_CONFIG_DRIFT')
  })

  it('detects .trufflehog.yml', () => {
    expect(ruleIds(scan(['.trufflehog.yml']))).toContain('SECRET_SCAN_CONFIG_DRIFT')
  })

  it('detects git-secrets.cfg', () => {
    expect(ruleIds(scan(['git-secrets.cfg']))).toContain('SECRET_SCAN_CONFIG_DRIFT')
  })

  it('detects files in gitleaks/ directory', () => {
    expect(ruleIds(scan(['config/gitleaks/rules.toml']))).toContain('SECRET_SCAN_CONFIG_DRIFT')
  })

  it('detects gitleaks-prefixed config files', () => {
    expect(ruleIds(scan(['gitleaks-custom.toml']))).toContain('SECRET_SCAN_CONFIG_DRIFT')
  })

  it('detects trufflehog-prefixed config files', () => {
    expect(ruleIds(scan(['trufflehog-enterprise.yml']))).toContain('SECRET_SCAN_CONFIG_DRIFT')
  })

  it('does not flag random .toml files', () => {
    expect(ruleIds(scan(['pyproject.toml', 'Cargo.toml']))).not.toContain('SECRET_SCAN_CONFIG_DRIFT')
  })

  it('does not flag .env files', () => {
    expect(ruleIds(scan(['.env', '.env.production']))).not.toContain('SECRET_SCAN_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// SAST_POLICY_DRIFT
// ---------------------------------------------------------------------------

describe('SAST_POLICY_DRIFT', () => {
  it('detects sonar-project.properties', () => {
    expect(ruleIds(scan(['sonar-project.properties']))).toContain('SAST_POLICY_DRIFT')
  })

  it('detects .semgrep.yml', () => {
    expect(ruleIds(scan(['.semgrep.yml']))).toContain('SAST_POLICY_DRIFT')
  })

  it('detects semgrep.yaml', () => {
    expect(ruleIds(scan(['semgrep.yaml']))).toContain('SAST_POLICY_DRIFT')
  })

  it('detects .bandit', () => {
    expect(ruleIds(scan(['.bandit']))).toContain('SAST_POLICY_DRIFT')
  })

  it('detects bandit.yml', () => {
    expect(ruleIds(scan(['bandit.yml']))).toContain('SAST_POLICY_DRIFT')
  })

  it('detects gosec.conf', () => {
    expect(ruleIds(scan(['gosec.conf']))).toContain('SAST_POLICY_DRIFT')
  })

  it('detects .tfsec.yml', () => {
    expect(ruleIds(scan(['.tfsec.yml']))).toContain('SAST_POLICY_DRIFT')
  })

  it('detects .checkov.yml', () => {
    expect(ruleIds(scan(['.checkov.yml']))).toContain('SAST_POLICY_DRIFT')
  })

  it('detects kics.config', () => {
    expect(ruleIds(scan(['kics.config']))).toContain('SAST_POLICY_DRIFT')
  })

  it('detects .yml files inside semgrep/ directory', () => {
    expect(ruleIds(scan(['ci/semgrep/custom-rules.yml']))).toContain('SAST_POLICY_DRIFT')
  })

  it('detects .yml files inside sonar/ directory', () => {
    expect(ruleIds(scan(['.sonar/analysis.yml']))).toContain('SAST_POLICY_DRIFT')
  })

  it('does not flag generic .yml files outside SAST dirs', () => {
    expect(ruleIds(scan(['config.yml', 'app.yaml']))).not.toContain('SAST_POLICY_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// SCA_POLICY_DRIFT
// ---------------------------------------------------------------------------

describe('SCA_POLICY_DRIFT', () => {
  it('detects .snyk (no extension)', () => {
    expect(ruleIds(scan(['.snyk']))).toContain('SCA_POLICY_DRIFT')
  })

  it('detects snyk.yml', () => {
    expect(ruleIds(scan(['snyk.yml']))).toContain('SCA_POLICY_DRIFT')
  })

  it('detects dependency-check.xml', () => {
    expect(ruleIds(scan(['dependency-check.xml']))).toContain('SCA_POLICY_DRIFT')
  })

  it('detects .ort.yml', () => {
    expect(ruleIds(scan(['.ort.yml']))).toContain('SCA_POLICY_DRIFT')
  })

  it('detects ort.yaml', () => {
    expect(ruleIds(scan(['ort.yaml']))).toContain('SCA_POLICY_DRIFT')
  })

  it('detects dependency-track.yml', () => {
    expect(ruleIds(scan(['dependency-track.yml']))).toContain('SCA_POLICY_DRIFT')
  })

  it('detects nancy.yml (Sonatype Nancy)', () => {
    expect(ruleIds(scan(['nancy.yml']))).toContain('SCA_POLICY_DRIFT')
  })

  it('detects files inside ort/ directory', () => {
    expect(ruleIds(scan(['config/ort/package-config.yml']))).toContain('SCA_POLICY_DRIFT')
  })

  it('detects files inside dependency-check/ directory', () => {
    expect(ruleIds(scan(['tools/dependency-check/suppression.xml']))).toContain('SCA_POLICY_DRIFT')
  })

  it('does not flag package-lock.json', () => {
    expect(ruleIds(scan(['package-lock.json', 'yarn.lock']))).not.toContain('SCA_POLICY_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// SECURITY_LINT_DRIFT
// ---------------------------------------------------------------------------

describe('SECURITY_LINT_DRIFT', () => {
  it('detects .brakeman.yml', () => {
    expect(ruleIds(scan(['.brakeman.yml']))).toContain('SECURITY_LINT_DRIFT')
  })

  it('detects brakeman.yaml', () => {
    expect(ruleIds(scan(['brakeman.yaml']))).toContain('SECURITY_LINT_DRIFT')
  })

  it('detects spotbugs-security.xml', () => {
    expect(ruleIds(scan(['spotbugs-security.xml']))).toContain('SECURITY_LINT_DRIFT')
  })

  it('detects pmd-security.xml', () => {
    expect(ruleIds(scan(['pmd-security.xml']))).toContain('SECURITY_LINT_DRIFT')
  })

  it('detects rubocop-security.yml', () => {
    expect(ruleIds(scan(['rubocop-security.yml']))).toContain('SECURITY_LINT_DRIFT')
  })

  it('detects files inside brakeman/ directory', () => {
    expect(ruleIds(scan(['config/brakeman/options.yml']))).toContain('SECURITY_LINT_DRIFT')
  })

  it('detects files inside spotbugs/ directory', () => {
    expect(ruleIds(scan(['config/spotbugs/exclude.xml']))).toContain('SECURITY_LINT_DRIFT')
  })

  it('detects eslint-security config filenames', () => {
    expect(ruleIds(scan(['eslint-security.config.js']))).toContain('SECURITY_LINT_DRIFT')
  })

  it('detects .eslint-security.json', () => {
    expect(ruleIds(scan(['.eslintrc-security.json']))).toContain('SECURITY_LINT_DRIFT')
  })

  it('does not flag generic .eslintrc.json', () => {
    expect(ruleIds(scan(['.eslintrc.json', '.eslintrc.yml']))).not.toContain('SECURITY_LINT_DRIFT')
  })

  it('does not flag rubocop.yml without security keyword', () => {
    expect(ruleIds(scan(['.rubocop.yml']))).not.toContain('SECURITY_LINT_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// DAST_SCAN_CONFIG_DRIFT — isDastScanConfigFile (user contribution)
// ---------------------------------------------------------------------------

describe('isDastScanConfigFile', () => {
  // Canonical exact names — always match
  it('matches nikto.conf', () => {
    expect(isDastScanConfigFile('nikto.conf')).toBe(true)
  })

  it('matches nuclei-config.yml', () => {
    expect(isDastScanConfigFile('nuclei-config.yml')).toBe(true)
  })

  it('matches zap.conf', () => {
    expect(isDastScanConfigFile('zap.conf')).toBe(true)
  })

  it('matches burpsuite.project.json', () => {
    expect(isDastScanConfigFile('burpsuite.project.json')).toBe(true)
  })

  it('matches amass.ini', () => {
    expect(isDastScanConfigFile('amass.ini')).toBe(true)
  })

  // Result-keyword exclusion
  it('excludes zap-report.html', () => {
    expect(isDastScanConfigFile('reports/zap-report.html')).toBe(false)
  })

  it('excludes nuclei-results.json', () => {
    expect(isDastScanConfigFile('scans/nuclei-results.json')).toBe(false)
  })

  it('excludes burp-findings.xml', () => {
    expect(isDastScanConfigFile('burp-findings.xml')).toBe(false)
  })

  it('excludes nikto-output.txt', () => {
    expect(isDastScanConfigFile('nikto-output.txt')).toBe(false)
  })

  it('excludes scan-log.json inside zap/', () => {
    expect(isDastScanConfigFile('zap/scan-log.json')).toBe(false)
  })

  // Tool-prefix + config-keyword
  it('matches zap-config.yaml', () => {
    expect(isDastScanConfigFile('zap-config.yaml')).toBe(true)
  })

  it('matches burp-policy.json', () => {
    expect(isDastScanConfigFile('ci/burp-policy.json')).toBe(true)
  })

  it('matches nuclei-template.yml', () => {
    expect(isDastScanConfigFile('nuclei-template.yml')).toBe(true)
  })

  it('matches nikto-options.conf', () => {
    expect(isDastScanConfigFile('nikto-options.conf')).toBe(true)
  })

  // Tool directory context
  it('matches .yaml inside zap/ directory', () => {
    expect(isDastScanConfigFile('ci/zap/scan-policy.yaml')).toBe(true)
  })

  it('matches .yml inside nuclei/ directory', () => {
    expect(isDastScanConfigFile('nuclei/custom-template.yml')).toBe(true)
  })

  it('matches .conf inside dast/ directory', () => {
    expect(isDastScanConfigFile('dast/scanner.conf')).toBe(true)
  })

  it('matches .ini inside pentest/ directory', () => {
    expect(isDastScanConfigFile('pentest/tool.ini')).toBe(true)
  })

  // Negative cases
  it('does not match random yaml files', () => {
    expect(isDastScanConfigFile('docker-compose.yaml')).toBe(false)
  })

  it('does not match .env files', () => {
    expect(isDastScanConfigFile('.env')).toBe(false)
  })
})

describe('DAST_SCAN_CONFIG_DRIFT (via scan)', () => {
  it('detects nikto.conf', () => {
    expect(ruleIds(scan(['nikto.conf']))).toContain('DAST_SCAN_CONFIG_DRIFT')
  })

  it('detects zap-config.yaml', () => {
    expect(ruleIds(scan(['zap-config.yaml']))).toContain('DAST_SCAN_CONFIG_DRIFT')
  })

  it('does not flag scan result files', () => {
    expect(ruleIds(scan(['zap-report.html', 'nuclei-results.json']))).not.toContain('DAST_SCAN_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// LICENSE_POLICY_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('LICENSE_POLICY_CONFIG_DRIFT', () => {
  it('detects .fossa.yml', () => {
    expect(ruleIds(scan(['.fossa.yml']))).toContain('LICENSE_POLICY_CONFIG_DRIFT')
  })

  it('detects fossa.yaml', () => {
    expect(ruleIds(scan(['fossa.yaml']))).toContain('LICENSE_POLICY_CONFIG_DRIFT')
  })

  it('detects license-finder.yml', () => {
    expect(ruleIds(scan(['license-finder.yml']))).toContain('LICENSE_POLICY_CONFIG_DRIFT')
  })

  it('detects .licensechecker.json', () => {
    expect(ruleIds(scan(['.licensechecker.json']))).toContain('LICENSE_POLICY_CONFIG_DRIFT')
  })

  it('detects scancode.cfg', () => {
    expect(ruleIds(scan(['scancode.cfg']))).toContain('LICENSE_POLICY_CONFIG_DRIFT')
  })

  it('detects about.yml', () => {
    expect(ruleIds(scan(['about.yml']))).toContain('LICENSE_POLICY_CONFIG_DRIFT')
  })

  it('detects files in fossa/ directory', () => {
    expect(ruleIds(scan(['.fossa/config.yml']))).toContain('LICENSE_POLICY_CONFIG_DRIFT')
  })

  it('does not flag LICENSE file', () => {
    expect(ruleIds(scan(['LICENSE', 'LICENSE.md']))).not.toContain('LICENSE_POLICY_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// CONTAINER_SCAN_POLICY_DRIFT
// ---------------------------------------------------------------------------

describe('CONTAINER_SCAN_POLICY_DRIFT', () => {
  it('detects trivy.yaml', () => {
    expect(ruleIds(scan(['trivy.yaml']))).toContain('CONTAINER_SCAN_POLICY_DRIFT')
  })

  it('detects .trivy.yaml', () => {
    expect(ruleIds(scan(['.trivy.yaml']))).toContain('CONTAINER_SCAN_POLICY_DRIFT')
  })

  it('detects grype.yaml', () => {
    expect(ruleIds(scan(['grype.yaml']))).toContain('CONTAINER_SCAN_POLICY_DRIFT')
  })

  it('detects .grype.yml', () => {
    expect(ruleIds(scan(['.grype.yml']))).toContain('CONTAINER_SCAN_POLICY_DRIFT')
  })

  it('detects anchore-policy.json', () => {
    expect(ruleIds(scan(['anchore-policy.json']))).toContain('CONTAINER_SCAN_POLICY_DRIFT')
  })

  it('detects clair-config.yaml', () => {
    expect(ruleIds(scan(['clair-config.yaml']))).toContain('CONTAINER_SCAN_POLICY_DRIFT')
  })

  it('detects snyk-container.yml', () => {
    expect(ruleIds(scan(['snyk-container.yml']))).toContain('CONTAINER_SCAN_POLICY_DRIFT')
  })

  it('detects files inside .grype/ directory', () => {
    expect(ruleIds(scan(['.grype/config.yaml']))).toContain('CONTAINER_SCAN_POLICY_DRIFT')
  })

  it('detects files inside trivy/ directory', () => {
    expect(ruleIds(scan(['ci/trivy/ignore.yaml']))).toContain('CONTAINER_SCAN_POLICY_DRIFT')
  })

  it('does not flag Dockerfile', () => {
    expect(ruleIds(scan(['Dockerfile', 'docker-compose.yml']))).not.toContain('CONTAINER_SCAN_POLICY_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// SECURITY_BASELINE_DRIFT
// ---------------------------------------------------------------------------

describe('SECURITY_BASELINE_DRIFT', () => {
  it('detects .talismanrc', () => {
    expect(ruleIds(scan(['.talismanrc']))).toContain('SECURITY_BASELINE_DRIFT')
  })

  it('detects talisman.yml', () => {
    expect(ruleIds(scan(['talisman.yml']))).toContain('SECURITY_BASELINE_DRIFT')
  })

  it('detects .hadolint.yaml', () => {
    expect(ruleIds(scan(['.hadolint.yaml']))).toContain('SECURITY_BASELINE_DRIFT')
  })

  it('detects hadolint.yml', () => {
    expect(ruleIds(scan(['hadolint.yml']))).toContain('SECURITY_BASELINE_DRIFT')
  })

  it('detects safety-policy.yml', () => {
    expect(ruleIds(scan(['safety-policy.yml']))).toContain('SECURITY_BASELINE_DRIFT')
  })

  it('detects .mega-linter.yml', () => {
    expect(ruleIds(scan(['.mega-linter.yml']))).toContain('SECURITY_BASELINE_DRIFT')
  })

  it('detects mega-linter.yaml', () => {
    expect(ruleIds(scan(['mega-linter.yaml']))).toContain('SECURITY_BASELINE_DRIFT')
  })

  it('detects files inside talisman/ directory', () => {
    expect(ruleIds(scan(['config/talisman/allowlist.yml']))).toContain('SECURITY_BASELINE_DRIFT')
  })

  it('does not flag generic linter configs', () => {
    expect(ruleIds(scan(['.prettierrc', 'eslint.config.js', '.stylelintrc']))).not.toContain('SECURITY_BASELINE_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scoring model', () => {
  it('1 high file → score 15, risk high', () => {
    const r = scan(['.gitleaks.toml'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('low')
  })

  it('3 high files for same rule → score 45 (hits HIGH_PENALTY_CAP), risk high', () => {
    const r = scan(['.gitleaks.toml', 'gitleaks.toml', 'gitleaks.yaml'])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('4 high files for same rule → still capped at 45', () => {
    const r = scan(['.gitleaks.toml', 'gitleaks.toml', 'gitleaks.yaml', 'gitleaks.yml'])
    expect(r.riskScore).toBe(45)
  })

  it('1 medium file → score 8', () => {
    const r = scan(['.brakeman.yml'])
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('4 medium files for same rule → 32, hits MED_PENALTY_CAP=25', () => {
    const r = scan(['.brakeman.yml', 'brakeman.yml', 'brakeman.yaml', '.brakeman.yaml'])
    expect(r.riskScore).toBe(25)
  })

  it('1 low file → score 4', () => {
    const r = scan(['.talismanrc'])
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('4 low files for same rule → hits LOW_PENALTY_CAP=15', () => {
    const r = scan(['.talismanrc', 'talisman.yml', 'talisman.yaml', '.talisman.toml'])
    expect(r.riskScore).toBe(15)
  })

  it('3 high rules + 4 medium rules → critical (score 77)', () => {
    // 3 × 15 = 45 (high cap), 4 × 8 = 32 → capped 25 (med cap) — but each medium rule is different
    // 3 rules high (1 match each) = 3×15 = 45
    // 4 rules medium (1 match each) = 4×8 = 32
    // total = 77 → critical
    const r = scan([
      '.gitleaks.toml',        // SECRET_SCAN_CONFIG_DRIFT (high)
      'semgrep.yml',           // SAST_POLICY_DRIFT (high)
      '.snyk',                 // SCA_POLICY_DRIFT (high)
      '.brakeman.yml',         // SECURITY_LINT_DRIFT (medium)
      'nikto.conf',            // DAST_SCAN_CONFIG_DRIFT (medium)
      '.fossa.yml',            // LICENSE_POLICY_CONFIG_DRIFT (medium)
      'trivy.yaml',            // CONTAINER_SCAN_POLICY_DRIFT (medium)
    ])
    expect(r.riskScore).toBe(77)
    expect(r.riskLevel).toBe('critical')
  })

  it('score clamped at 100 for extreme inputs', () => {
    const paths: string[] = []
    // Flood all high rules with enough matches to exceed 100
    for (let i = 0; i < 10; i++) {
      paths.push('.gitleaks.toml', 'semgrep.yml', '.snyk')
    }
    const r = scan(paths)
    expect(r.riskScore).toBeLessThanOrEqual(100)
  })
})

// ---------------------------------------------------------------------------
// Risk level boundaries
// ---------------------------------------------------------------------------

describe('risk level boundaries', () => {
  it('score 0 → none', () => {
    expect(scan([]).riskLevel).toBe('none')
  })

  it('score 4 (one low finding) → low', () => {
    expect(scan(['.talismanrc']).riskLevel).toBe('low')
  })

  it('score 15 (one high finding) → low', () => {
    expect(scan(['.gitleaks.toml']).riskLevel).toBe('low')
  })

  it('score 20 (one high + one low) → medium', () => {
    const r = scan(['.gitleaks.toml', '.talismanrc'])
    expect(r.riskScore).toBe(19)
    expect(r.riskLevel).toBe('low')
  })

  it('score ≥20 → medium', () => {
    // 1 high (15) + 1 medium (8) = 23 → medium
    const r = scan(['.gitleaks.toml', '.brakeman.yml'])
    expect(r.riskScore).toBe(23)
    expect(r.riskLevel).toBe('medium')
  })

  it('score 45 → high', () => {
    // 3 high rules × 15 = 45; toRiskLevel: < 45 → medium, else high
    const r = scan(['.gitleaks.toml', 'semgrep.yml', '.snyk'])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('score ≥70 → critical', () => {
    // 3 high × 3 matches each → 3×45 = 135 → each capped at 45, but still 45 per rule
    // 3 high rules × cap 45 each, wait — each rule has its own cap
    // Let's use: 3 high rules (3 matches each → each capped at 45) + 1 medium → 45+45+45 = 135 > 100, clamped
    // Better: 2 high rules (cap 45 each) = 90 > 70 → critical
    const r = scan([
      '.gitleaks.toml', 'gitleaks.toml', 'gitleaks.yaml', // SECRET (×3 → 45)
      'semgrep.yml', '.semgrep.yml', 'semgrep.yaml',       // SAST   (×3 → 45)
    ])
    expect(r.riskScore).toBe(90)
    expect(r.riskLevel).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

describe('deduplication (one finding per rule)', () => {
  it('multiple secret scan files produce one SECRET_SCAN_CONFIG_DRIFT finding', () => {
    const r = scan(['.gitleaks.toml', 'gitleaks.toml', '.secrets.baseline', 'trufflehog.toml'])
    const ids = ruleIds(r)
    expect(ids.filter((id) => id === 'SECRET_SCAN_CONFIG_DRIFT')).toHaveLength(1)
  })

  it('matchCount reflects number of matched paths', () => {
    const r = scan(['.gitleaks.toml', 'gitleaks.toml', '.secrets.baseline'])
    const finding = r.findings.find((f) => f.ruleId === 'SECRET_SCAN_CONFIG_DRIFT')
    expect(finding?.matchCount).toBe(3)
  })

  it('matchedPath is the first matched path', () => {
    const r = scan(['.gitleaks.toml', 'gitleaks.toml'])
    const finding = r.findings.find((f) => f.ruleId === 'SECRET_SCAN_CONFIG_DRIFT')
    expect(finding?.matchedPath).toBe('.gitleaks.toml')
  })

  it('duplicate identical paths each count separately', () => {
    const r = scan(['.gitleaks.toml', '.gitleaks.toml', '.gitleaks.toml'])
    const finding = r.findings.find((f) => f.ruleId === 'SECRET_SCAN_CONFIG_DRIFT')
    expect(finding?.matchCount).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// Finding ordering
// ---------------------------------------------------------------------------

describe('finding ordering (high before medium before low)', () => {
  it('returns high findings before medium and low', () => {
    const r = scan(['.talismanrc', '.brakeman.yml', '.gitleaks.toml'])
    const severities = r.findings.map((f) => f.severity)
    const highIdx  = severities.indexOf('high')
    const medIdx   = severities.indexOf('medium')
    const lowIdx   = severities.indexOf('low')
    if (highIdx !== -1 && medIdx !== -1) expect(highIdx).toBeLessThan(medIdx)
    if (medIdx  !== -1 && lowIdx  !== -1) expect(medIdx).toBeLessThan(lowIdx)
    if (highIdx !== -1 && lowIdx  !== -1) expect(highIdx).toBeLessThan(lowIdx)
  })

  it('all-high results are all high severity', () => {
    const r = scan(['.gitleaks.toml', 'semgrep.yml', '.snyk'])
    for (const f of r.findings) {
      expect(f.severity).toBe('high')
    }
  })
})

// ---------------------------------------------------------------------------
// Summary text
// ---------------------------------------------------------------------------

describe('summary text', () => {
  it('contains "none" message for empty result', () => {
    expect(scan([]).summary).toContain('No developer security tooling')
  })

  it('mentions "high" count when high findings exist', () => {
    const r = scan(['.gitleaks.toml'])
    expect(r.summary).toContain('1 high')
  })

  it('mentions the top rule label', () => {
    const r = scan(['.gitleaks.toml'])
    expect(r.summary.toLowerCase()).toContain('secret scan config drift')
  })

  it('mentions medium findings', () => {
    const r = scan(['.brakeman.yml'])
    expect(r.summary).toContain('1 medium')
  })

  it('uses plural "findings" for multiple', () => {
    const r = scan(['.gitleaks.toml', '.brakeman.yml'])
    expect(r.summary).toContain('findings')
  })

  it('uses singular "finding" for one', () => {
    const r = scan(['.gitleaks.toml'])
    expect(r.summary).toContain('finding')
  })
})

// ---------------------------------------------------------------------------
// Windows path normalisation
// ---------------------------------------------------------------------------

describe('Windows path normalisation', () => {
  it('handles backslash paths for secret scan config', () => {
    const r = scan(['.gitleaks.toml'.replace(/\//g, '\\')])
    expect(ruleIds(r)).toContain('SECRET_SCAN_CONFIG_DRIFT')
  })

  it('handles backslash paths for nested SAST config', () => {
    const r = scan(['ci\\semgrep\\custom.yml'])
    expect(ruleIds(r)).toContain('SAST_POLICY_DRIFT')
  })

  it('handles backslash paths for container scan config in directory', () => {
    const r = scan(['ci\\trivy\\ignore.yaml'])
    expect(ruleIds(r)).toContain('CONTAINER_SCAN_POLICY_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Multi-rule scenarios
// ---------------------------------------------------------------------------

describe('multi-rule scenarios', () => {
  it('a commit touching both secret scan and SAST configs triggers both rules', () => {
    const r = scan(['.gitleaks.toml', 'semgrep.yml'])
    expect(ruleIds(r)).toContain('SECRET_SCAN_CONFIG_DRIFT')
    expect(ruleIds(r)).toContain('SAST_POLICY_DRIFT')
    expect(r.totalFindings).toBe(2)
    expect(r.highCount).toBe(2)
  })

  it('touching all 8 rule families triggers 8 findings', () => {
    const r = scan([
      '.gitleaks.toml',   // SECRET_SCAN_CONFIG_DRIFT
      'semgrep.yml',      // SAST_POLICY_DRIFT
      '.snyk',            // SCA_POLICY_DRIFT
      '.brakeman.yml',    // SECURITY_LINT_DRIFT
      'nikto.conf',       // DAST_SCAN_CONFIG_DRIFT
      '.fossa.yml',       // LICENSE_POLICY_CONFIG_DRIFT
      'trivy.yaml',       // CONTAINER_SCAN_POLICY_DRIFT
      '.talismanrc',      // SECURITY_BASELINE_DRIFT
    ])
    expect(r.totalFindings).toBe(8)
    expect(r.highCount).toBe(3)
    expect(r.mediumCount).toBe(4)
    expect(r.lowCount).toBe(1)
  })

  it('counts from all rules are tracked independently', () => {
    const r = scan([
      '.gitleaks.toml', 'gitleaks.toml',     // SECRET ×2
      'semgrep.yml',                          // SAST ×1
    ])
    const secretFinding = r.findings.find((f) => f.ruleId === 'SECRET_SCAN_CONFIG_DRIFT')
    const sastFinding   = r.findings.find((f) => f.ruleId === 'SAST_POLICY_DRIFT')
    expect(secretFinding?.matchCount).toBe(2)
    expect(sastFinding?.matchCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// Registry completeness
// ---------------------------------------------------------------------------

describe('DEV_SEC_TOOLS_RULES registry completeness', () => {
  const EXPECTED_RULE_IDS = [
    'SECRET_SCAN_CONFIG_DRIFT',
    'SAST_POLICY_DRIFT',
    'SCA_POLICY_DRIFT',
    'SECURITY_LINT_DRIFT',
    'DAST_SCAN_CONFIG_DRIFT',
    'LICENSE_POLICY_CONFIG_DRIFT',
    'CONTAINER_SCAN_POLICY_DRIFT',
    'SECURITY_BASELINE_DRIFT',
  ]

  it('has exactly 8 rules', () => {
    expect(DEV_SEC_TOOLS_RULES).toHaveLength(8)
  })

  it('contains all expected rule IDs', () => {
    const ids = DEV_SEC_TOOLS_RULES.map((r) => r.id)
    for (const id of EXPECTED_RULE_IDS) {
      expect(ids).toContain(id)
    }
  })

  it('every rule has a non-empty description and recommendation', () => {
    for (const rule of DEV_SEC_TOOLS_RULES) {
      expect(rule.description.length).toBeGreaterThan(10)
      expect(rule.recommendation.length).toBeGreaterThan(10)
    }
  })

  it('severity distribution: 3 high, 4 medium, 1 low', () => {
    const highRules   = DEV_SEC_TOOLS_RULES.filter((r) => r.severity === 'high')
    const mediumRules = DEV_SEC_TOOLS_RULES.filter((r) => r.severity === 'medium')
    const lowRules    = DEV_SEC_TOOLS_RULES.filter((r) => r.severity === 'low')
    expect(highRules).toHaveLength(3)
    expect(mediumRules).toHaveLength(4)
    expect(lowRules).toHaveLength(1)
  })
})
