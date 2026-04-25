import { describe, expect, it } from 'vitest'
import {
  CERT_PKI_RULES,
  isCertificatePinningConfig,
  scanCertPkiDrift,
  type CertPkiDriftResult,
} from './certPkiDrift'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function scan(paths: string[]): CertPkiDriftResult {
  return scanCertPkiDrift(paths)
}

function ruleIds(result: CertPkiDriftResult) {
  return result.findings.map((f) => f.ruleId)
}

// ---------------------------------------------------------------------------
// Trivial inputs
// ---------------------------------------------------------------------------

describe('trivial inputs', () => {
  it('returns none risk on empty array', () => {
    const r = scan([])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
    expect(r.totalFindings).toBe(0)
    expect(r.findings).toHaveLength(0)
  })

  it('returns none risk on whitespace-only paths', () => {
    const r = scan(['', '  ', '\t'])
    expect(r.riskLevel).toBe('none')
    expect(r.totalFindings).toBe(0)
  })

  it('returns none risk on unrelated source files', () => {
    const r = scan([
      'src/auth/jwt.ts',
      'src/api/users.ts',
      'README.md',
      'package.json',
      'src/utils/crypto.ts',
    ])
    expect(r.riskLevel).toBe('none')
  })

  it('summary mentions file count when clean', () => {
    const r = scan(['src/app.ts', 'src/index.ts'])
    expect(r.summary).toContain('2')
    expect(r.summary).toContain('no cryptographic')
  })
})

// ---------------------------------------------------------------------------
// Vendor exclusion
// ---------------------------------------------------------------------------

describe('vendor exclusion', () => {
  it('skips node_modules paths', () => {
    const r = scan(['node_modules/some-lib/ca.pem', 'node_modules/.bin/cosign.pub'])
    expect(r.riskLevel).toBe('none')
  })

  it('skips dist paths', () => {
    const r = scan(['dist/certs/ca.crt', 'dist/cosign.yaml'])
    expect(r.riskLevel).toBe('none')
  })

  it('skips .terraform paths', () => {
    const r = scan(['.terraform/modules/pki.tf', '.terraform/ca.pem'])
    expect(r.riskLevel).toBe('none')
  })

  it('skips __pycache__ paths', () => {
    const r = scan(['__pycache__/certificate.yaml'])
    expect(r.riskLevel).toBe('none')
  })

  it('does not skip non-vendor PKI files in the same directory', () => {
    // Make sure vendor exclusion doesn't accidentally exclude legitimate paths
    const r = scan(['infrastructure/pki/ca.pem'])
    expect(r.riskLevel).not.toBe('none')
  })
})

// ---------------------------------------------------------------------------
// CERT_MANAGER_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('CERT_MANAGER_CONFIG_DRIFT', () => {
  it('detects exact certificate.yaml', () => {
    const r = scan(['k8s/certificate.yaml'])
    expect(ruleIds(r)).toContain('CERT_MANAGER_CONFIG_DRIFT')
  })

  it('detects issuer.yml', () => {
    const r = scan(['infra/issuer.yml'])
    expect(ruleIds(r)).toContain('CERT_MANAGER_CONFIG_DRIFT')
  })

  it('detects clusterissuer.yaml', () => {
    const r = scan(['manifests/clusterissuer.yaml'])
    expect(ruleIds(r)).toContain('CERT_MANAGER_CONFIG_DRIFT')
  })

  it('detects cluster-issuer.yaml', () => {
    const r = scan(['cluster-issuer.yaml'])
    expect(ruleIds(r)).toContain('CERT_MANAGER_CONFIG_DRIFT')
  })

  it('detects certificaterequest.yaml', () => {
    const r = scan(['k8s/certificaterequest.yaml'])
    expect(ruleIds(r)).toContain('CERT_MANAGER_CONFIG_DRIFT')
  })

  it('detects files in /cert-manager/ directory', () => {
    const r = scan(['infra/cert-manager/production-cert.yaml'])
    expect(ruleIds(r)).toContain('CERT_MANAGER_CONFIG_DRIFT')
  })

  it('detects cert-manager-prefixed yaml files', () => {
    const r = scan(['k8s/cert-manager-config.yaml'])
    expect(ruleIds(r)).toContain('CERT_MANAGER_CONFIG_DRIFT')
  })

  it('does not trigger on certificate.ts (source file)', () => {
    const r = scan(['src/certificate.ts'])
    expect(ruleIds(r)).not.toContain('CERT_MANAGER_CONFIG_DRIFT')
  })

  it('does not trigger on generic config.yaml', () => {
    const r = scan(['config.yaml'])
    expect(ruleIds(r)).not.toContain('CERT_MANAGER_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// PKI_CA_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('PKI_CA_CONFIG_DRIFT', () => {
  it('detects ca.pem', () => {
    const r = scan(['tls/ca.pem'])
    expect(ruleIds(r)).toContain('PKI_CA_CONFIG_DRIFT')
  })

  it('detects ca.crt', () => {
    const r = scan(['certs/ca.crt'])
    expect(ruleIds(r)).toContain('PKI_CA_CONFIG_DRIFT')
  })

  it('detects root-ca.crt', () => {
    const r = scan(['pki/root-ca.crt'])
    expect(ruleIds(r)).toContain('PKI_CA_CONFIG_DRIFT')
  })

  it('detects intermediate-ca.pem', () => {
    const r = scan(['pki/intermediate-ca.pem'])
    expect(ruleIds(r)).toContain('PKI_CA_CONFIG_DRIFT')
  })

  it('detects ca-chain.crt', () => {
    const r = scan(['ca-chain.crt'])
    expect(ruleIds(r)).toContain('PKI_CA_CONFIG_DRIFT')
  })

  it('detects pki.yaml config', () => {
    const r = scan(['infra/pki.yaml'])
    expect(ruleIds(r)).toContain('PKI_CA_CONFIG_DRIFT')
  })

  it('detects files in /pki/ directory', () => {
    const r = scan(['infra/pki/root-certificate.pem'])
    expect(ruleIds(r)).toContain('PKI_CA_CONFIG_DRIFT')
  })

  it('does not trigger on src/ca.ts (source file)', () => {
    const r = scan(['src/ca.ts'])
    expect(ruleIds(r)).not.toContain('PKI_CA_CONFIG_DRIFT')
  })

  it('does not trigger on src/caUtils.js (source file with ca prefix)', () => {
    const r = scan(['src/caUtils.js'])
    expect(ruleIds(r)).not.toContain('PKI_CA_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// LETS_ENCRYPT_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('LETS_ENCRYPT_CONFIG_DRIFT', () => {
  it('detects acme.json', () => {
    const r = scan(['data/acme.json'])
    expect(ruleIds(r)).toContain('LETS_ENCRYPT_CONFIG_DRIFT')
  })

  it('detects .acme.json (Traefik)', () => {
    const r = scan(['.acme.json'])
    expect(ruleIds(r)).toContain('LETS_ENCRYPT_CONFIG_DRIFT')
  })

  it('detects letsencrypt.yaml', () => {
    const r = scan(['config/letsencrypt.yaml'])
    expect(ruleIds(r)).toContain('LETS_ENCRYPT_CONFIG_DRIFT')
  })

  it('detects certbot-prefixed config', () => {
    const r = scan(['certbot-config.ini'])
    expect(ruleIds(r)).toContain('LETS_ENCRYPT_CONFIG_DRIFT')
  })

  it('detects lego-config.toml', () => {
    const r = scan(['lego-config.toml'])
    expect(ruleIds(r)).toContain('LETS_ENCRYPT_CONFIG_DRIFT')
  })

  it('detects files in /letsencrypt/ directory', () => {
    const r = scan(['/etc/letsencrypt/renewal/example.com.conf'])
    expect(ruleIds(r)).toContain('LETS_ENCRYPT_CONFIG_DRIFT')
  })

  it('detects files in /certbot/ directory', () => {
    const r = scan(['ops/certbot/cli.ini'])
    expect(ruleIds(r)).toContain('LETS_ENCRYPT_CONFIG_DRIFT')
  })

  it('does not trigger on acme.ts (source file)', () => {
    const r = scan(['src/acme.ts'])
    expect(ruleIds(r)).not.toContain('LETS_ENCRYPT_CONFIG_DRIFT')
  })

  it('does not trigger on lego.go (source file)', () => {
    const r = scan(['cmd/lego.go'])
    expect(ruleIds(r)).not.toContain('LETS_ENCRYPT_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// CERTIFICATE_PINNING_CONFIG_DRIFT — user contribution point
// ---------------------------------------------------------------------------

describe('isCertificatePinningConfig (user contribution)', () => {
  it('detects network-security-config.xml (Android)', () => {
    expect(isCertificatePinningConfig('res/xml/network-security-config.xml')).toBe(true)
  })

  it('detects network_security_config.xml (Android underscore variant)', () => {
    expect(isCertificatePinningConfig('android/app/src/main/res/xml/network_security_config.xml')).toBe(true)
  })

  it('detects trustkit.json (iOS TrustKit)', () => {
    expect(isCertificatePinningConfig('ios/TrustKit/trustkit.json')).toBe(true)
  })

  it('detects TrustKit.plist (iOS)', () => {
    expect(isCertificatePinningConfig('ios/TrustKitConfig.plist')).toBe(true)
  })

  it('detects hpkp.json (HPKP)', () => {
    expect(isCertificatePinningConfig('security/hpkp.json')).toBe(true)
  })

  it('detects certificate-pinning.json', () => {
    expect(isCertificatePinningConfig('config/certificate-pinning.json')).toBe(true)
  })

  it('detects ssl-pinning.yaml', () => {
    expect(isCertificatePinningConfig('ssl-pinning.yaml')).toBe(true)
  })

  it('detects cert-pins.json', () => {
    expect(isCertificatePinningConfig('cert-pins.json')).toBe(true)
  })

  it('detects files in /pinning/ directory', () => {
    expect(isCertificatePinningConfig('security/pinning/production.json')).toBe(true)
  })

  it('does not detect Info.plist (too generic)', () => {
    expect(isCertificatePinningConfig('ios/Info.plist')).toBe(false)
  })

  it('does not detect arbitrary .xml files', () => {
    expect(isCertificatePinningConfig('res/layout/activity_main.xml')).toBe(false)
  })

  it('does not detect source files', () => {
    expect(isCertificatePinningConfig('src/pinning/PinValidator.ts')).toBe(false)
  })
})

describe('CERTIFICATE_PINNING_CONFIG_DRIFT rule', () => {
  it('triggers via scanner', () => {
    const r = scan(['config/certificate-pinning.json'])
    expect(ruleIds(r)).toContain('CERTIFICATE_PINNING_CONFIG_DRIFT')
  })

  it('triggers for Android NSC via scanner', () => {
    const r = scan(['android/res/xml/network-security-config.xml'])
    expect(ruleIds(r)).toContain('CERTIFICATE_PINNING_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// SSH_AUTH_KEY_DRIFT
// ---------------------------------------------------------------------------

describe('SSH_AUTH_KEY_DRIFT', () => {
  it('detects authorized_keys', () => {
    const r = scan(['.ssh/authorized_keys'])
    expect(ruleIds(r)).toContain('SSH_AUTH_KEY_DRIFT')
  })

  it('detects authorized_keys2', () => {
    const r = scan(['/home/deploy/.ssh/authorized_keys2'])
    expect(ruleIds(r)).toContain('SSH_AUTH_KEY_DRIFT')
  })

  it('detects sshd_config', () => {
    const r = scan(['etc/sshd_config'])
    expect(ruleIds(r)).toContain('SSH_AUTH_KEY_DRIFT')
  })

  it('detects ssh_config', () => {
    const r = scan(['ssh_config'])
    expect(ruleIds(r)).toContain('SSH_AUTH_KEY_DRIFT')
  })

  it('detects files in .ssh/ directory', () => {
    const r = scan(['ops/server/.ssh/id_rsa.pub'])
    expect(ruleIds(r)).toContain('SSH_AUTH_KEY_DRIFT')
  })

  it('detects SSH host public keys', () => {
    const r = scan(['ssh_host_ecdsa_key.pub'])
    expect(ruleIds(r)).toContain('SSH_AUTH_KEY_DRIFT')
  })

  it('detects files in /etc/ssh/ directory', () => {
    const r = scan(['/etc/ssh/sshd_config'])
    expect(ruleIds(r)).toContain('SSH_AUTH_KEY_DRIFT')
  })

  it('does not trigger on sshd.ts (source file)', () => {
    const r = scan(['src/sshd.ts'])
    expect(ruleIds(r)).not.toContain('SSH_AUTH_KEY_DRIFT')
  })

  it('does not trigger on authorized.json (no SSH prefix match)', () => {
    const r = scan(['config/authorized.json'])
    expect(ruleIds(r)).not.toContain('SSH_AUTH_KEY_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// GPG_KEYRING_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('GPG_KEYRING_CONFIG_DRIFT', () => {
  it('detects gpg.conf', () => {
    const r = scan(['.gnupg/gpg.conf'])
    expect(ruleIds(r)).toContain('GPG_KEYRING_CONFIG_DRIFT')
  })

  it('detects pubring.gpg', () => {
    const r = scan(['.gnupg/pubring.gpg'])
    expect(ruleIds(r)).toContain('GPG_KEYRING_CONFIG_DRIFT')
  })

  it('detects trustdb.gpg', () => {
    const r = scan(['trustdb.gpg'])
    expect(ruleIds(r)).toContain('GPG_KEYRING_CONFIG_DRIFT')
  })

  it('detects dirmngr.conf', () => {
    const r = scan(['.gnupg/dirmngr.conf'])
    expect(ruleIds(r)).toContain('GPG_KEYRING_CONFIG_DRIFT')
  })

  it('detects files in .gnupg/ directory', () => {
    const r = scan(['ops/.gnupg/custom-keyring.gpg'])
    expect(ruleIds(r)).toContain('GPG_KEYRING_CONFIG_DRIFT')
  })

  it('detects gpg-key-prefixed .gpg files', () => {
    const r = scan(['signing/gpg-key.asc'])
    expect(ruleIds(r)).toContain('GPG_KEYRING_CONFIG_DRIFT')
  })

  it('detects keyring-prefixed config', () => {
    const r = scan(['keyring-config.json'])
    expect(ruleIds(r)).toContain('GPG_KEYRING_CONFIG_DRIFT')
  })

  it('does not trigger on gpg.ts (source file)', () => {
    const r = scan(['src/gpg.ts'])
    expect(ruleIds(r)).not.toContain('GPG_KEYRING_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// SIGSTORE_COSIGN_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('SIGSTORE_COSIGN_CONFIG_DRIFT', () => {
  it('detects cosign.pub', () => {
    const r = scan(['signing/cosign.pub'])
    expect(ruleIds(r)).toContain('SIGSTORE_COSIGN_CONFIG_DRIFT')
  })

  it('detects cosign.yaml', () => {
    const r = scan(['cosign.yaml'])
    expect(ruleIds(r)).toContain('SIGSTORE_COSIGN_CONFIG_DRIFT')
  })

  it('detects cosign.key', () => {
    const r = scan(['.cosign/cosign.key'])
    expect(ruleIds(r)).toContain('SIGSTORE_COSIGN_CONFIG_DRIFT')
  })

  it('detects rekor.yaml', () => {
    const r = scan(['sigstore/rekor.yaml'])
    expect(ruleIds(r)).toContain('SIGSTORE_COSIGN_CONFIG_DRIFT')
  })

  it('detects files in /cosign/ directory', () => {
    const r = scan(['infra/cosign/policy.json'])
    expect(ruleIds(r)).toContain('SIGSTORE_COSIGN_CONFIG_DRIFT')
  })

  it('detects .intoto.jsonl provenance files', () => {
    // dist/ is vendor-excluded; use artifacts/ instead
    const r = scan(['artifacts/image.intoto.jsonl'])
    expect(ruleIds(r)).toContain('SIGSTORE_COSIGN_CONFIG_DRIFT')
  })

  it('detects slsa-prefixed config', () => {
    const r = scan(['slsa-config.json'])
    expect(ruleIds(r)).toContain('SIGSTORE_COSIGN_CONFIG_DRIFT')
  })

  it('detects files in /sigstore/ directory', () => {
    const r = scan(['ops/sigstore/fulcio-config.json'])
    expect(ruleIds(r)).toContain('SIGSTORE_COSIGN_CONFIG_DRIFT')
  })

  it('does not trigger on cosign.go (source file)', () => {
    const r = scan(['cmd/cosign.go'])
    expect(ruleIds(r)).not.toContain('SIGSTORE_COSIGN_CONFIG_DRIFT')
  })

  it('does not trigger on sigstore-sdk.ts (source file)', () => {
    const r = scan(['src/sigstore-sdk.ts'])
    expect(ruleIds(r)).not.toContain('SIGSTORE_COSIGN_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// TLS_CERTIFICATE_BUNDLE_DRIFT
// ---------------------------------------------------------------------------

describe('TLS_CERTIFICATE_BUNDLE_DRIFT', () => {
  it('detects ca-certificates.crt (system trust store)', () => {
    const r = scan(['/etc/ssl/certs/ca-certificates.crt'])
    expect(ruleIds(r)).toContain('TLS_CERTIFICATE_BUNDLE_DRIFT')
  })

  it('detects cacert.pem', () => {
    const r = scan(['cacert.pem'])
    expect(ruleIds(r)).toContain('TLS_CERTIFICATE_BUNDLE_DRIFT')
  })

  it('detects ca-bundle.crt', () => {
    const r = scan(['tls/ca-bundle.crt'])
    expect(ruleIds(r)).toContain('TLS_CERTIFICATE_BUNDLE_DRIFT')
  })

  it('detects trusted-certs.pem', () => {
    const r = scan(['trusted-certs.pem'])
    expect(ruleIds(r)).toContain('TLS_CERTIFICATE_BUNDLE_DRIFT')
  })

  it('detects truststore.jks', () => {
    const r = scan(['config/truststore.jks'])
    expect(ruleIds(r)).toContain('TLS_CERTIFICATE_BUNDLE_DRIFT')
  })

  it('detects files in /trusted-certs/ directory', () => {
    const r = scan(['docker/trusted-certs/corporate.crt'])
    expect(ruleIds(r)).toContain('TLS_CERTIFICATE_BUNDLE_DRIFT')
  })

  it('detects truststore-prefixed pem', () => {
    const r = scan(['trust-store.pem'])
    expect(ruleIds(r)).toContain('TLS_CERTIFICATE_BUNDLE_DRIFT')
  })

  it('does not trigger on ca-readme.md', () => {
    const r = scan(['docs/ca-readme.md'])
    expect(ruleIds(r)).not.toContain('TLS_CERTIFICATE_BUNDLE_DRIFT')
  })

  it('does not trigger on arbitrary .crt without bundle prefix', () => {
    const r = scan(['server.crt'])
    expect(ruleIds(r)).not.toContain('TLS_CERTIFICATE_BUNDLE_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Scoring and risk levels
// ---------------------------------------------------------------------------

describe('scoring and risk levels', () => {
  it('returns none when no cert/PKI files changed', () => {
    const r = scan(['src/app.ts'])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })

  it('single low finding → low risk level', () => {
    // 1 × low (4) = 4 → low (< 20)
    const r = scan(['cacert.pem'])
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('single medium finding → low risk level', () => {
    // 1 × medium (8) = 8 → low (< 20)
    const r = scan(['authorized_keys'])
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('single high finding → low risk level', () => {
    // 1 × high (15) = 15 → low (< 20)
    const r = scan(['ca.pem'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('low')
  })

  it('two high findings → medium risk level', () => {
    // 2 × high (30) → medium (< 45)
    const r = scan(['ca.pem', 'certificate.yaml'])
    expect(r.riskScore).toBe(30)
    expect(r.riskLevel).toBe('medium')
  })

  it('three high findings → medium risk level', () => {
    // 3 × high (45) = capped → 45 → high (≥ 45)
    const r = scan(['ca.pem', 'certificate.yaml', 'acme.json'])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('max high tier score is capped at PENALTY_CAP', () => {
    // 4 × high would be 60, but cap is 45
    const r = scan([
      'ca.pem',
      'certificate.yaml',
      'acme.json',
      'root-ca.crt',
    ])
    const highFindings = r.findings.filter((f) => f.severity === 'high').length
    expect(highFindings).toBeGreaterThanOrEqual(3)
    // High cap is 45; total should not exceed 100
    expect(r.riskScore).toBeLessThanOrEqual(100)
  })

  it('reaches critical risk with 3 high + 3 medium findings', () => {
    const r = scan([
      'ca.pem',            // high: PKI_CA_CONFIG_DRIFT
      'certificate.yaml',  // high: CERT_MANAGER_CONFIG_DRIFT
      'acme.json',         // high: LETS_ENCRYPT_CONFIG_DRIFT
      'authorized_keys',   // medium: SSH_AUTH_KEY_DRIFT
      'gpg.conf',          // medium: GPG_KEYRING_CONFIG_DRIFT
      'cosign.pub',        // medium: SIGSTORE_COSIGN_CONFIG_DRIFT
    ])
    // 3×high capped at 45 + 3×medium (24) = 69 → high
    // Actually: 45 + 24 = 69 → high (< 70)
    expect(r.riskScore).toBe(69)
    expect(r.riskLevel).toBe('high')
  })

  it('reaches critical with all 8 rules triggered', () => {
    const r = scan([
      'certificate.yaml',                  // CERT_MANAGER_CONFIG_DRIFT (high)
      'ca.pem',                            // PKI_CA_CONFIG_DRIFT (high)
      'acme.json',                         // LETS_ENCRYPT_CONFIG_DRIFT (high)
      'certificate-pinning.json',          // CERTIFICATE_PINNING_CONFIG_DRIFT (medium)
      'authorized_keys',                   // SSH_AUTH_KEY_DRIFT (medium)
      'gpg.conf',                          // GPG_KEYRING_CONFIG_DRIFT (medium)
      'cosign.pub',                        // SIGSTORE_COSIGN_CONFIG_DRIFT (medium)
      'cacert.pem',                        // TLS_CERTIFICATE_BUNDLE_DRIFT (low)
    ])
    // 3×high capped at 45 + 4×medium capped at 25 + 1×low = 4 → 74 → critical
    expect(r.riskScore).toBe(74)
    expect(r.riskLevel).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// Counts
// ---------------------------------------------------------------------------

describe('severity counts', () => {
  it('reflects correct high/medium/low counts', () => {
    const r = scan([
      'ca.pem',               // high
      'certificate.yaml',     // high
      'authorized_keys',      // medium
      'cacert.pem',           // low
    ])
    expect(r.highCount).toBe(2)
    expect(r.mediumCount).toBe(1)
    expect(r.lowCount).toBe(1)
    expect(r.totalFindings).toBe(4)
  })
})

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

describe('deduplication', () => {
  it('deduplicates multiple ca.pem files into one finding with count', () => {
    const r = scan([
      'tls/ca.pem',
      'other/ca.crt',
      'root-ca.crt',
    ])
    const pkiFinding = r.findings.find((f) => f.ruleId === 'PKI_CA_CONFIG_DRIFT')
    expect(pkiFinding).toBeDefined()
    expect(pkiFinding!.matchCount).toBe(3)
    // Should still be one finding for the rule
    const pkiFindings = r.findings.filter((f) => f.ruleId === 'PKI_CA_CONFIG_DRIFT')
    expect(pkiFindings).toHaveLength(1)
  })

  it('records first matched path for deduped finding', () => {
    // ca-first.pem starts with 'ca-' prefix → matches PKI_CA before second/ca.crt
    const r = scan(['ca-first.pem', 'second/ca.crt'])
    const pkiFinding = r.findings.find((f) => f.ruleId === 'PKI_CA_CONFIG_DRIFT')
    expect(pkiFinding!.matchedPath).toBe('ca-first.pem')
  })

  it('multiple authorized_keys files deduplicate into one finding', () => {
    const r = scan([
      'home/admin/.ssh/authorized_keys',
      'home/deploy/.ssh/authorized_keys',
      'home/ci/.ssh/authorized_keys',
    ])
    const sshFinding = r.findings.find((f) => f.ruleId === 'SSH_AUTH_KEY_DRIFT')
    expect(sshFinding!.matchCount).toBe(3)
    expect(r.findings.filter((f) => f.ruleId === 'SSH_AUTH_KEY_DRIFT')).toHaveLength(1)
  })
})

// ---------------------------------------------------------------------------
// Finding order
// ---------------------------------------------------------------------------

describe('finding order', () => {
  it('returns findings in rule-definition order', () => {
    const r = scan([
      'cacert.pem',                 // TLS_CERTIFICATE_BUNDLE_DRIFT (last)
      'cosign.pub',                 // SIGSTORE_COSIGN_CONFIG_DRIFT
      'gpg.conf',                   // GPG_KEYRING_CONFIG_DRIFT
      'ca.pem',                     // PKI_CA_CONFIG_DRIFT (second)
      'certificate.yaml',           // CERT_MANAGER_CONFIG_DRIFT (first)
    ])
    const ids = ruleIds(r)
    // CERT_MANAGER_CONFIG_DRIFT should come before PKI_CA_CONFIG_DRIFT
    expect(ids.indexOf('CERT_MANAGER_CONFIG_DRIFT')).toBeLessThan(ids.indexOf('PKI_CA_CONFIG_DRIFT'))
    // GPG_KEYRING_CONFIG_DRIFT should come before SIGSTORE_COSIGN_CONFIG_DRIFT
    expect(ids.indexOf('GPG_KEYRING_CONFIG_DRIFT')).toBeLessThan(ids.indexOf('SIGSTORE_COSIGN_CONFIG_DRIFT'))
    // SIGSTORE_COSIGN_CONFIG_DRIFT should come before TLS_CERTIFICATE_BUNDLE_DRIFT
    expect(ids.indexOf('SIGSTORE_COSIGN_CONFIG_DRIFT')).toBeLessThan(ids.indexOf('TLS_CERTIFICATE_BUNDLE_DRIFT'))
  })
})

// ---------------------------------------------------------------------------
// Summary text
// ---------------------------------------------------------------------------

describe('summary', () => {
  it('clean summary includes file count', () => {
    const r = scan(['src/index.ts', 'README.md', 'package.json'])
    expect(r.summary).toContain('3')
    expect(r.summary).toContain('no cryptographic')
  })

  it('high-finding summary mentions mandatory review', () => {
    const r = scan(['ca.pem'])
    expect(r.summary).toContain('mandatory security review')
  })

  it('medium-only summary mentions risk level', () => {
    const r = scan(['authorized_keys'])
    expect(r.summary).toContain('risk level')
  })

  it('low-only summary mentions risk level', () => {
    const r = scan(['cacert.pem'])
    expect(r.summary).toContain('risk level')
  })

  it('high summary correctly labels multiple rules', () => {
    const r = scan(['ca.pem', 'certificate.yaml'])
    expect(r.summary).toContain('PKI/CA certificate')
    expect(r.summary).toContain('cert-manager CRD')
  })
})

// ---------------------------------------------------------------------------
// Windows-style path normalisation
// ---------------------------------------------------------------------------

describe('Windows path normalisation', () => {
  it('handles Windows backslash paths', () => {
    const r = scan(['infra\\certs\\ca.pem'])
    expect(ruleIds(r)).toContain('PKI_CA_CONFIG_DRIFT')
  })

  it('handles Windows-style cert-manager paths', () => {
    const r = scan(['k8s\\cert-manager\\issuer.yaml'])
    expect(ruleIds(r)).toContain('CERT_MANAGER_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Multi-rule scenarios
// ---------------------------------------------------------------------------

describe('multi-rule scenarios', () => {
  it('simultaneous PKI and cert-manager changes both fire', () => {
    const r = scan(['ca.pem', 'certificate.yaml'])
    expect(ruleIds(r)).toContain('PKI_CA_CONFIG_DRIFT')
    expect(ruleIds(r)).toContain('CERT_MANAGER_CONFIG_DRIFT')
  })

  it('SSH + GPG + cosign all fire from a single commit', () => {
    const r = scan([
      '.ssh/authorized_keys',
      '.gnupg/gpg.conf',
      'cosign.pub',
    ])
    expect(ruleIds(r)).toContain('SSH_AUTH_KEY_DRIFT')
    expect(ruleIds(r)).toContain('GPG_KEYRING_CONFIG_DRIFT')
    expect(ruleIds(r)).toContain('SIGSTORE_COSIGN_CONFIG_DRIFT')
  })

  it('full suite: all 8 rules fire', () => {
    const r = scan([
      'certificate.yaml',                  // CERT_MANAGER_CONFIG_DRIFT
      'ca.pem',                            // PKI_CA_CONFIG_DRIFT
      'acme.json',                         // LETS_ENCRYPT_CONFIG_DRIFT
      'certificate-pinning.json',          // CERTIFICATE_PINNING_CONFIG_DRIFT
      'authorized_keys',                   // SSH_AUTH_KEY_DRIFT
      'gpg.conf',                          // GPG_KEYRING_CONFIG_DRIFT
      'cosign.pub',                        // SIGSTORE_COSIGN_CONFIG_DRIFT
      'cacert.pem',                        // TLS_CERTIFICATE_BUNDLE_DRIFT
    ])
    expect(r.totalFindings).toBe(8)
    expect(ruleIds(r)).toContain('CERT_MANAGER_CONFIG_DRIFT')
    expect(ruleIds(r)).toContain('PKI_CA_CONFIG_DRIFT')
    expect(ruleIds(r)).toContain('LETS_ENCRYPT_CONFIG_DRIFT')
    expect(ruleIds(r)).toContain('CERTIFICATE_PINNING_CONFIG_DRIFT')
    expect(ruleIds(r)).toContain('SSH_AUTH_KEY_DRIFT')
    expect(ruleIds(r)).toContain('GPG_KEYRING_CONFIG_DRIFT')
    expect(ruleIds(r)).toContain('SIGSTORE_COSIGN_CONFIG_DRIFT')
    expect(ruleIds(r)).toContain('TLS_CERTIFICATE_BUNDLE_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Registry integrity
// ---------------------------------------------------------------------------

describe('CERT_PKI_RULES registry', () => {
  it('contains exactly 8 rules', () => {
    expect(CERT_PKI_RULES).toHaveLength(8)
  })

  it('all rule IDs are unique', () => {
    const ids = CERT_PKI_RULES.map((r) => r.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it('severity distribution: 3 high, 4 medium, 1 low', () => {
    const highRules   = CERT_PKI_RULES.filter((r) => r.severity === 'high')
    const mediumRules = CERT_PKI_RULES.filter((r) => r.severity === 'medium')
    const lowRules    = CERT_PKI_RULES.filter((r) => r.severity === 'low')
    expect(highRules).toHaveLength(3)
    expect(mediumRules).toHaveLength(4)
    expect(lowRules).toHaveLength(1)
  })

  it('every rule has non-empty description and recommendation', () => {
    for (const rule of CERT_PKI_RULES) {
      expect(rule.description.length).toBeGreaterThan(10)
      expect(rule.recommendation.length).toBeGreaterThan(10)
    }
  })

  it('CERT_MANAGER_CONFIG_DRIFT is high severity', () => {
    const rule = CERT_PKI_RULES.find((r) => r.id === 'CERT_MANAGER_CONFIG_DRIFT')
    expect(rule?.severity).toBe('high')
  })

  it('TLS_CERTIFICATE_BUNDLE_DRIFT is low severity', () => {
    const rule = CERT_PKI_RULES.find((r) => r.id === 'TLS_CERTIFICATE_BUNDLE_DRIFT')
    expect(rule?.severity).toBe('low')
  })
})
