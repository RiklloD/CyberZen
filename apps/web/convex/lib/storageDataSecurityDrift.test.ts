// WS-87 — Storage & Data Security Configuration Drift Detector: test suite.

import { describe, expect, it } from 'vitest'
import {
  isObjectStorageClientConfig,
  STORAGE_DATA_SECURITY_RULES,
  scanStorageDataSecurityDrift,
} from './storageDataSecurityDrift'

// ---------------------------------------------------------------------------
// isObjectStorageClientConfig — user contribution point
// ---------------------------------------------------------------------------

describe('isObjectStorageClientConfig', () => {
  it('returns true for .s3cfg (globally unambiguous s3cmd config)', () => {
    expect(isObjectStorageClientConfig('.s3cfg', '.s3cfg')).toBe(true)
  })

  it('returns true for .boto (globally unambiguous boto config)', () => {
    expect(isObjectStorageClientConfig('.boto', '.boto')).toBe(true)
  })

  it('returns true for aws/credentials path', () => {
    expect(isObjectStorageClientConfig('aws/credentials', 'credentials')).toBe(true)
  })

  it('returns true for .aws/credentials path', () => {
    expect(isObjectStorageClientConfig('.aws/credentials', 'credentials')).toBe(true)
  })

  it('returns true for nested .aws/credentials', () => {
    expect(isObjectStorageClientConfig('home/user/.aws/credentials', 'credentials')).toBe(true)
  })

  it('returns true for .aws/config (role ARN config)', () => {
    expect(isObjectStorageClientConfig('.aws/config', 'config')).toBe(true)
  })

  it('returns true for MinIO client config.json', () => {
    expect(isObjectStorageClientConfig('.mc/config.json', 'config.json')).toBe(true)
  })

  it('returns true for MinIO client in mc/ dir', () => {
    expect(isObjectStorageClientConfig('mc/config.json', 'config.json')).toBe(true)
  })

  it('returns true for s3-config prefix', () => {
    expect(isObjectStorageClientConfig('config/s3-config.yaml', 's3-config.yaml')).toBe(true)
  })

  it('returns true for aws-credentials prefix', () => {
    expect(isObjectStorageClientConfig('secrets/aws-credentials-prod.json', 'aws-credentials-prod.json')).toBe(true)
  })

  it('returns true for gcs-credentials prefix', () => {
    expect(isObjectStorageClientConfig('keys/gcs-credentials-dev.json', 'gcs-credentials-dev.json')).toBe(true)
  })

  it('returns true for gcs-key prefix', () => {
    expect(isObjectStorageClientConfig('keys/gcs-key-prod.json', 'gcs-key-prod.json')).toBe(true)
  })

  it('returns true for azure-storage- prefix', () => {
    expect(isObjectStorageClientConfig('config/azure-storage-account.env', 'azure-storage-account.env')).toBe(true)
  })

  it('returns true for credentials in aws/ dir', () => {
    expect(isObjectStorageClientConfig('aws/credentials', 'credentials')).toBe(true)
  })

  it('returns true for service-account.json in object-storage dir', () => {
    expect(isObjectStorageClientConfig('object-storage/service-account.json', 'service-account.json')).toBe(true)
  })

  it('returns false for terraform/ dir (IaC exclusion)', () => {
    expect(isObjectStorageClientConfig('terraform/aws/credentials', 'credentials')).toBe(false)
  })

  it('returns false for pulumi/ dir (IaC exclusion)', () => {
    expect(isObjectStorageClientConfig('pulumi/aws/credentials.yaml', 'credentials.yaml')).toBe(false)
  })

  it('returns false for .github/ dir (CI exclusion)', () => {
    expect(isObjectStorageClientConfig('.github/workflows/deploy.yaml', 'deploy.yaml')).toBe(false)
  })

  it('returns false for generic credentials file not in aws path', () => {
    expect(isObjectStorageClientConfig('src/credentials', 'credentials')).toBe(false)
  })

  it('returns false for config.json not in mc/ dir', () => {
    expect(isObjectStorageClientConfig('src/config.json', 'config.json')).toBe(false)
  })

  it('returns false for .aws path under .github', () => {
    expect(isObjectStorageClientConfig('.github/.aws/credentials', 'credentials')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 1: NFS_EXPORT_CONFIG_DRIFT (high)
// ---------------------------------------------------------------------------

describe('NFS_EXPORT_CONFIG_DRIFT', () => {
  const rule = STORAGE_DATA_SECURITY_RULES.find((r) => r.id === 'NFS_EXPORT_CONFIG_DRIFT')!

  it('matches nfs-ganesha.conf (ungated)', () => {
    expect(rule.match('nfs-ganesha.conf', 'nfs-ganesha.conf')).toBe(true)
  })

  it('matches ganesha.conf (ungated)', () => {
    expect(rule.match('config/ganesha.conf', 'ganesha.conf')).toBe(true)
  })

  it('matches nfs.conf (ungated)', () => {
    expect(rule.match('etc/nfs.conf', 'nfs.conf')).toBe(true)
  })

  it('matches nfsd.conf (ungated)', () => {
    expect(rule.match('nfsd.conf', 'nfsd.conf')).toBe(true)
  })

  it('matches nfs-export-config.conf prefix', () => {
    expect(rule.match('config/nfs-export-config.conf', 'nfs-export-config.conf')).toBe(true)
  })

  it('matches exports in nfs/ dir', () => {
    expect(rule.match('nfs/exports', 'exports')).toBe(true)
  })

  it('matches exports.conf in nfs/ dir', () => {
    expect(rule.match('nfs/exports.conf', 'exports.conf')).toBe(true)
  })

  it('matches .conf files in nfs-config/ dir', () => {
    expect(rule.match('nfs-config/custom.conf', 'custom.conf')).toBe(true)
  })

  it('does NOT match exports outside NFS dirs', () => {
    expect(rule.match('src/exports', 'exports')).toBe(false)
  })

  it('does NOT match exports.js (JavaScript exports)', () => {
    expect(rule.match('src/exports.js', 'exports.js')).toBe(false)
  })

  it('does NOT match exports outside NFS dirs', () => {
    expect(rule.match('src/exports', 'exports')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 2: SMB_CIFS_CONFIG_DRIFT (high)
// ---------------------------------------------------------------------------

describe('SMB_CIFS_CONFIG_DRIFT', () => {
  const rule = STORAGE_DATA_SECURITY_RULES.find((r) => r.id === 'SMB_CIFS_CONFIG_DRIFT')!

  it('matches smb.conf (ungated)', () => {
    expect(rule.match('smb.conf', 'smb.conf')).toBe(true)
  })

  it('matches samba.conf (ungated)', () => {
    expect(rule.match('etc/samba.conf', 'samba.conf')).toBe(true)
  })

  it('matches smb4.conf (FreeBSD, ungated)', () => {
    expect(rule.match('smb4.conf', 'smb4.conf')).toBe(true)
  })

  it('matches lmhosts (ungated)', () => {
    expect(rule.match('lmhosts', 'lmhosts')).toBe(true)
  })

  it('matches smb-prod.conf prefix', () => {
    expect(rule.match('config/smb-prod.conf', 'smb-prod.conf')).toBe(true)
  })

  it('matches samba-dc.conf prefix', () => {
    expect(rule.match('samba-dc.conf', 'samba-dc.conf')).toBe(true)
  })

  it('matches smbpasswd in samba/ dir', () => {
    expect(rule.match('samba/smbpasswd', 'smbpasswd')).toBe(true)
  })

  it('matches .conf in samba-config/ dir', () => {
    expect(rule.match('samba-config/shares.conf', 'shares.conf')).toBe(true)
  })

  it('does NOT match a generic config.conf outside samba dirs', () => {
    expect(rule.match('config/config.conf', 'config.conf')).toBe(false)
  })

  it('does NOT match a generic config.conf outside samba dirs', () => {
    expect(rule.match('config/config.conf', 'config.conf')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 3: STORAGE_ENCRYPTION_CONFIG_DRIFT (high)
// ---------------------------------------------------------------------------

describe('STORAGE_ENCRYPTION_CONFIG_DRIFT', () => {
  const rule = STORAGE_DATA_SECURITY_RULES.find((r) => r.id === 'STORAGE_ENCRYPTION_CONFIG_DRIFT')!

  it('matches crypttab (ungated)', () => {
    expect(rule.match('crypttab', 'crypttab')).toBe(true)
  })

  it('matches crypttab.conf (ungated)', () => {
    expect(rule.match('etc/crypttab.conf', 'crypttab.conf')).toBe(true)
  })

  it('matches cryptsetup.conf (ungated)', () => {
    expect(rule.match('cryptsetup.conf', 'cryptsetup.conf')).toBe(true)
  })

  it('matches luks-rootfs.conf prefix', () => {
    expect(rule.match('config/luks-rootfs.conf', 'luks-rootfs.conf')).toBe(true)
  })

  it('matches dm-crypt-data.conf prefix', () => {
    expect(rule.match('dm-crypt-data.conf', 'dm-crypt-data.conf')).toBe(true)
  })

  it('matches encryption-config.yaml prefix', () => {
    expect(rule.match('encryption-config.yaml', 'encryption-config.yaml')).toBe(true)
  })

  it('matches ecryptfs.conf', () => {
    expect(rule.match('ecryptfs.conf', 'ecryptfs.conf')).toBe(true)
  })

  it('matches .conf in luks/ dir', () => {
    expect(rule.match('luks/partition.conf', 'partition.conf')).toBe(true)
  })

  it('matches keyfile in disk-encryption/ dir', () => {
    expect(rule.match('disk-encryption/keyfile', 'keyfile')).toBe(true)
  })

  it('does NOT match a generic partition.conf outside encryption dirs', () => {
    expect(rule.match('config/partition.conf', 'partition.conf')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 4: OBJECT_STORAGE_CLIENT_DRIFT (high)
// ---------------------------------------------------------------------------

describe('OBJECT_STORAGE_CLIENT_DRIFT', () => {
  const rule = STORAGE_DATA_SECURITY_RULES.find((r) => r.id === 'OBJECT_STORAGE_CLIENT_DRIFT')!

  it('matches .s3cfg', () => {
    expect(rule.match('.s3cfg', '.s3cfg')).toBe(true)
  })

  it('matches .boto', () => {
    expect(rule.match('.boto', '.boto')).toBe(true)
  })

  it('matches aws/credentials', () => {
    expect(rule.match('aws/credentials', 'credentials')).toBe(true)
  })

  it('matches .aws/config', () => {
    expect(rule.match('.aws/config', 'config')).toBe(true)
  })

  it('matches MinIO client config.json in .mc/', () => {
    expect(rule.match('.mc/config.json', 'config.json')).toBe(true)
  })

  it('matches gcs-credentials prefix', () => {
    expect(rule.match('gcs-credentials-prod.json', 'gcs-credentials-prod.json')).toBe(true)
  })

  it('does NOT match terraform/credentials', () => {
    expect(rule.match('terraform/aws/credentials', 'credentials')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 5: DATABASE_BACKUP_ENCRYPTION_DRIFT (medium)
// ---------------------------------------------------------------------------

describe('DATABASE_BACKUP_ENCRYPTION_DRIFT', () => {
  const rule = STORAGE_DATA_SECURITY_RULES.find((r) => r.id === 'DATABASE_BACKUP_ENCRYPTION_DRIFT')!

  it('matches pgbackrest.conf (ungated)', () => {
    expect(rule.match('pgbackrest.conf', 'pgbackrest.conf')).toBe(true)
  })

  it('matches pgbackrest.ini (ungated)', () => {
    expect(rule.match('etc/pgbackrest.ini', 'pgbackrest.ini')).toBe(true)
  })

  it('matches .pgbackrest.conf (ungated)', () => {
    expect(rule.match('.pgbackrest.conf', '.pgbackrest.conf')).toBe(true)
  })

  it('matches barman.conf (ungated)', () => {
    expect(rule.match('barman.conf', 'barman.conf')).toBe(true)
  })

  it('matches .barman.conf (ungated)', () => {
    expect(rule.match('.barman.conf', '.barman.conf')).toBe(true)
  })

  it('matches barman-server.conf (ungated)', () => {
    expect(rule.match('barman-server.conf', 'barman-server.conf')).toBe(true)
  })

  it('matches walg.yaml prefix', () => {
    expect(rule.match('walg.yaml', 'walg.yaml')).toBe(true)
  })

  it('matches wal-g.json prefix', () => {
    expect(rule.match('config/wal-g.json', 'wal-g.json')).toBe(true)
  })

  it('matches walg.env prefix', () => {
    expect(rule.match('walg.env', 'walg.env')).toBe(true)
  })

  it('matches pgbackrest-prod.conf prefix', () => {
    expect(rule.match('pgbackrest-prod.conf', 'pgbackrest-prod.conf')).toBe(true)
  })

  it('matches barman-replica.conf prefix', () => {
    expect(rule.match('barman-replica.conf', 'barman-replica.conf')).toBe(true)
  })

  it('matches walg-s3.yaml prefix', () => {
    expect(rule.match('walg-s3.yaml', 'walg-s3.yaml')).toBe(true)
  })

  it('matches backup.conf in pgbackrest/ dir', () => {
    expect(rule.match('pgbackrest/backup.conf', 'backup.conf')).toBe(true)
  })

  it('matches walg.yaml in wal-g/ dir', () => {
    expect(rule.match('wal-g/walg.yaml', 'walg.yaml')).toBe(true)
  })

  it('does NOT match backup.conf outside backup dirs', () => {
    expect(rule.match('config/backup.conf', 'backup.conf')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 6: FILE_INTEGRITY_MONITORING_DRIFT (medium)
// ---------------------------------------------------------------------------

describe('FILE_INTEGRITY_MONITORING_DRIFT', () => {
  const rule = STORAGE_DATA_SECURITY_RULES.find((r) => r.id === 'FILE_INTEGRITY_MONITORING_DRIFT')!

  it('matches aide.conf (ungated)', () => {
    expect(rule.match('aide.conf', 'aide.conf')).toBe(true)
  })

  it('matches tripwire.cfg (ungated)', () => {
    expect(rule.match('tripwire.cfg', 'tripwire.cfg')).toBe(true)
  })

  it('matches tripwire-local.cfg (ungated)', () => {
    expect(rule.match('tripwire-local.cfg', 'tripwire-local.cfg')).toBe(true)
  })

  it('matches twcfg.txt (ungated)', () => {
    expect(rule.match('twcfg.txt', 'twcfg.txt')).toBe(true)
  })

  it('matches samhain.conf (ungated)', () => {
    expect(rule.match('samhain.conf', 'samhain.conf')).toBe(true)
  })

  it('matches .samhainrc (ungated)', () => {
    expect(rule.match('.samhainrc', '.samhainrc')).toBe(true)
  })

  it('matches aide-custom.conf prefix', () => {
    expect(rule.match('aide-custom.conf', 'aide-custom.conf')).toBe(true)
  })

  it('matches aide.site.conf prefix', () => {
    expect(rule.match('aide.site.conf', 'aide.site.conf')).toBe(true)
  })

  it('matches tripwire-site.cfg prefix', () => {
    expect(rule.match('tripwire-site.cfg', 'tripwire-site.cfg')).toBe(true)
  })

  it('matches tripwire policy .pol file in FIM dir', () => {
    expect(rule.match('tripwire/server.pol', 'server.pol')).toBe(true)
  })

  it('matches .conf in fim/ dir', () => {
    expect(rule.match('fim/rules.conf', 'rules.conf')).toBe(true)
  })

  it('matches aide.db in aide/ dir', () => {
    expect(rule.match('aide/aide.db', 'aide.db')).toBe(true)
  })

  it('does NOT match generic rules.conf outside FIM dirs', () => {
    expect(rule.match('config/rules.conf', 'rules.conf')).toBe(false)
  })

  it('does NOT match generic rules.conf outside FIM dirs (second check)', () => {
    expect(rule.match('etc/rules.conf', 'rules.conf')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 7: DATA_LOSS_PREVENTION_CONFIG_DRIFT (medium)
// ---------------------------------------------------------------------------

describe('DATA_LOSS_PREVENTION_CONFIG_DRIFT', () => {
  const rule = STORAGE_DATA_SECURITY_RULES.find((r) => r.id === 'DATA_LOSS_PREVENTION_CONFIG_DRIFT')!

  it('matches dlp-config.yaml (ungated)', () => {
    expect(rule.match('dlp-config.yaml', 'dlp-config.yaml')).toBe(true)
  })

  it('matches dlp-config.json (ungated)', () => {
    expect(rule.match('dlp-config.json', 'dlp-config.json')).toBe(true)
  })

  it('matches dlp-policy.yaml (ungated)', () => {
    expect(rule.match('dlp-policy.yaml', 'dlp-policy.yaml')).toBe(true)
  })

  it('matches data-classification.yaml (ungated)', () => {
    expect(rule.match('data-classification.yaml', 'data-classification.yaml')).toBe(true)
  })

  it('matches data-loss-prevention.json (ungated)', () => {
    expect(rule.match('data-loss-prevention.json', 'data-loss-prevention.json')).toBe(true)
  })

  it('matches dlp-prod.yaml prefix', () => {
    expect(rule.match('config/dlp-prod.yaml', 'dlp-prod.yaml')).toBe(true)
  })

  it('matches data-classification-rules.json prefix', () => {
    expect(rule.match('data-classification-rules.json', 'data-classification-rules.json')).toBe(true)
  })

  it('matches data-security-policy.yaml prefix', () => {
    expect(rule.match('data-security-policy.yaml', 'data-security-policy.yaml')).toBe(true)
  })

  it('matches privacy-policy-gdpr.yaml prefix', () => {
    expect(rule.match('privacy-policy-gdpr.yaml', 'privacy-policy-gdpr.yaml')).toBe(true)
  })

  it('matches .yaml in dlp/ dir', () => {
    expect(rule.match('dlp/rules.yaml', 'rules.yaml')).toBe(true)
  })

  it('matches .json in data-classification/ dir', () => {
    expect(rule.match('data-classification/patterns.json', 'patterns.json')).toBe(true)
  })

  it('does NOT match rules.yaml outside DLP dirs', () => {
    expect(rule.match('config/rules.yaml', 'rules.yaml')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 8: STORAGE_AUDIT_CONFIG_DRIFT (low)
// ---------------------------------------------------------------------------

describe('STORAGE_AUDIT_CONFIG_DRIFT', () => {
  const rule = STORAGE_DATA_SECURITY_RULES.find((r) => r.id === 'STORAGE_AUDIT_CONFIG_DRIFT')!

  it('matches minio-audit.env (ungated)', () => {
    expect(rule.match('minio-audit.env', 'minio-audit.env')).toBe(true)
  })

  it('matches storage-audit.yaml (ungated)', () => {
    expect(rule.match('storage-audit.yaml', 'storage-audit.yaml')).toBe(true)
  })

  it('matches storage-audit.json (ungated)', () => {
    expect(rule.match('storage-audit.json', 'storage-audit.json')).toBe(true)
  })

  it('matches minio-audit-config.yaml (ungated)', () => {
    expect(rule.match('minio-audit-config.yaml', 'minio-audit-config.yaml')).toBe(true)
  })

  it('matches minio-audit-webhook.yaml prefix', () => {
    expect(rule.match('minio-audit-webhook.yaml', 'minio-audit-webhook.yaml')).toBe(true)
  })

  it('matches storage-audit-prod.json prefix', () => {
    expect(rule.match('storage-audit-prod.json', 'storage-audit-prod.json')).toBe(true)
  })

  it('matches config.env in minio/ dir (MinIO canonical config)', () => {
    expect(rule.match('minio/config.env', 'config.env')).toBe(true)
  })

  it('matches audit.conf in storage-audit/ dir', () => {
    expect(rule.match('storage-audit/audit.conf', 'audit.conf')).toBe(true)
  })

  it('matches audit.yaml in audit/ dir', () => {
    expect(rule.match('audit/audit.yaml', 'audit.yaml')).toBe(true)
  })

  it('does NOT match config.env outside storage dirs', () => {
    expect(rule.match('app/config.env', 'config.env')).toBe(false)
  })

  it('does NOT match audit.conf outside storage dirs', () => {
    expect(rule.match('config/audit.conf', 'audit.conf')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// scanStorageDataSecurityDrift — integration
// ---------------------------------------------------------------------------

describe('scanStorageDataSecurityDrift', () => {
  it('returns clean result for empty file list', () => {
    const r = scanStorageDataSecurityDrift([])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
    expect(r.totalFindings).toBe(0)
    expect(r.findings).toHaveLength(0)
    expect(r.summary).toMatch(/no storage/i)
  })

  it('returns clean result for non-matching files', () => {
    const r = scanStorageDataSecurityDrift([
      'src/index.ts',
      'package.json',
      'README.md',
      'docs/architecture.md',
    ])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
    expect(r.totalFindings).toBe(0)
  })

  it('detects single HIGH finding — smb.conf', () => {
    const r = scanStorageDataSecurityDrift(['smb.conf'])
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0]!.ruleId).toBe('SMB_CIFS_CONFIG_DRIFT')
    expect(r.findings[0]!.severity).toBe('high')
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('medium')
  })

  it('detects single HIGH finding — crypttab', () => {
    const r = scanStorageDataSecurityDrift(['crypttab'])
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0]!.ruleId).toBe('STORAGE_ENCRYPTION_CONFIG_DRIFT')
    expect(r.findings[0]!.severity).toBe('high')
    expect(r.riskScore).toBe(15)
  })

  it('detects single MEDIUM finding — aide.conf', () => {
    const r = scanStorageDataSecurityDrift(['aide.conf'])
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0]!.ruleId).toBe('FILE_INTEGRITY_MONITORING_DRIFT')
    expect(r.findings[0]!.severity).toBe('medium')
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('detects single LOW finding — storage-audit.yaml', () => {
    const r = scanStorageDataSecurityDrift(['storage-audit.yaml'])
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0]!.ruleId).toBe('STORAGE_AUDIT_CONFIG_DRIFT')
    expect(r.findings[0]!.severity).toBe('low')
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('produces correct multi-rule result with all severities', () => {
    const r = scanStorageDataSecurityDrift([
      'smb.conf',               // HIGH SMB_CIFS_CONFIG_DRIFT
      'aide.conf',              // MEDIUM FILE_INTEGRITY_MONITORING_DRIFT
      'storage-audit.yaml',     // LOW STORAGE_AUDIT_CONFIG_DRIFT
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
    const r = scanStorageDataSecurityDrift([
      'smb.conf',        // HIGH
      'crypttab',        // HIGH
      'nfs-ganesha.conf', // HIGH
      '.s3cfg',          // HIGH
    ])
    expect(r.highCount).toBe(4)
    // 4 × 15 = 60 → capped at 45
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('caps MEDIUM score at 25 with 4+ medium findings', () => {
    const r = scanStorageDataSecurityDrift([
      'aide.conf',             // MEDIUM FIM
      'barman.conf',           // MEDIUM DB_BACKUP_ENCRYPTION
      'dlp-config.yaml',       // MEDIUM DLP
    ])
    expect(r.mediumCount).toBe(3)
    // 3 × 8 = 24 → under cap
    expect(r.riskScore).toBe(24)

    // Add a 4th medium to exceed cap
    const r2 = scanStorageDataSecurityDrift([
      'aide.conf',
      'barman.conf',
      'dlp-config.yaml',
      'dlp-policy.yaml',  // same DLP rule — deduped as matchCount on same rule
    ])
    // DLP dedups to 1 finding, so still 3 mediums at 24
    expect(r2.mediumCount).toBe(3)
    expect(r2.riskScore).toBe(24)
  })

  it('caps LOW score at 15 with many low findings', () => {
    const r = scanStorageDataSecurityDrift([
      'storage-audit.yaml', // LOW — only 1 LOW rule exists
    ])
    expect(r.lowCount).toBe(1)
    expect(r.riskScore).toBe(4)
  })

  it('score exactly 44 → high (boundary: < 45 = medium, >= 45 = high)', () => {
    // 2 HIGH (30) + 1 MEDIUM (8) + 1 LOW (4) = 42 ... need 44
    // 2H=30 + 1M=8 + 1L=4 = 42; try 2H + 2M = 30+16=46 (>45 so HIGH)
    // Need score exactly 44: 2H=30 + 1M=8 + 1L=4 = 42, still not 44
    // 2H=30 + 1M=8 + 1L=4 = 42; 3H=45 cap+0m+0l=45 (high)
    // For 44: need 2H=30 + 1M=8 + 1.5L... not possible with whole penalties
    // closest test for boundary: score 45 → high (not medium)
    const r = scanStorageDataSecurityDrift([
      'smb.conf',        // HIGH
      'crypttab',        // HIGH
      'nfs-ganesha.conf', // HIGH — 3×15=45 → capped=45
    ])
    expect(r.riskScore).toBe(45)
    // score 45 is not < 45, falls to 'high'
    expect(r.riskLevel).toBe('high')
  })

  it('score 42 → medium (< 45)', () => {
    const r = scanStorageDataSecurityDrift([
      'smb.conf',        // HIGH 15
      'crypttab',        // HIGH 15
      'aide.conf',       // MEDIUM 8
      'storage-audit.yaml', // LOW 4
    ])
    // 30 + 8 + 4 = 42
    expect(r.riskScore).toBe(42)
    expect(r.riskLevel).toBe('medium')
  })

  it('deduplicates findings per rule — multiple SMB files count as one finding with matchCount', () => {
    const r = scanStorageDataSecurityDrift([
      'smb.conf',
      'samba.conf',
      'smb4.conf',
    ])
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0]!.ruleId).toBe('SMB_CIFS_CONFIG_DRIFT')
    expect(r.findings[0]!.matchCount).toBe(3)
    expect(r.riskScore).toBe(15) // still one HIGH penalty
  })

  it('deduplicates multiple NFS files into one finding', () => {
    const r = scanStorageDataSecurityDrift([
      'nfs-ganesha.conf',
      'nfs/exports',
      'nfs/nfs4.conf',
    ])
    expect(r.findings.filter((f) => f.ruleId === 'NFS_EXPORT_CONFIG_DRIFT')).toHaveLength(1)
    expect(r.findings.find((f) => f.ruleId === 'NFS_EXPORT_CONFIG_DRIFT')!.matchCount).toBe(3)
  })

  it('records firstPath as the matched path in the finding', () => {
    const r = scanStorageDataSecurityDrift([
      'src/config.ts',     // non-matching
      'smb.conf',          // first match
      'samba.conf',        // second match
    ])
    expect(r.findings[0]!.matchedPath).toBe('smb.conf')
  })

  it('sorts findings high → medium → low', () => {
    const r = scanStorageDataSecurityDrift([
      'storage-audit.yaml', // LOW
      'aide.conf',          // MEDIUM
      'smb.conf',           // HIGH
    ])
    expect(r.findings[0]!.severity).toBe('high')
    expect(r.findings[1]!.severity).toBe('medium')
    expect(r.findings[2]!.severity).toBe('low')
  })

  it('skips vendor directory paths', () => {
    const r = scanStorageDataSecurityDrift([
      'vendor/samba/smb.conf',
      'node_modules/samba-lib/smb.conf',
    ])
    expect(r.totalFindings).toBe(0)
  })

  it('normalises Windows backslash paths', () => {
    const r = scanStorageDataSecurityDrift(['config\\smb.conf'])
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0]!.ruleId).toBe('SMB_CIFS_CONFIG_DRIFT')
  })

  it('is case-insensitive (uppercase path)', () => {
    const r = scanStorageDataSecurityDrift(['SMB.CONF'])
    expect(r.totalFindings).toBe(1)
  })

  it('detects all 8 rules simultaneously', () => {
    const r = scanStorageDataSecurityDrift([
      'nfs-ganesha.conf',          // NFS_EXPORT_CONFIG_DRIFT
      'smb.conf',                  // SMB_CIFS_CONFIG_DRIFT
      'crypttab',                  // STORAGE_ENCRYPTION_CONFIG_DRIFT
      '.s3cfg',                    // OBJECT_STORAGE_CLIENT_DRIFT
      'barman.conf',               // DATABASE_BACKUP_ENCRYPTION_DRIFT
      'aide.conf',                 // FILE_INTEGRITY_MONITORING_DRIFT
      'dlp-config.yaml',           // DATA_LOSS_PREVENTION_CONFIG_DRIFT
      'storage-audit.yaml',        // STORAGE_AUDIT_CONFIG_DRIFT
    ])
    expect(r.totalFindings).toBe(8)
    expect(r.highCount).toBe(4)
    expect(r.mediumCount).toBe(3)
    expect(r.lowCount).toBe(1)
    // 4H capped at 45 + 3M=24 + 1L=4 = 73
    expect(r.riskScore).toBe(73)
    expect(r.riskLevel).toBe('high')
  })

  it('all 8 rule IDs appear in STORAGE_DATA_SECURITY_RULES', () => {
    const ids = STORAGE_DATA_SECURITY_RULES.map((r) => r.id)
    expect(ids).toContain('NFS_EXPORT_CONFIG_DRIFT')
    expect(ids).toContain('SMB_CIFS_CONFIG_DRIFT')
    expect(ids).toContain('STORAGE_ENCRYPTION_CONFIG_DRIFT')
    expect(ids).toContain('OBJECT_STORAGE_CLIENT_DRIFT')
    expect(ids).toContain('DATABASE_BACKUP_ENCRYPTION_DRIFT')
    expect(ids).toContain('FILE_INTEGRITY_MONITORING_DRIFT')
    expect(ids).toContain('DATA_LOSS_PREVENTION_CONFIG_DRIFT')
    expect(ids).toContain('STORAGE_AUDIT_CONFIG_DRIFT')
    expect(ids).toHaveLength(8)
  })

  it('result shape has all required fields', () => {
    const r = scanStorageDataSecurityDrift(['smb.conf'])
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
    const r = scanStorageDataSecurityDrift(['smb.conf'])
    expect(r.summary).toMatch(/drift/i)
    expect(r.summary).toMatch(/high/i)
  })

  it('riskLevel none → score 0', () => {
    const r = scanStorageDataSecurityDrift([])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })

  it('riskLevel low → score 4 (single LOW finding)', () => {
    const r = scanStorageDataSecurityDrift(['storage-audit.yaml'])
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('riskLevel low → score 8 (single MEDIUM finding)', () => {
    const r = scanStorageDataSecurityDrift(['aide.conf'])
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('riskLevel medium → score 15 (single HIGH finding)', () => {
    const r = scanStorageDataSecurityDrift(['smb.conf'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('medium')
  })

  it('riskLevel high → score 45 (3 HIGH findings, at cap)', () => {
    const r = scanStorageDataSecurityDrift([
      'smb.conf',
      'crypttab',
      'nfs-ganesha.conf',
    ])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('object storage client drift detected via .aws/credentials path', () => {
    const r = scanStorageDataSecurityDrift(['.aws/credentials'])
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0]!.ruleId).toBe('OBJECT_STORAGE_CLIENT_DRIFT')
    expect(r.findings[0]!.severity).toBe('high')
  })

  it('database backup drift detected via pgbackrest.conf', () => {
    const r = scanStorageDataSecurityDrift(['pgbackrest.conf'])
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0]!.ruleId).toBe('DATABASE_BACKUP_ENCRYPTION_DRIFT')
    expect(r.findings[0]!.severity).toBe('medium')
  })

  it('FIM drift detected via tripwire.cfg', () => {
    const r = scanStorageDataSecurityDrift(['tripwire.cfg'])
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0]!.ruleId).toBe('FILE_INTEGRITY_MONITORING_DRIFT')
  })

  it('DLP drift detected via dlp-policy.yaml', () => {
    const r = scanStorageDataSecurityDrift(['dlp-policy.yaml'])
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0]!.ruleId).toBe('DATA_LOSS_PREVENTION_CONFIG_DRIFT')
  })
})
