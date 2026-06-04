// WS-87 — Storage & Data Security Configuration Drift Detector:
// pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to storage daemon configuration, disk encryption settings, object storage
// client credentials, file integrity monitoring, and data-loss prevention
// policies.  A tampered NFS exports file can expose filesystem shares to
// unexpected hosts; a modified crypttab can bypass full-disk encryption; an
// altered AIDE config can hide attacker footprint from integrity checks.
//
// DISTINCT from:
//   WS-62  cloudSecurityDrift     — cloud IAM resource policies and S3/GCS/Azure
//                                   bucket ACLs (the resource-side); WS-87 covers
//                                   the storage daemon config and client credentials
//   WS-70  identityAccessDrift    — Vault access policies, LDAP server configs;
//                                   WS-87 covers storage-specific encryption and
//                                   FIM tooling, not IAM policy content
//   WS-71  observabilitySecurityDrift — log pipeline configs (Fluentd/Logstash);
//                                   WS-87 covers storage audit configuration
//   WS-85  backupDrSecurityDrift  — backup agent credentials (rclone.conf,
//                                   restic-password, borg passphrase, velero
//                                   credentials); WS-87 covers storage daemon
//                                   configs and encryption layer, not backup agents
//
// Covered rule groups (8 rules):
//
//   NFS_EXPORT_CONFIG_DRIFT          — NFS server exports (/etc/exports-style),
//                                      NFS Ganesha server configuration
//   SMB_CIFS_CONFIG_DRIFT            — Samba / SMB server configuration (smb.conf,
//                                      samba.conf, FreeBSD smb4.conf)
//   STORAGE_ENCRYPTION_CONFIG_DRIFT  — Disk encryption configuration: crypttab
//                                      (LUKS device map), dm-crypt, eCryptfs
//   OBJECT_STORAGE_CLIENT_DRIFT      — Object storage client credentials and config:
//                                      AWS credentials (~/.aws/credentials),
//                                      s3cmd config (.s3cfg), MinIO client config
//   DATABASE_BACKUP_ENCRYPTION_DRIFT — Database backup tool encryption settings:
//                                      pgbackrest.conf (PostgreSQL PITR), barman.conf
//                                      (Barman backup manager), wal-g config
//   FILE_INTEGRITY_MONITORING_DRIFT  — FIM tool configuration: AIDE (Advanced
//                                      Intrusion Detection Environment), Tripwire,
//                                      Samhain; FIM config tampering hides attacker
//                                      modifications from integrity checks
//   DATA_LOSS_PREVENTION_CONFIG_DRIFT — DLP policy, data-classification and
//                                      privacy policy configuration
//   STORAGE_AUDIT_CONFIG_DRIFT       — Storage access audit log configuration:
//                                      MinIO audit webhook, object-storage audit
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Vendor directory exclusion applied to all paths.
//   • Same penalty/cap scoring model as WS-60–86 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (firstPath + matchCount).
//   • crypttab is globally unambiguous (Linux LUKS device mapping) — ungated.
//   • smb.conf/samba.conf are globally unambiguous Samba names — ungated.
//   • pgbackrest.conf/barman.conf are globally unambiguous pg-backup names.
//   • aide.conf/tripwire.cfg/samhain.conf are globally unambiguous FIM names.
//   • Generic names (exports, config.env) are gated on tool-specific directories.
//   • All ungated Set entries stored lowercase (lesson from WS-83).
//
// Exports:
//   isObjectStorageClientConfig    — user contribution point (see JSDoc below)
//   STORAGE_DATA_SECURITY_RULES    — readonly rule registry
//   scanStorageDataSecurityDrift   — main scanner, returns StorageDataSecurityDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type StorageDataSecurityRuleId =
  | 'NFS_EXPORT_CONFIG_DRIFT'
  | 'SMB_CIFS_CONFIG_DRIFT'
  | 'STORAGE_ENCRYPTION_CONFIG_DRIFT'
  | 'OBJECT_STORAGE_CLIENT_DRIFT'
  | 'DATABASE_BACKUP_ENCRYPTION_DRIFT'
  | 'FILE_INTEGRITY_MONITORING_DRIFT'
  | 'DATA_LOSS_PREVENTION_CONFIG_DRIFT'
  | 'STORAGE_AUDIT_CONFIG_DRIFT'

export type StorageDataSecuritySeverity = 'high' | 'medium' | 'low'
export type StorageDataSecurityRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type StorageDataSecurityDriftFinding = {
  ruleId: StorageDataSecurityRuleId
  severity: StorageDataSecuritySeverity
  matchedPath: string
  matchCount: number
  description: string
  recommendation: string
}

export type StorageDataSecurityDriftResult = {
  riskScore: number
  riskLevel: StorageDataSecurityRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: StorageDataSecurityDriftFinding[]
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

const NFS_DIRS          = ['nfs/', 'nfs-config/', 'nfs-exports/', 'etc/nfs/', 'exports.d/', 'ganesha/']
const SAMBA_DIRS        = ['samba/', 'smb/', 'samba-config/', 'cifs/', 'windows-shares/', 'fileserver/']
const ENCRYPTION_DIRS   = ['encryption/', 'luks/', 'dm-crypt/', 'crypto/', 'disk-encryption/', 'full-disk-encryption/', 'ecryptfs/']
const OBJECT_STORAGE_DIRS = ['aws/', '.aws/', 'gcloud/', '.config/gcloud/', 'azure/', 'minio/', 'object-storage/', 'cloud-storage/']
const WALG_DIRS         = ['wal-g/', 'walg/', 'wal_g/', 'postgres-backup/', 'pg-backup/', 'barman/', 'barman-config/', 'pgbackrest/', 'pgbackrest-config/']
const FIM_DIRS          = ['aide/', '.aide/', 'tripwire/', 'tripwire-config/', 'samhain/', 'fim/', 'integrity/']
const DLP_DIRS          = ['dlp/', 'data-loss-prevention/', 'data-classification/', 'data-security/', 'privacy/', 'data-governance/']
const STORAGE_AUDIT_DIRS = ['minio/', 'minio-config/', 'storage-audit/', 'object-storage/', 'data-audit/', 'audit/']
const MC_DIRS           = ['.mc/', 'mc/', 'minio-client/']

function inAnyDir(pathLower: string, dirs: readonly string[]): boolean {
  return dirs.some((d) => pathLower.includes(d))
}

// ---------------------------------------------------------------------------
// Rule 1: NFS_EXPORT_CONFIG_DRIFT (high)
// NFS server exports and NFS Ganesha configuration
// ---------------------------------------------------------------------------

const NFS_UNGATED = new Set([
  'nfs-ganesha.conf', // NFS Ganesha server config — globally unambiguous
  'ganesha.conf',     // NFS Ganesha shorthand — globally unambiguous
  'nfs.conf',         // modern Linux NFS config file at /etc/nfs.conf
  'nfsd.conf',        // BSD NFS daemon config
])

function isNfsExportConfig(pathLower: string, base: string): boolean {
  if (NFS_UNGATED.has(base)) return true

  // NFS Ganesha export config (EXPORT block files)
  if (base.startsWith('nfs-') && base.endsWith('.conf')) return true
  if (base.startsWith('nfs-export-') && (base.endsWith('.conf') || base.endsWith('.yaml'))) return true
  if (base.startsWith('ganesha-') && base.endsWith('.conf')) return true

  // exports / exports.d entries — gated on NFS dirs to avoid other 'exports' files
  if ((base === 'exports' || base === 'exports.conf') && inAnyDir(pathLower, NFS_DIRS)) return true

  if (!inAnyDir(pathLower, NFS_DIRS)) return false

  if (base.endsWith('.conf') || base.endsWith('.export') || base === 'exports') return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 2: SMB_CIFS_CONFIG_DRIFT (high)
// Samba / SMB server configuration
// ---------------------------------------------------------------------------

const SMB_UNGATED = new Set([
  'smb.conf',    // Samba main config — globally unambiguous
  'samba.conf',  // alternative Samba config name — globally unambiguous
  'smb4.conf',   // FreeBSD Samba4 — globally unambiguous
  'lmhosts',     // Samba NetBIOS host mapping — globally unambiguous
])

function isSmbCifsConfig(pathLower: string, base: string): boolean {
  if (SMB_UNGATED.has(base)) return true

  // Samba config prefix patterns
  if (base.startsWith('smb-') && base.endsWith('.conf')) return true
  if (base.startsWith('samba-') && base.endsWith('.conf')) return true

  if (!inAnyDir(pathLower, SAMBA_DIRS)) return false

  // Common Samba config files gated on samba dirs
  if (
    base === 'secrets.tdb' || base === 'passdb.tdb' ||
    base === 'smbpasswd'   || base === 'pdbedit.conf' ||
    base.endsWith('.conf') || base.endsWith('.tdb')
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 3: STORAGE_ENCRYPTION_CONFIG_DRIFT (high)
// Disk encryption configuration: LUKS crypttab, dm-crypt, eCryptfs
// ---------------------------------------------------------------------------

const ENCRYPTION_UNGATED = new Set([
  'crypttab',      // LUKS device mapping to passphrase — globally unambiguous
  'crypttab.conf', // variant with explicit extension
  'cryptsetup.conf',
])

function isStorageEncryptionConfig(pathLower: string, base: string): boolean {
  if (ENCRYPTION_UNGATED.has(base)) return true

  // LUKS / dm-crypt prefix patterns
  if (base.startsWith('luks-') && base.endsWith('.conf')) return true
  if (base.startsWith('dm-crypt-') && base.endsWith('.conf')) return true
  if (base.startsWith('cryptsetup-') && base.endsWith('.conf')) return true
  if (base.startsWith('encryption-') && (base.endsWith('.conf') || base.endsWith('.yaml'))) return true

  // eCryptfs configuration files
  if (base === 'ecryptfs.conf' || base === '.ecryptfs' || base === 'Private.mnt') return true

  if (!inAnyDir(pathLower, ENCRYPTION_DIRS)) return false

  if (base.endsWith('.conf') || base.endsWith('.yaml') || base.endsWith('.key') || base === 'keyfile') return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 4: OBJECT_STORAGE_CLIENT_DRIFT (high)
// Object storage client credentials and configuration
// ---------------------------------------------------------------------------

/**
 * Returns true if the given path is an object storage client credentials or
 * configuration file.
 *
 * CONTRIBUTION POINT — implement the core detection logic here.
 *
 * Constraints to respect:
 *   • Exclude IaC tool directories (terraform/, pulumi/, cdk/, cloudformation/)
 *     to avoid false positives on Terraform provider config files that reference
 *     AWS/GCS identically named resources.
 *   • Exclude CI/CD config directories (.github/, .gitlab/, .circleci/, .buildkite/)
 *     since pipeline yamls reference credential *names*, not actual credential files.
 *   • .s3cfg and .boto are globally unambiguous s3cmd/boto configuration files
 *     containing access keys — always return true for these.
 *   • AWS credentials files live at .aws/credentials or aws/credentials in a
 *     repo; match when base === 'credentials' and path contains /aws/ or /.aws/.
 *   • AWS config file at .aws/config may contain role ARNs and output format;
 *     match when base === 'config' and path contains '/.aws/'.
 *   • MinIO client config at .mc/config.json or mc/config.json.
 *   • s3-config*, aws-credentials*, gcs-credentials*, azure-storage-* prefix
 *     patterns in object storage directories.
 *
 * @param pathLower Normalised (lowercase, forward-slash) file path from repo root.
 * @param base Basename extracted from pathLower (already lowercase).
 * @returns true if this file is an object storage client credentials or config file.
 */
export function isObjectStorageClientConfig(pathLower: string, base: string): boolean {
  // Exclude IaC tool directories — these contain Terraform/CDK references, not real creds
  if (
    pathLower.includes('terraform/')    ||
    pathLower.includes('pulumi/')       ||
    pathLower.includes('cdk/')          ||
    pathLower.includes('cloudformation/')
  ) return false

  // Exclude CI/CD config directories
  if (
    pathLower.includes('.github/')    ||
    pathLower.includes('.gitlab/')    ||
    pathLower.includes('.circleci/')  ||
    pathLower.includes('.buildkite/')
  ) return false

  // Globally unambiguous s3cmd / boto configuration files
  if (base === '.s3cfg' || base === '.boto') return true

  // AWS credentials file (.aws/credentials or aws/credentials at any depth)
  if (base === 'credentials' && (pathLower.includes('/.aws/') || pathLower.includes('/aws/') || pathLower.startsWith('.aws/') || pathLower.startsWith('aws/'))) return true

  // AWS config file in .aws directory
  if (base === 'config' && (pathLower.includes('/.aws/') || pathLower.startsWith('.aws/'))) return true

  // MinIO client config
  if (base === 'config.json' && inAnyDir(pathLower, MC_DIRS)) return true

  // Object storage credential prefix patterns
  if (
    base.startsWith('s3-config') ||
    base.startsWith('aws-credentials') ||
    base.startsWith('gcs-credentials') ||
    base.startsWith('gcs-key') ||
    base.startsWith('azure-storage-') ||
    base.startsWith('cloud-credentials')
  ) return true

  if (!inAnyDir(pathLower, OBJECT_STORAGE_DIRS)) return false

  // Config / credentials files in object storage directories
  if (
    base === 'credentials'       || base === 'config'          ||
    base === 'service-account.json' || base.endsWith('-key.json') ||
    base.endsWith('.credentials') || base.endsWith('.keyfile')  ||
    base.endsWith('.json')       || base.endsWith('.env')
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 5: DATABASE_BACKUP_ENCRYPTION_DRIFT (medium)
// Database backup tool encryption and repository configuration
// ---------------------------------------------------------------------------

const DB_BACKUP_UNGATED = new Set([
  'pgbackrest.conf',      // pgBackRest PostgreSQL backup — globally unambiguous
  'pgbackrest.ini',       // ini variant
  '.pgbackrest.conf',     // user-home variant
  'barman.conf',          // Barman backup manager — globally unambiguous
  '.barman.conf',         // user-home Barman config
  'barman-server.conf',   // Barman server-specific config
])

function isDatabaseBackupEncryptionConfig(pathLower: string, base: string): boolean {
  if (DB_BACKUP_UNGATED.has(base)) return true

  // wal-g (WAL-G PostgreSQL backup) prefix patterns
  if (
    base.startsWith('walg') && (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json') || base.endsWith('.env'))
  ) return true
  if (
    base.startsWith('wal-g') && (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json') || base.endsWith('.env'))
  ) return true

  // pgbackrest prefix pattern
  if (base.startsWith('pgbackrest-') && (base.endsWith('.conf') || base.endsWith('.ini'))) return true

  // Barman server config prefix
  if (base.startsWith('barman-') && base.endsWith('.conf')) return true

  if (!inAnyDir(pathLower, WALG_DIRS)) return false

  if (
    base === 'walg.yaml'    || base === 'walg.yml'    || base === 'walg.json' ||
    base === 'wal-g.yaml'   || base === 'wal-g.json'  ||
    base === 'walg.env'     || base === 'backup.conf' ||
    base.endsWith('.conf')  || base.endsWith('.yaml')  || base.endsWith('.env')
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 6: FILE_INTEGRITY_MONITORING_DRIFT (medium)
// AIDE, Tripwire, Samhain file integrity monitoring configuration
// ---------------------------------------------------------------------------

const FIM_UNGATED = new Set([
  'aide.conf',           // AIDE main configuration — globally unambiguous
  'aide.conf.d',         // AIDE conf.d include directory marker
  'tripwire.cfg',        // Tripwire main config — globally unambiguous
  'tripwire-local.cfg',  // Tripwire site-specific config — globally unambiguous
  'twcfg.txt',           // Tripwire text-format config
  'samhain.conf',        // Samhain IDS config — globally unambiguous
  '.samhainrc',          // Samhain user config
])

function isFimConfig(pathLower: string, base: string): boolean {
  if (FIM_UNGATED.has(base)) return true

  // AIDE prefix patterns and directory include files
  if (base.startsWith('aide-') && (base.endsWith('.conf') || base.endsWith('.rules'))) return true
  if (base.startsWith('aide.') && base.endsWith('.conf')) return true

  // Tripwire policy/config prefix patterns
  if (base.startsWith('tripwire-') && (base.endsWith('.cfg') || base.endsWith('.pol') || base.endsWith('.txt'))) return true
  if (base.endsWith('.pol') && inAnyDir(pathLower, FIM_DIRS)) return true

  // Samhain prefix patterns
  if (base.startsWith('samhain') && base.endsWith('.conf')) return true

  if (!inAnyDir(pathLower, FIM_DIRS)) return false

  if (
    base === 'aide.db'      || base === 'aide.db.new'  ||
    base === 'twdb.dat'     || base === 'twpol.txt'    ||
    base.endsWith('.conf')  || base.endsWith('.cfg')   ||
    base.endsWith('.rules') || base.endsWith('.pol')
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 7: DATA_LOSS_PREVENTION_CONFIG_DRIFT (medium)
// DLP policy and data classification configuration
// ---------------------------------------------------------------------------

const DLP_UNGATED = new Set([
  'dlp-config.yaml',
  'dlp-config.json',
  'dlp-policy.yaml',
  'dlp-policy.json',
  'data-classification.yaml',
  'data-classification.json',
  'data-loss-prevention.yaml',
  'data-loss-prevention.json',
])

function isDlpConfig(pathLower: string, base: string): boolean {
  if (DLP_UNGATED.has(base)) return true

  // DLP / data classification prefix patterns
  if (base.startsWith('dlp-') && (base.endsWith('.yaml') || base.endsWith('.json') || base.endsWith('.conf'))) return true
  if (base.startsWith('data-classification-') && (base.endsWith('.yaml') || base.endsWith('.json'))) return true
  if (base.startsWith('data-security-') && (base.endsWith('.yaml') || base.endsWith('.json'))) return true
  if (base.startsWith('privacy-policy-') && (base.endsWith('.yaml') || base.endsWith('.json'))) return true

  if (!inAnyDir(pathLower, DLP_DIRS)) return false

  if (
    base.endsWith('.yaml') || base.endsWith('.yml') ||
    base.endsWith('.json') || base.endsWith('.conf') ||
    base.endsWith('.xml')
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 8: STORAGE_AUDIT_CONFIG_DRIFT (low)
// Storage access audit log and audit webhook configuration
// ---------------------------------------------------------------------------

const STORAGE_AUDIT_UNGATED = new Set([
  'minio-audit.env',    // MinIO audit webhook env config
  'storage-audit.yaml',
  'storage-audit.json',
  'minio-audit-config.yaml',
  'minio-audit-config.json',
])

function isStorageAuditConfig(pathLower: string, base: string): boolean {
  if (STORAGE_AUDIT_UNGATED.has(base)) return true

  // MinIO / object-storage audit prefix patterns
  if (base.startsWith('minio-audit-') && (base.endsWith('.yaml') || base.endsWith('.json') || base.endsWith('.env'))) return true
  if (base.startsWith('storage-audit-') && (base.endsWith('.yaml') || base.endsWith('.json'))) return true
  if (base.startsWith('object-storage-audit-') && (base.endsWith('.yaml') || base.endsWith('.json'))) return true

  if (!inAnyDir(pathLower, STORAGE_AUDIT_DIRS)) return false

  // MinIO canonical config file (contains MINIO_AUDIT_WEBHOOK_* vars)
  if (base === 'config.env') return true
  if (base === 'audit.conf' || base === 'audit.yaml' || base === 'audit.json') return true

  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

type StorageDataSecurityRule = {
  id: StorageDataSecurityRuleId
  severity: StorageDataSecuritySeverity
  match: (pathLower: string, base: string) => boolean
  description: string
  recommendation: string
}

export const STORAGE_DATA_SECURITY_RULES: readonly StorageDataSecurityRule[] = [
  {
    id: 'NFS_EXPORT_CONFIG_DRIFT',
    severity: 'high',
    match: isNfsExportConfig,
    description: 'NFS server export configuration was modified. Changes to /etc/exports or NFS Ganesha config can expose filesystem shares to unintended hosts.',
    recommendation: 'Review NFS export permissions and host-access lists. Ensure no_root_squash is not used unnecessarily and exports are restricted to specific client CIDRs.',
  },
  {
    id: 'SMB_CIFS_CONFIG_DRIFT',
    severity: 'high',
    match: isSmbCifsConfig,
    description: 'Samba/SMB server configuration was modified. Changes to smb.conf can alter share permissions, authentication requirements, and guest access settings.',
    recommendation: 'Audit share definitions, valid users, and security mode settings. Ensure guest access is disabled and SMB signing is enforced.',
  },
  {
    id: 'STORAGE_ENCRYPTION_CONFIG_DRIFT',
    severity: 'high',
    match: isStorageEncryptionConfig,
    description: 'Disk encryption configuration (crypttab, LUKS, dm-crypt) was modified. Changes can disable or weaken full-disk encryption on production systems.',
    recommendation: 'Verify that crypttab entries use strong cipher settings (aes-xts-plain64), that keyfiles are stored securely, and that no volumes have been quietly removed from the encryption map.',
  },
  {
    id: 'OBJECT_STORAGE_CLIENT_DRIFT',
    severity: 'high',
    match: isObjectStorageClientConfig,
    description: 'Object storage client credentials or configuration was modified. AWS credentials files, s3cmd configs, or MinIO client configs store access keys that grant broad cloud storage access.',
    recommendation: 'Rotate any committed credentials immediately. Use IAM roles or workload identity federation instead of static access keys. Ensure credential files are in .gitignore.',
  },
  {
    id: 'DATABASE_BACKUP_ENCRYPTION_DRIFT',
    severity: 'medium',
    match: isDatabaseBackupEncryptionConfig,
    description: 'Database backup tool configuration (pgBackRest, Barman, wal-g) was modified. Changes can disable backup encryption, alter retention policies, or expose backup repository credentials.',
    recommendation: 'Verify encryption settings (repo-cipher-type, compress-type), retention policy values, and that repository credentials are not hardcoded in config files.',
  },
  {
    id: 'FILE_INTEGRITY_MONITORING_DRIFT',
    severity: 'medium',
    match: isFimConfig,
    description: 'File integrity monitoring configuration (AIDE, Tripwire, Samhain) was modified. Attackers modify FIM configs to exclude their tools from integrity checks, creating a blind spot.',
    recommendation: 'Review changes to monitored paths and exclusion rules. Ensure the FIM database (aide.db) is stored read-only or off-system. Validate that critical system directories remain monitored.',
  },
  {
    id: 'DATA_LOSS_PREVENTION_CONFIG_DRIFT',
    severity: 'medium',
    match: isDlpConfig,
    description: 'Data loss prevention or data classification policy configuration was modified. Changes can reduce the scope of monitored sensitive data or disable DLP enforcement rules.',
    recommendation: 'Review changes to data classification labels, detection patterns, and enforcement actions. Ensure regulatory-required data categories (PII, PCI, PHI) remain in scope.',
  },
  {
    id: 'STORAGE_AUDIT_CONFIG_DRIFT',
    severity: 'low',
    match: isStorageAuditConfig,
    description: 'Storage access audit configuration (MinIO audit webhook, object storage audit log) was modified. Changes can disable audit trails for data access.',
    recommendation: 'Verify audit webhook endpoints are still configured and reachable, and that audit log retention meets compliance requirements.',
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

function computeRiskScore(findings: StorageDataSecurityDriftFinding[]): number {
  let highRaw = 0, mediumRaw = 0, lowRaw = 0
  for (const f of findings) {
    if (f.severity === 'high')   highRaw   += HIGH_PENALTY
    if (f.severity === 'medium') mediumRaw += MEDIUM_PENALTY
    if (f.severity === 'low')    lowRaw    += LOW_PENALTY
  }
  return Math.min(100, Math.min(highRaw, HIGH_CAP) + Math.min(mediumRaw, MEDIUM_CAP) + Math.min(lowRaw, LOW_CAP))
}

function computeRiskLevel(score: number): StorageDataSecurityRiskLevel {
  if (score === 0)   return 'none'
  if (score < 15)   return 'low'
  if (score < 45)   return 'medium'
  if (score < 80)   return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

export function scanStorageDataSecurityDrift(changedFiles: string[]): StorageDataSecurityDriftResult {
  const findings: StorageDataSecurityDriftFinding[] = []

  for (const rule of STORAGE_DATA_SECURITY_RULES) {
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
    summary = 'No storage or data security configuration drift detected.'
  } else {
    const parts: string[] = []
    if (highCount > 0)   parts.push(`${highCount} high`)
    if (mediumCount > 0) parts.push(`${mediumCount} medium`)
    if (lowCount > 0)    parts.push(`${lowCount} low`)
    summary = `Storage & data security drift detected: ${parts.join(', ')} severity finding${findings.length !== 1 ? 's' : ''} across ${findings.length} rule${findings.length !== 1 ? 's' : ''} (risk score ${riskScore}/100).`
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
