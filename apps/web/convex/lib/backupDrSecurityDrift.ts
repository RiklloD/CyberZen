// WS-85 — Backup & Disaster Recovery Security Configuration Drift Detector:
// pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to backup agent, cloud sync, and disaster recovery security configuration
// files.  A modified rclone.conf exposes credentials for every cloud storage
// provider in one file; a changed Restic password file or BorgBackup passphrase
// makes every backup archive readable; a rotated Bacula Director config can
// redirect restores to an attacker-controlled server.
//
// DISTINCT from:
//   WS-62  cloudSecurityDrift     — cloud-wide IAM/KMS and S3/GCS bucket
//                                   policies; WS-85 covers the backup agent
//                                   credentials used to reach those buckets
//   WS-66  certPkiDrift           — TLS certificate lifecycle, Let's Encrypt;
//                                   WS-85 covers backup-specific encryption
//                                   keys and passphrases
//   WS-68  networkFirewallDrift   — iptables/UFW firewall rules; WS-85 covers
//                                   the backup daemon network configuration
//   WS-83  cfgMgmtSecurityDrift   — Ansible/Chef/Puppet/SaltStack toolchain;
//                                   WS-85 covers the backup toolchain itself
//
// Covered rule groups (8 rules):
//
//   RCLONE_CONFIG_DRIFT             — rclone.conf stores credentials for every
//                                     cloud provider in one file (S3, GCS,
//                                     Azure Blob, OneDrive, Dropbox, B2, etc.)
//   RESTIC_BACKUP_DRIFT             — Restic password files and repository
//                                     configuration (password exposes all
//                                     backup data)
//   BORGBACKUP_DRIFT                — BorgBackup passphrase and borgmatic YAML
//                                     configs (passphrase = all-or-nothing
//                                     repository access)
//   BACKUP_ENCRYPTION_CREDENTIAL_DRIFT — Generic backup-specific encryption
//                                     keys and passphrases in backup dirs
//                                     (user contribution — see
//                                     isBackupEncryptionCredential)
//   RSYNC_DAEMON_DRIFT              — rsyncd.conf daemon configuration and
//                                     rsyncd.secrets username/password file
//   ENTERPRISE_BACKUP_DRIFT         — Bacula Director/File/Storage daemon
//                                     configs and Amanda backup server configs
//   CLOUD_BACKUP_AGENT_DRIFT        — Velero Kubernetes backup, Duplicati, and
//                                     Duplicity encrypted cloud backup configs
//   BACKUP_SCRIPT_DRIFT             — Backup shell scripts in backup dirs
//                                     (frequently contain hardcoded credentials)
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Vendor directory exclusion applied to all paths.
//   • Same penalty/cap scoring model as WS-60–84 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (firstPath + matchCount).
//   • rclone.conf/.rclone.conf are globally unambiguous (rclone tool name in
//     filename).
//   • restic-password / .restic-password / borgpassphrase are explicitly named
//     for their tools and match ungated.
//   • borgmatic.yaml is globally unambiguous — borgmatic is the canonical
//     borgbackup management wrapper.
//   • rsyncd.conf / rsyncd.secrets are the rsync daemon's specific config and
//     credentials file names — globally unambiguous.
//   • bacula-dir.conf / bacula-fd.conf / bacula-sd.conf are Bacula-specific
//     daemon config filenames — globally unambiguous.
//   • Generic backup encryption credentials (.gpg/.asc/.key in backup dirs)
//     handled by user contribution isBackupEncryptionCredential to avoid
//     over-matching general key material.
//
// Exports:
//   isBackupEncryptionCredential  — user contribution point (see JSDoc below)
//   BACKUP_DR_SECURITY_RULES      — readonly rule registry
//   scanBackupDrSecurityDrift     — main scanner, returns BackupDrSecurityDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type BackupDrSecurityRuleId =
  | 'RCLONE_CONFIG_DRIFT'
  | 'RESTIC_BACKUP_DRIFT'
  | 'BORGBACKUP_DRIFT'
  | 'BACKUP_ENCRYPTION_CREDENTIAL_DRIFT'
  | 'RSYNC_DAEMON_DRIFT'
  | 'ENTERPRISE_BACKUP_DRIFT'
  | 'CLOUD_BACKUP_AGENT_DRIFT'
  | 'BACKUP_SCRIPT_DRIFT'

export type BackupDrSecuritySeverity = 'high' | 'medium' | 'low'
export type BackupDrSecurityRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type BackupDrSecurityDriftFinding = {
  ruleId: BackupDrSecurityRuleId
  severity: BackupDrSecuritySeverity
  matchedPath: string
  matchCount: number
  description: string
  recommendation: string
}

export type BackupDrSecurityDriftResult = {
  riskScore: number
  riskLevel: BackupDrSecurityRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: BackupDrSecurityDriftFinding[]
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

const RCLONE_DIRS    = ['rclone/', '.rclone/', 'backup/rclone/', 'rclone-config/']
const RESTIC_DIRS    = ['restic/', '.restic/', 'backup/restic/', 'restic-backup/', 'restic-config/']
const BORG_DIRS      = ['borg/', '.borg/', 'borgbackup/', 'borgmatic/', 'backup/borg/', 'borg-config/']
const RSYNC_DIRS     = ['rsync/', 'rsync-config/', 'backup/rsync/']
const BACULA_DIRS    = ['bacula/', '.bacula/', 'bacula-config/']
const AMANDA_DIRS    = ['amanda/', '.amanda/', 'amanda-config/']
const VELERO_DIRS    = ['velero/', '.velero/', 'velero-config/']
const DUPLICITY_DIRS = ['duplicity/', '.duplicity/', 'duplicati/', '.duplicati/']
const BACKUP_CRED_DIRS = ['backup/', 'backups/', 'backup-config/', '.backup/', 'restic/', 'borg/', 'borgmatic/', '.duplicity/', 'rclone/', '.rclone/']
const BACKUP_SCRIPT_DIRS = ['backup/', 'backups/', 'backup-scripts/', 'backup/scripts/', 'scripts/backup/']

function inAnyDir(pathLower: string, dirs: readonly string[]): boolean {
  return dirs.some((d) => pathLower.includes(d))
}

// ---------------------------------------------------------------------------
// Rule 1: RCLONE_CONFIG_DRIFT (high)
// rclone.conf stores credentials for every configured cloud provider
// ---------------------------------------------------------------------------

const RCLONE_UNGATED = new Set([
  'rclone.conf',   // rclone canonical configuration — globally unambiguous
  '.rclone.conf',  // Dot-prefixed variant (common in $HOME)
])

function isRcloneConfig(pathLower: string, base: string): boolean {
  if (RCLONE_UNGATED.has(base)) return true
  if (base.startsWith('rclone-') && base.endsWith('.conf')) return true  // rclone-prod.conf, rclone-s3.conf

  if (!inAnyDir(pathLower, RCLONE_DIRS)) return false

  if (base === 'config' || base.endsWith('.conf') || base === '.env') return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 2: RESTIC_BACKUP_DRIFT (high)
// Restic password files and repository configuration
// ---------------------------------------------------------------------------

const RESTIC_UNGATED = new Set([
  'restic-password',          // Explicit password file — globally unambiguous
  'restic-password.txt',      // Text variant
  '.restic-password',         // Dot-prefixed variant
  'restic-password-file',     // Canonical --password-file argument target
  'restic.conf',              // Restic configuration file
])

function isResticConfig(pathLower: string, base: string): boolean {
  if (RESTIC_UNGATED.has(base)) return true
  if (base.startsWith('restic-') && (base.endsWith('.conf') || base.endsWith('.toml') || base.endsWith('.yaml'))) return true

  if (!inAnyDir(pathLower, RESTIC_DIRS)) return false

  if (
    base === 'password'     || base === 'password.txt'  ||
    base === 'repository'   || base === 'exclude'        ||
    base === 'include'      || base.endsWith('.conf')   ||
    base.endsWith('.toml')  || base === '.env'
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 3: BORGBACKUP_DRIFT (high)
// BorgBackup passphrase and borgmatic YAML configuration
// ---------------------------------------------------------------------------

const BORG_UNGATED = new Set([
  'borgmatic.yaml',    // borgmatic canonical config — globally unambiguous
  'borgmatic.yml',
  '.borgmatic.yaml',   // Dot-prefixed variant
  'borgpassphrase',    // BorgBackup BORG_PASSPHRASE file — globally unambiguous
  '.borgpassphrase',
  'borg-passphrase',   // Hyphenated variant
])

function isBorgBackupConfig(pathLower: string, base: string): boolean {
  if (BORG_UNGATED.has(base)) return true
  if (base.startsWith('borgmatic-') && (base.endsWith('.yaml') || base.endsWith('.yml'))) return true

  if (!inAnyDir(pathLower, BORG_DIRS)) return false

  if (
    base === 'config'    || base === 'passphrase'  ||
    base.endsWith('.yaml') || base.endsWith('.yml') ||
    base.endsWith('.conf') || base === '.env'
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 4: BACKUP_ENCRYPTION_CREDENTIAL_DRIFT (high) — user contribution
// Generic backup-specific encryption keys and passphrases in backup dirs
// ---------------------------------------------------------------------------

/**
 * WS-85 user contribution — determines whether a file path contains backup-
 * specific encryption credential material that warrants a security drift alert.
 *
 * The challenge: files named with key/passphrase/secret suffixes and .gpg/.asc/.key
 * extensions appear in many contexts across a repository.  WS-66 (certPkiDrift)
 * covers general TLS certificates; WS-84 (vpnRemoteAccessDrift) covers VPN PKI
 * material.  WS-85 covers encryption credentials that are backup-tool-specific.
 *
 * Two disambiguation signals:
 *
 *   1. Globally unambiguous backup credential basenames that name their own
 *      purpose regardless of directory:
 *        backup-passphrase, backup-encryption-key, backup-key, backup-aes-key,
 *        backup-secret, encrypt.key, encryption.key, backup-key.gpg etc.
 *
 *   2. Credential-type file extensions (.gpg, .asc, .key, .passphrase, .secret)
 *      inside a recognised backup-specific directory segment (backup/, backups/,
 *      backup-config/, .backup/, restic/, borg/, borgmatic/, .duplicity/,
 *      rclone/, .rclone/).
 *
 * Exclusions:
 *   • Files already captured ungated by other rules in this detector
 *     (rclone.conf, restic-password, borgpassphrase, borgmatic.yaml,
 *     rsyncd.secrets) to avoid redundant findings.
 *   • .github/ and .gitlab/ paths — workflow files may reference backup
 *     credential paths but are not credential files themselves.
 *   • TLS cert extensions (.pem, .crt, .p12) deferred to WS-66.
 *
 * @param pathLower  Lowercased, forward-slash-normalised file path.
 * @param base       Lowercased filename component of `pathLower`.
 */
export function isBackupEncryptionCredential(pathLower: string, base: string): boolean {
  // Already captured by more-specific ungated rules in this detector
  if (
    base === 'rclone.conf'           || base === '.rclone.conf'         ||
    base === 'restic-password'        || base === 'restic-password.txt'  ||
    base === '.restic-password'       || base === 'restic-password-file' ||
    base === 'borgpassphrase'         || base === '.borgpassphrase'       ||
    base === 'borg-passphrase'        || base === 'borgmatic.yaml'        ||
    base === 'borgmatic.yml'          || base === 'rsyncd.secrets'
  ) return false

  // CI/CD pipeline workflow dirs — not credential files
  if (pathLower.includes('.github/') || pathLower.includes('.gitlab/')) return false

  // Globally unambiguous backup credential basenames (match regardless of dir)
  if (
    base === 'backup-passphrase'    || base === 'backup-encryption-key' ||
    base === 'backup-key'           || base === 'backup-aes-key'        ||
    base === 'backup-secret'        || base === 'encrypt.key'           ||
    base === 'encryption.key'       || base === 'backup-gpg-key'
  ) return true

  // Must be inside a backup-specific directory segment
  if (!inAnyDir(pathLower, BACKUP_CRED_DIRS)) return false

  // Credential-type file extensions found inside backup dirs
  return (
    base.endsWith('.gpg')        || base.endsWith('.asc')      ||
    base.endsWith('.key')        || base.endsWith('.passphrase')||
    base.endsWith('.secret')     || base.endsWith('.keyring')   ||
    base === 'passphrase'        || base === 'secret'           ||
    base === 'key'               || base === 'credentials'
  )
}

// ---------------------------------------------------------------------------
// Rule 5: RSYNC_DAEMON_DRIFT (medium)
// rsync daemon configuration and username/password secrets file
// ---------------------------------------------------------------------------

const RSYNCD_UNGATED = new Set([
  'rsyncd.conf',     // rsync daemon main configuration — globally unambiguous
  'rsyncd.secrets',  // rsync module username:password file — globally unambiguous
])

function isRsyncDaemonConfig(pathLower: string, base: string): boolean {
  if (RSYNCD_UNGATED.has(base)) return true
  if (base.startsWith('rsyncd-') && base.endsWith('.conf')) return true

  if (!inAnyDir(pathLower, RSYNC_DIRS)) return false

  if (base.endsWith('.conf') || base.endsWith('.secrets') || base === '.env') return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 6: ENTERPRISE_BACKUP_DRIFT (medium)
// Bacula Director/File/Storage daemon configs and Amanda backup server configs
// ---------------------------------------------------------------------------

const ENTERPRISE_BACKUP_UNGATED = new Set([
  'bacula-dir.conf',    // Bacula Director daemon — globally unambiguous
  'bacula-fd.conf',     // Bacula File Daemon — globally unambiguous
  'bacula-sd.conf',     // Bacula Storage Daemon — globally unambiguous
  'amanda.conf',        // Amanda backup main configuration — globally unambiguous
  'amanda-client.conf', // Amanda client configuration
])

function isEnterpriseBackupConfig(pathLower: string, base: string): boolean {
  if (ENTERPRISE_BACKUP_UNGATED.has(base)) return true
  if (base.startsWith('bacula-') && base.endsWith('.conf')) return true
  if (base.startsWith('amanda-') && base.endsWith('.conf')) return true

  if (inAnyDir(pathLower, BACULA_DIRS)) {
    if (base.endsWith('.conf') || base.endsWith('.bconsole') || base === '.env') return true
  }

  if (inAnyDir(pathLower, AMANDA_DIRS)) {
    if (base.endsWith('.conf') || base === 'disklist' || base === 'tapelist' || base === '.env') return true
  }

  return false
}

// ---------------------------------------------------------------------------
// Rule 7: CLOUD_BACKUP_AGENT_DRIFT (medium)
// Velero Kubernetes backup, Duplicati, and Duplicity encrypted backup configs
// ---------------------------------------------------------------------------

const CLOUD_BACKUP_UNGATED = new Set([
  'credentials-velero', // Velero cloud provider credential file — globally unambiguous
  'velero-credentials', // Alternative Velero credential filename
])

function isCloudBackupAgentConfig(pathLower: string, base: string): boolean {
  if (CLOUD_BACKUP_UNGATED.has(base)) return true

  if (base.startsWith('velero-') && (base.endsWith('.yaml') || base.endsWith('.json') || base.endsWith('.conf'))) return true
  if (base.startsWith('duplicati-') && (base.endsWith('.json') || base.endsWith('.dconfig'))) return true
  if (base.startsWith('duplicity-') && (base.endsWith('.conf') || base.endsWith('.gpg'))) return true

  if (inAnyDir(pathLower, VELERO_DIRS)) {
    if (
      base.endsWith('.yaml') || base.endsWith('.json') || base === 'credentials' ||
      base === '.env' || base === 'config'
    ) return true
  }

  if (inAnyDir(pathLower, DUPLICITY_DIRS)) {
    if (
      base.endsWith('.json')  || base.endsWith('.conf') || base.endsWith('.sqlite') ||
      base.endsWith('.dconfig')|| base === 'passphrase'  || base === '.env'
    ) return true
  }

  return false
}

// ---------------------------------------------------------------------------
// Rule 8: BACKUP_SCRIPT_DRIFT (low)
// Backup shell scripts in backup dirs (frequently contain hardcoded credentials)
// ---------------------------------------------------------------------------

function isBackupScript(pathLower: string, base: string): boolean {
  // backup-*.sh prefix anywhere in repo — explicitly named backup scripts
  if (base.startsWith('backup-') && base.endsWith('.sh')) return true
  if (base.startsWith('backup-') && base.endsWith('.py')) return true

  if (!inAnyDir(pathLower, BACKUP_SCRIPT_DIRS)) return false

  if (base.endsWith('.sh') || base.endsWith('.py') || base.endsWith('.bash')) return true
  if (base === 'backup.sh' || base === 'restore.sh' || base === 'backup.py') return true
  if (base === 'makefile' || base === 'Makefile'.toLowerCase()) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

export const BACKUP_DR_SECURITY_RULES: ReadonlyArray<{
  id: BackupDrSecurityRuleId
  severity: BackupDrSecuritySeverity
  description: string
  recommendation: string
  match: (pathLower: string, base: string) => boolean
}> = [
  {
    id: 'RCLONE_CONFIG_DRIFT',
    severity: 'high',
    description: 'rclone configuration file changed — contains credentials for every configured cloud storage provider.',
    recommendation:
      'Treat rclone.conf as a master credential store and review it with the same urgency as a leaked IAM key: inspect every [section] for changed access_key_id, secret_access_key, token, or client_secret values; verify that credentials for S3, GCS, Azure Blob, OneDrive, B2, and other configured providers have not been rotated without corresponding rotation on the provider side; confirm the file has not been committed with live production credentials and replace it with environment variable references or a secrets manager path.',
    match: (p, b) => isRcloneConfig(p, b),
  },
  {
    id: 'RESTIC_BACKUP_DRIFT',
    severity: 'high',
    description: 'Restic backup password file or repository configuration changed.',
    recommendation:
      'Review the restic password file change immediately — anyone with the password and repository access can decrypt all backup snapshots; if the password was changed, verify all automated restore paths have been updated; if the password was committed as plaintext, rotate it and re-key the repository with `restic key add` / `restic key remove`; audit restic.conf for changes to repository location, backend credentials, or exclude patterns that could result in sensitive files being omitted from or inadvertently added to the backup.',
    match: (p, b) => isResticConfig(p, b),
  },
  {
    id: 'BORGBACKUP_DRIFT',
    severity: 'high',
    description: 'BorgBackup passphrase or borgmatic configuration file changed.',
    recommendation:
      'Inspect the passphrase change: BorgBackup uses the BORG_PASSPHRASE to encrypt all repository data, so a committed or changed passphrase file exposes every snapshot; review borgmatic.yaml for changes to repositories, archive_name_format, hooks (pre/post-backup commands that may contain credentials), or encryption settings; verify that any added repository URLs do not point to untrusted storage endpoints; and confirm that retention.keep_* changes will not cause required recovery points to be pruned.',
    match: (p, b) => isBorgBackupConfig(p, b),
  },
  {
    id: 'BACKUP_ENCRYPTION_CREDENTIAL_DRIFT',
    severity: 'high',
    description: 'Backup-specific encryption key or passphrase file changed in a backup directory.',
    recommendation:
      'Confirm that the backup encryption credential change is intentional — unintended key rotation can make existing archives unrecoverable; if a credential file was added, verify it does not contain plaintext secrets and replace with a reference to a secrets manager (HashiCorp Vault, AWS Secrets Manager, SOPS); audit GPG key (.gpg/.asc) changes for key substitution attacks where the backup stream is re-encrypted for an attacker-controlled key; and validate that any changed keyring or credentials file in a backup directory corresponds to a documented key rotation event.',
    match: (p, b) => isBackupEncryptionCredential(p, b),
  },
  {
    id: 'RSYNC_DAEMON_DRIFT',
    severity: 'medium',
    description: 'rsync daemon configuration or secrets file changed.',
    recommendation:
      'Review rsyncd.conf for changes to [module] path, hosts allow/deny, read only, or auth users settings that could expose backup data to unauthorized rsync clients; inspect rsyncd.secrets for added or removed username:password entries — any cleartext password in this file should be treated as compromised and rotated; verify that the uid and gid settings have not been changed to run the daemon with elevated privileges; and confirm that newly added modules do not expose filesystem paths containing sensitive data.',
    match: (p, b) => isRsyncDaemonConfig(p, b),
  },
  {
    id: 'ENTERPRISE_BACKUP_DRIFT',
    severity: 'medium',
    description: 'Bacula or Amanda enterprise backup daemon configuration changed.',
    recommendation:
      'Review bacula-dir.conf for changes to Director password, Storage daemon address and password, Client name/address/password tuples, and Pool configuration — any of these could redirect restores or allow unauthorized clients to initiate jobs; inspect bacula-fd.conf for Director name and password changes that determine which Directors can connect to the File Daemon; audit amanda.conf for changes to dumptype definitions, holdingdisk paths, or auth settings; and verify that any new client definitions correspond to authorized backup targets.',
    match: (p, b) => isEnterpriseBackupConfig(p, b),
  },
  {
    id: 'CLOUD_BACKUP_AGENT_DRIFT',
    severity: 'medium',
    description: 'Velero, Duplicati, or Duplicity cloud backup agent configuration changed.',
    recommendation:
      'Review credentials-velero or velero-credentials for changes to AWS access keys, GCP service account JSON, or Azure storage account keys — these credentials should be rotated immediately if committed; inspect Velero BackupStorageLocation and VolumeSnapshotLocation manifest changes for destination redirects; audit Duplicati .dconfig or Duplicati-server.sqlite for changed target URL, auth token, or encryption passphrase; and confirm that Duplicity GPG key or passphrase changes are accompanied by re-encryption of existing backup archives.',
    match: (p, b) => isCloudBackupAgentConfig(p, b),
  },
  {
    id: 'BACKUP_SCRIPT_DRIFT',
    severity: 'low',
    description: 'Backup shell script or automation script changed in a backup directory.',
    recommendation:
      'Review backup shell scripts for hardcoded credentials (AWS_ACCESS_KEY_ID, database passwords, storage bucket URLs, SSH keys), verify that any credential references have been migrated to environment variables or secrets manager calls rather than committed values, confirm that changed exclude patterns or target paths still capture all business-critical data, and audit any added cron schedule changes or restore test scripts for unintended exposure of backup infrastructure topology.',
    match: (p, b) => isBackupScript(p, b),
  },
]

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

const SEVERITY_PENALTIES: Record<BackupDrSecuritySeverity, { per: number; cap: number }> = {
  high:   { per: 15, cap: 45 },
  medium: { per: 8,  cap: 25 },
  low:    { per: 4,  cap: 15 },
}

function computeRiskScore(findings: BackupDrSecurityDriftFinding[]): number {
  let score = 0
  for (const f of findings) {
    const { per, cap } = SEVERITY_PENALTIES[f.severity]
    score += Math.min(f.matchCount * per, cap)
  }
  return Math.min(score, 100)
}

function computeRiskLevel(score: number): BackupDrSecurityRiskLevel {
  if (score === 0) return 'none'
  if (score < 20)  return 'low'
  if (score < 45)  return 'medium'
  if (score < 70)  return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Main scanner
// ---------------------------------------------------------------------------

const MAX_PATHS_PER_SCAN = 500

export function scanBackupDrSecurityDrift(changedFiles: string[]): BackupDrSecurityDriftResult {
  const normalise = (p: string) => p.replace(/\\/g, '/').toLowerCase()

  const findings: BackupDrSecurityDriftFinding[] = []

  for (const rule of BACKUP_DR_SECURITY_RULES) {
    let firstPath  = ''
    let matchCount = 0

    for (const raw of changedFiles.slice(0, MAX_PATHS_PER_SCAN)) {
      const p    = normalise(raw)
      const base = p.split('/').pop() ?? p

      if (isVendor(p)) continue
      if (!rule.match(p, base)) continue

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
  const ORDER: Record<BackupDrSecuritySeverity, number> = { high: 0, medium: 1, low: 2 }
  findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity])

  const riskScore   = computeRiskScore(findings)
  const riskLevel   = computeRiskLevel(riskScore)
  const highCount   = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount    = findings.filter((f) => f.severity === 'low').length

  const summary =
    findings.length === 0
      ? 'No backup or disaster recovery security drift detected.'
      : `${findings.length} backup/DR rule${findings.length === 1 ? '' : 's'} triggered ` +
        `(${[
          highCount   ? `${highCount} high`    : '',
          mediumCount ? `${mediumCount} medium` : '',
          lowCount    ? `${lowCount} low`       : '',
        ].filter(Boolean).join(', ')}); risk score ${riskScore}/100.`

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
