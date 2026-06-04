import { describe, expect, it } from 'vitest'
import {
  BACKUP_DR_SECURITY_RULES,
  isBackupEncryptionCredential,
  scanBackupDrSecurityDrift,
} from './backupDrSecurityDrift'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const scan = (files: string[]) => scanBackupDrSecurityDrift(files)
const triggeredRules = (files: string[]) => scan(files).findings.map((f) => f.ruleId)

// ---------------------------------------------------------------------------
// Rule 1: RCLONE_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('RCLONE_CONFIG_DRIFT', () => {
  it('matches rclone.conf (ungated)', () => {
    expect(triggeredRules(['rclone.conf'])).toContain('RCLONE_CONFIG_DRIFT')
  })
  it('matches .rclone.conf (ungated dot-prefixed variant)', () => {
    expect(triggeredRules(['.rclone.conf'])).toContain('RCLONE_CONFIG_DRIFT')
  })
  it('matches rclone-prod.conf via prefix', () => {
    expect(triggeredRules(['rclone-prod.conf'])).toContain('RCLONE_CONFIG_DRIFT')
  })
  it('matches rclone-s3.conf via prefix', () => {
    expect(triggeredRules(['rclone-s3.conf'])).toContain('RCLONE_CONFIG_DRIFT')
  })
  it('matches config inside rclone/ dir', () => {
    expect(triggeredRules(['rclone/config'])).toContain('RCLONE_CONFIG_DRIFT')
  })
  it('matches any .conf inside .rclone/ dir', () => {
    expect(triggeredRules(['.rclone/backup.conf'])).toContain('RCLONE_CONFIG_DRIFT')
  })
  it('does NOT match config in non-rclone dir', () => {
    expect(triggeredRules(['app/config'])).not.toContain('RCLONE_CONFIG_DRIFT')
  })
  it('does NOT match vendor path', () => {
    expect(triggeredRules(['vendor/rclone/rclone.conf'])).not.toContain('RCLONE_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 2: RESTIC_BACKUP_DRIFT
// ---------------------------------------------------------------------------

describe('RESTIC_BACKUP_DRIFT', () => {
  it('matches restic-password (ungated)', () => {
    expect(triggeredRules(['restic-password'])).toContain('RESTIC_BACKUP_DRIFT')
  })
  it('matches restic-password.txt (ungated)', () => {
    expect(triggeredRules(['restic-password.txt'])).toContain('RESTIC_BACKUP_DRIFT')
  })
  it('matches .restic-password (ungated dot-prefixed)', () => {
    expect(triggeredRules(['.restic-password'])).toContain('RESTIC_BACKUP_DRIFT')
  })
  it('matches restic-password-file (ungated)', () => {
    expect(triggeredRules(['restic-password-file'])).toContain('RESTIC_BACKUP_DRIFT')
  })
  it('matches restic.conf (ungated)', () => {
    expect(triggeredRules(['restic.conf'])).toContain('RESTIC_BACKUP_DRIFT')
  })
  it('matches restic-prod.conf via prefix', () => {
    expect(triggeredRules(['restic-prod.conf'])).toContain('RESTIC_BACKUP_DRIFT')
  })
  it('matches restic-backup.toml via prefix', () => {
    expect(triggeredRules(['restic-backup.toml'])).toContain('RESTIC_BACKUP_DRIFT')
  })
  it('matches password inside restic/ dir', () => {
    expect(triggeredRules(['restic/password'])).toContain('RESTIC_BACKUP_DRIFT')
  })
  it('matches password.txt inside .restic/ dir', () => {
    expect(triggeredRules(['.restic/password.txt'])).toContain('RESTIC_BACKUP_DRIFT')
  })
  it('matches repository inside restic-backup/ dir', () => {
    expect(triggeredRules(['restic-backup/repository'])).toContain('RESTIC_BACKUP_DRIFT')
  })
  it('matches exclude inside restic/ dir', () => {
    expect(triggeredRules(['restic/exclude'])).toContain('RESTIC_BACKUP_DRIFT')
  })
  it('does NOT match password outside restic dirs', () => {
    expect(triggeredRules(['config/password'])).not.toContain('RESTIC_BACKUP_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 3: BORGBACKUP_DRIFT
// ---------------------------------------------------------------------------

describe('BORGBACKUP_DRIFT', () => {
  it('matches borgmatic.yaml (ungated)', () => {
    expect(triggeredRules(['borgmatic.yaml'])).toContain('BORGBACKUP_DRIFT')
  })
  it('matches borgmatic.yml (ungated)', () => {
    expect(triggeredRules(['borgmatic.yml'])).toContain('BORGBACKUP_DRIFT')
  })
  it('matches .borgmatic.yaml (ungated dot-prefixed)', () => {
    expect(triggeredRules(['.borgmatic.yaml'])).toContain('BORGBACKUP_DRIFT')
  })
  it('matches borgpassphrase (ungated)', () => {
    expect(triggeredRules(['borgpassphrase'])).toContain('BORGBACKUP_DRIFT')
  })
  it('matches .borgpassphrase (ungated dot-prefixed)', () => {
    expect(triggeredRules(['.borgpassphrase'])).toContain('BORGBACKUP_DRIFT')
  })
  it('matches borg-passphrase (ungated hyphenated)', () => {
    expect(triggeredRules(['borg-passphrase'])).toContain('BORGBACKUP_DRIFT')
  })
  it('matches borgmatic-prod.yaml via prefix', () => {
    expect(triggeredRules(['borgmatic-prod.yaml'])).toContain('BORGBACKUP_DRIFT')
  })
  it('matches config inside borg/ dir', () => {
    expect(triggeredRules(['borg/config'])).toContain('BORGBACKUP_DRIFT')
  })
  it('matches passphrase inside .borg/ dir', () => {
    expect(triggeredRules(['.borg/passphrase'])).toContain('BORGBACKUP_DRIFT')
  })
  it('matches backup.yaml inside borgmatic/ dir', () => {
    expect(triggeredRules(['borgmatic/backup.yaml'])).toContain('BORGBACKUP_DRIFT')
  })
  it('does NOT match config.yaml outside borg dirs', () => {
    expect(triggeredRules(['config/config.yaml'])).not.toContain('BORGBACKUP_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 4: BACKUP_ENCRYPTION_CREDENTIAL_DRIFT (user contribution)
// ---------------------------------------------------------------------------

describe('BACKUP_ENCRYPTION_CREDENTIAL_DRIFT', () => {
  it('matches backup-passphrase (globally unambiguous basename)', () => {
    expect(triggeredRules(['backup-passphrase'])).toContain('BACKUP_ENCRYPTION_CREDENTIAL_DRIFT')
  })
  it('matches backup-encryption-key (globally unambiguous)', () => {
    expect(triggeredRules(['backup-encryption-key'])).toContain('BACKUP_ENCRYPTION_CREDENTIAL_DRIFT')
  })
  it('matches backup-key (globally unambiguous)', () => {
    expect(triggeredRules(['backup-key'])).toContain('BACKUP_ENCRYPTION_CREDENTIAL_DRIFT')
  })
  it('matches encrypt.key (globally unambiguous)', () => {
    expect(triggeredRules(['encrypt.key'])).toContain('BACKUP_ENCRYPTION_CREDENTIAL_DRIFT')
  })
  it('matches backup-gpg-key (globally unambiguous)', () => {
    expect(triggeredRules(['backup-gpg-key'])).toContain('BACKUP_ENCRYPTION_CREDENTIAL_DRIFT')
  })
  it('matches any .gpg file inside backup/ dir', () => {
    expect(triggeredRules(['backup/secret.gpg'])).toContain('BACKUP_ENCRYPTION_CREDENTIAL_DRIFT')
  })
  it('matches any .asc file inside backup/ dir', () => {
    expect(triggeredRules(['backup/key.asc'])).toContain('BACKUP_ENCRYPTION_CREDENTIAL_DRIFT')
  })
  it('matches any .key file inside backups/ dir', () => {
    expect(triggeredRules(['backups/encrypt.key'])).toContain('BACKUP_ENCRYPTION_CREDENTIAL_DRIFT')
  })
  it('matches credentials inside borg/ dir', () => {
    expect(triggeredRules(['borg/credentials'])).toContain('BACKUP_ENCRYPTION_CREDENTIAL_DRIFT')
  })
  it('matches passphrase inside .duplicity/ dir', () => {
    expect(triggeredRules(['.duplicity/passphrase'])).toContain('BACKUP_ENCRYPTION_CREDENTIAL_DRIFT')
  })
  it('does NOT match borgpassphrase (already caught by BORGBACKUP rule)', () => {
    const result = scan(['borgpassphrase'])
    const encFindings = result.findings.filter((f) => f.ruleId === 'BACKUP_ENCRYPTION_CREDENTIAL_DRIFT')
    expect(encFindings).toHaveLength(0)
  })
  it('does NOT match rclone.conf (already caught by RCLONE rule)', () => {
    const result = scan(['rclone.conf'])
    const encFindings = result.findings.filter((f) => f.ruleId === 'BACKUP_ENCRYPTION_CREDENTIAL_DRIFT')
    expect(encFindings).toHaveLength(0)
  })
  it('does NOT match rsyncd.secrets (already caught by RSYNC rule)', () => {
    const result = scan(['rsyncd.secrets'])
    const encFindings = result.findings.filter((f) => f.ruleId === 'BACKUP_ENCRYPTION_CREDENTIAL_DRIFT')
    expect(encFindings).toHaveLength(0)
  })
  it('does NOT match .github/ path', () => {
    expect(triggeredRules(['.github/workflows/backup.gpg'])).not.toContain('BACKUP_ENCRYPTION_CREDENTIAL_DRIFT')
  })
  it('does NOT match .gpg file outside backup dirs', () => {
    expect(triggeredRules(['keys/secret.gpg'])).not.toContain('BACKUP_ENCRYPTION_CREDENTIAL_DRIFT')
  })
})

describe('isBackupEncryptionCredential unit tests', () => {
  it('returns true for backup-passphrase anywhere', () => {
    expect(isBackupEncryptionCredential('backup-passphrase', 'backup-passphrase')).toBe(true)
  })
  it('returns true for .gpg in backup dir', () => {
    expect(isBackupEncryptionCredential('backup/archive.gpg', 'archive.gpg')).toBe(true)
  })
  it('returns true for passphrase inside .duplicity dir', () => {
    expect(isBackupEncryptionCredential('.duplicity/passphrase', 'passphrase')).toBe(true)
  })
  it('returns false for borgpassphrase (excluded)', () => {
    expect(isBackupEncryptionCredential('borgpassphrase', 'borgpassphrase')).toBe(false)
  })
  it('returns false for restic-password (excluded)', () => {
    expect(isBackupEncryptionCredential('restic-password', 'restic-password')).toBe(false)
  })
  it('returns false for rsyncd.secrets (excluded)', () => {
    expect(isBackupEncryptionCredential('rsyncd.secrets', 'rsyncd.secrets')).toBe(false)
  })
  it('returns false for .github/ path', () => {
    expect(isBackupEncryptionCredential('.github/workflows/backup.gpg', 'backup.gpg')).toBe(false)
  })
  it('returns false for .key file outside backup dirs', () => {
    expect(isBackupEncryptionCredential('infra/keys/server.key', 'server.key')).toBe(false)
  })
  it('returns true for credentials inside rclone/ dir', () => {
    expect(isBackupEncryptionCredential('rclone/credentials', 'credentials')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Rule 5: RSYNC_DAEMON_DRIFT
// ---------------------------------------------------------------------------

describe('RSYNC_DAEMON_DRIFT', () => {
  it('matches rsyncd.conf (ungated)', () => {
    expect(triggeredRules(['rsyncd.conf'])).toContain('RSYNC_DAEMON_DRIFT')
  })
  it('matches rsyncd.secrets (ungated)', () => {
    expect(triggeredRules(['rsyncd.secrets'])).toContain('RSYNC_DAEMON_DRIFT')
  })
  it('matches rsyncd-backup.conf via prefix', () => {
    expect(triggeredRules(['rsyncd-backup.conf'])).toContain('RSYNC_DAEMON_DRIFT')
  })
  it('matches any .conf inside rsync/ dir', () => {
    expect(triggeredRules(['rsync/server.conf'])).toContain('RSYNC_DAEMON_DRIFT')
  })
  it('matches .secrets file inside rsync-config/ dir', () => {
    expect(triggeredRules(['rsync-config/auth.secrets'])).toContain('RSYNC_DAEMON_DRIFT')
  })
  it('does NOT match config.conf outside rsync dirs', () => {
    expect(triggeredRules(['config/config.conf'])).not.toContain('RSYNC_DAEMON_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 6: ENTERPRISE_BACKUP_DRIFT
// ---------------------------------------------------------------------------

describe('ENTERPRISE_BACKUP_DRIFT', () => {
  it('matches bacula-dir.conf (ungated Bacula Director)', () => {
    expect(triggeredRules(['bacula-dir.conf'])).toContain('ENTERPRISE_BACKUP_DRIFT')
  })
  it('matches bacula-fd.conf (ungated Bacula File Daemon)', () => {
    expect(triggeredRules(['bacula-fd.conf'])).toContain('ENTERPRISE_BACKUP_DRIFT')
  })
  it('matches bacula-sd.conf (ungated Bacula Storage Daemon)', () => {
    expect(triggeredRules(['bacula-sd.conf'])).toContain('ENTERPRISE_BACKUP_DRIFT')
  })
  it('matches amanda.conf (ungated Amanda main config)', () => {
    expect(triggeredRules(['amanda.conf'])).toContain('ENTERPRISE_BACKUP_DRIFT')
  })
  it('matches amanda-client.conf (ungated Amanda client)', () => {
    expect(triggeredRules(['amanda-client.conf'])).toContain('ENTERPRISE_BACKUP_DRIFT')
  })
  it('matches bacula-console.conf via prefix', () => {
    expect(triggeredRules(['bacula-console.conf'])).toContain('ENTERPRISE_BACKUP_DRIFT')
  })
  it('matches amanda-server.conf via prefix', () => {
    expect(triggeredRules(['amanda-server.conf'])).toContain('ENTERPRISE_BACKUP_DRIFT')
  })
  it('matches any .conf inside bacula/ dir', () => {
    expect(triggeredRules(['bacula/client.conf'])).toContain('ENTERPRISE_BACKUP_DRIFT')
  })
  it('matches disklist inside amanda/ dir', () => {
    expect(triggeredRules(['amanda/disklist'])).toContain('ENTERPRISE_BACKUP_DRIFT')
  })
  it('does NOT match config.conf outside enterprise backup dirs', () => {
    expect(triggeredRules(['deploy/config.conf'])).not.toContain('ENTERPRISE_BACKUP_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 7: CLOUD_BACKUP_AGENT_DRIFT
// ---------------------------------------------------------------------------

describe('CLOUD_BACKUP_AGENT_DRIFT', () => {
  it('matches credentials-velero (ungated Velero creds)', () => {
    expect(triggeredRules(['credentials-velero'])).toContain('CLOUD_BACKUP_AGENT_DRIFT')
  })
  it('matches velero-credentials (ungated alternative)', () => {
    expect(triggeredRules(['velero-credentials'])).toContain('CLOUD_BACKUP_AGENT_DRIFT')
  })
  it('matches velero-config.yaml via prefix', () => {
    expect(triggeredRules(['velero-config.yaml'])).toContain('CLOUD_BACKUP_AGENT_DRIFT')
  })
  it('matches velero-backup.json via prefix', () => {
    expect(triggeredRules(['velero-backup.json'])).toContain('CLOUD_BACKUP_AGENT_DRIFT')
  })
  it('matches duplicati-config.json via prefix', () => {
    expect(triggeredRules(['duplicati-config.json'])).toContain('CLOUD_BACKUP_AGENT_DRIFT')
  })
  it('matches duplicati-backup.dconfig via prefix', () => {
    expect(triggeredRules(['duplicati-backup.dconfig'])).toContain('CLOUD_BACKUP_AGENT_DRIFT')
  })
  it('matches credentials inside velero/ dir', () => {
    expect(triggeredRules(['velero/credentials'])).toContain('CLOUD_BACKUP_AGENT_DRIFT')
  })
  it('matches config.yaml inside .velero/ dir', () => {
    expect(triggeredRules(['.velero/config.yaml'])).toContain('CLOUD_BACKUP_AGENT_DRIFT')
  })
  it('matches passphrase inside .duplicity/ dir', () => {
    expect(triggeredRules(['.duplicity/passphrase'])).toContain('CLOUD_BACKUP_AGENT_DRIFT')
  })
  it('matches settings.json inside duplicati/ dir', () => {
    expect(triggeredRules(['duplicati/settings.json'])).toContain('CLOUD_BACKUP_AGENT_DRIFT')
  })
  it('does NOT match config.yaml outside cloud backup dirs', () => {
    expect(triggeredRules(['deploy/config.yaml'])).not.toContain('CLOUD_BACKUP_AGENT_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 8: BACKUP_SCRIPT_DRIFT
// ---------------------------------------------------------------------------

describe('BACKUP_SCRIPT_DRIFT', () => {
  it('matches backup-prod.sh via prefix', () => {
    expect(triggeredRules(['backup-prod.sh'])).toContain('BACKUP_SCRIPT_DRIFT')
  })
  it('matches backup-database.sh via prefix', () => {
    expect(triggeredRules(['backup-database.sh'])).toContain('BACKUP_SCRIPT_DRIFT')
  })
  it('matches backup-s3.py via prefix', () => {
    expect(triggeredRules(['backup-s3.py'])).toContain('BACKUP_SCRIPT_DRIFT')
  })
  it('matches backup.sh inside backup/ dir', () => {
    expect(triggeredRules(['backup/backup.sh'])).toContain('BACKUP_SCRIPT_DRIFT')
  })
  it('matches restore.sh inside backup/ dir', () => {
    expect(triggeredRules(['backup/restore.sh'])).toContain('BACKUP_SCRIPT_DRIFT')
  })
  it('matches any .sh file inside backups/ dir', () => {
    expect(triggeredRules(['backups/weekly-run.sh'])).toContain('BACKUP_SCRIPT_DRIFT')
  })
  it('matches any .py inside backup-scripts/ dir', () => {
    expect(triggeredRules(['backup-scripts/encrypt_upload.py'])).toContain('BACKUP_SCRIPT_DRIFT')
  })
  it('matches makefile inside backup/ dir', () => {
    expect(triggeredRules(['backup/makefile'])).toContain('BACKUP_SCRIPT_DRIFT')
  })
  it('does NOT match deploy.sh outside backup dirs', () => {
    expect(triggeredRules(['scripts/deploy.sh'])).not.toContain('BACKUP_SCRIPT_DRIFT')
  })
  it('does NOT match app.py outside backup dirs', () => {
    expect(triggeredRules(['src/app.py'])).not.toContain('BACKUP_SCRIPT_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Vendor exclusion
// ---------------------------------------------------------------------------

describe('vendor exclusion', () => {
  it('skips node_modules path', () => {
    expect(triggeredRules(['node_modules/rclone/rclone.conf'])).toHaveLength(0)
  })
  it('skips vendor path', () => {
    expect(triggeredRules(['vendor/backup/restic-password'])).toHaveLength(0)
  })
  it('skips .git path', () => {
    expect(triggeredRules(['.git/objects/borgmatic.yaml'])).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Windows path normalisation
// ---------------------------------------------------------------------------

describe('Windows path normalisation', () => {
  it('normalises backslashes for rclone.conf in rclone dir', () => {
    expect(triggeredRules(['rclone\\rclone.conf'])).toContain('RCLONE_CONFIG_DRIFT')
  })
  it('normalises backslashes for borgmatic.yaml', () => {
    expect(triggeredRules(['borgmatic\\borgmatic.yaml'])).toContain('BORGBACKUP_DRIFT')
  })
  it('normalises backslashes for bacula-dir.conf', () => {
    expect(triggeredRules(['bacula\\bacula-dir.conf'])).toContain('ENTERPRISE_BACKUP_DRIFT')
  })
  it('normalises backslashes for backup.sh in backup dir', () => {
    expect(triggeredRules(['backup\\backup.sh'])).toContain('BACKUP_SCRIPT_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

describe('deduplication', () => {
  it('produces a single finding per triggered rule', () => {
    const result = scan(['rclone.conf', '.rclone.conf'])
    const rcloneFindings = result.findings.filter((f) => f.ruleId === 'RCLONE_CONFIG_DRIFT')
    expect(rcloneFindings).toHaveLength(1)
  })
  it('records matchCount for multiple files matching same rule', () => {
    const result = scan(['restic-password', 'restic-password.txt', '.restic-password'])
    const finding = result.findings.find((f) => f.ruleId === 'RESTIC_BACKUP_DRIFT')
    expect(finding?.matchCount).toBe(3)
  })
  it('produces separate findings for different rules', () => {
    const result = scan(['rclone.conf', 'restic-password', 'borgmatic.yaml'])
    const ruleIds = result.findings.map((f) => f.ruleId)
    expect(ruleIds).toEqual(expect.arrayContaining([
      'RCLONE_CONFIG_DRIFT',
      'RESTIC_BACKUP_DRIFT',
      'BORGBACKUP_DRIFT',
    ]))
  })
  it('records firstPath as the first matched file', () => {
    const result = scan(['borgmatic.yaml', 'borgmatic.yml'])
    const finding = result.findings.find((f) => f.ruleId === 'BORGBACKUP_DRIFT')
    expect(finding?.matchedPath).toBe('borgmatic.yaml')
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scoring model', () => {
  it('1 high finding → score 15', () => {
    expect(scan(['rclone.conf']).riskScore).toBe(15)
  })
  it('2 high findings → score 30', () => {
    expect(scan(['rclone.conf', 'restic-password']).riskScore).toBe(30)
  })
  it('3 high findings → score 45', () => {
    expect(scan(['rclone.conf', 'restic-password', 'borgmatic.yaml']).riskScore).toBe(45)
  })
  it('score 45 → high (45 is NOT < 45)', () => {
    expect(scan(['rclone.conf', 'restic-password', 'borgmatic.yaml']).riskLevel).toBe('high')
  })
  it('4 high findings → score 60', () => {
    expect(scan(['rclone.conf', 'restic-password', 'borgmatic.yaml', 'backup-passphrase']).riskScore).toBe(60)
  })
  it('4 high + 1 medium → score 68', () => {
    expect(
      scan(['rclone.conf', 'restic-password', 'borgmatic.yaml', 'backup-passphrase', 'rsyncd.conf']).riskScore,
    ).toBe(68)
  })
  it('4 high + 2 medium → score 76 → critical', () => {
    const result = scan([
      'rclone.conf', 'restic-password', 'borgmatic.yaml', 'backup-passphrase',
      'rsyncd.conf', 'bacula-dir.conf',
    ])
    expect(result.riskScore).toBe(76)
    expect(result.riskLevel).toBe('critical')
  })
  it('1 medium finding → score 8', () => {
    expect(scan(['rsyncd.conf']).riskScore).toBe(8)
  })
  it('1 low finding → score 4', () => {
    expect(scan(['backup-prod.sh']).riskScore).toBe(4)
  })
  it('total score capped at 100 when all 8 rules fire', () => {
    const result = scan([
      'rclone.conf', 'restic-password', 'borgmatic.yaml', 'backup-passphrase',
      'rsyncd.conf', 'bacula-dir.conf', 'credentials-velero', 'backup-prod.sh',
    ])
    expect(result.riskScore).toBeLessThanOrEqual(100)
    expect(result.riskLevel).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// Risk level boundaries
// ---------------------------------------------------------------------------

describe('risk level boundaries', () => {
  it('score 0 → none', () => {
    expect(scan([]).riskLevel).toBe('none')
  })
  it('score 15 → low', () => {
    expect(scan(['rclone.conf']).riskLevel).toBe('low')
  })
  it('score 30 → medium', () => {
    expect(scan(['rclone.conf', 'restic-password']).riskLevel).toBe('medium')
  })
  it('score 45 → high', () => {
    expect(scan(['rclone.conf', 'restic-password', 'borgmatic.yaml']).riskLevel).toBe('high')
  })
  it('score 60 → high', () => {
    expect(
      scan(['rclone.conf', 'restic-password', 'borgmatic.yaml', 'backup-passphrase']).riskLevel,
    ).toBe('high')
  })
  it('score 76 → critical', () => {
    expect(
      scan([
        'rclone.conf', 'restic-password', 'borgmatic.yaml', 'backup-passphrase',
        'rsyncd.conf', 'bacula-dir.conf',
      ]).riskLevel,
    ).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// Severity ordering in findings
// ---------------------------------------------------------------------------

describe('severity ordering', () => {
  it('high findings appear before medium', () => {
    const result = scan(['rsyncd.conf', 'rclone.conf'])
    const severities = result.findings.map((f) => f.severity)
    expect(severities.indexOf('high')).toBeLessThan(severities.indexOf('medium'))
  })
  it('medium findings appear before low', () => {
    const result = scan(['backup-prod.sh', 'rsyncd.conf'])
    const severities = result.findings.map((f) => f.severity)
    expect(severities.indexOf('medium')).toBeLessThan(severities.indexOf('low'))
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
    const result = scan(['rclone.conf'])
    const f = result.findings[0]
    expect(f).toHaveProperty('ruleId')
    expect(f).toHaveProperty('severity')
    expect(f).toHaveProperty('matchedPath')
    expect(f).toHaveProperty('matchCount')
    expect(f).toHaveProperty('description')
    expect(f).toHaveProperty('recommendation')
  })
  it('summary mentions no drift when clean', () => {
    expect(scan([]).summary).toContain('No backup')
  })
  it('summary mentions count and score when findings exist', () => {
    const result = scan(['rclone.conf'])
    expect(result.summary).toContain('1')
    expect(result.summary).toContain('15')
  })
  it('matchedPath preserves original casing', () => {
    const result = scan(['Backup/Rclone.conf'])
    const finding = result.findings.find((f) => f.ruleId === 'RCLONE_CONFIG_DRIFT')
    expect(finding?.matchedPath).toBe('Backup/Rclone.conf')
  })
})

// ---------------------------------------------------------------------------
// Multi-rule scenarios
// ---------------------------------------------------------------------------

describe('multi-rule scenarios', () => {
  it('rclone.conf and rsyncd.conf trigger different severity rules', () => {
    const result = scan(['rclone.conf', 'rsyncd.conf'])
    expect(result.highCount).toBe(1)
    expect(result.mediumCount).toBe(1)
  })
  it('borgpassphrase triggers BORGBACKUP but not BACKUP_ENCRYPTION_CREDENTIAL', () => {
    const result = scan(['borgpassphrase'])
    const ruleIds = result.findings.map((f) => f.ruleId)
    expect(ruleIds).toContain('BORGBACKUP_DRIFT')
    expect(ruleIds).not.toContain('BACKUP_ENCRYPTION_CREDENTIAL_DRIFT')
  })
  it('restic-password triggers RESTIC but not BACKUP_ENCRYPTION_CREDENTIAL', () => {
    const result = scan(['restic-password'])
    const ruleIds = result.findings.map((f) => f.ruleId)
    expect(ruleIds).toContain('RESTIC_BACKUP_DRIFT')
    expect(ruleIds).not.toContain('BACKUP_ENCRYPTION_CREDENTIAL_DRIFT')
  })
  it('all 4 high rules can fire simultaneously', () => {
    const result = scan(['rclone.conf', 'restic-password', 'borgmatic.yaml', 'backup-encryption-key'])
    expect(result.highCount).toBe(4)
  })
})

// ---------------------------------------------------------------------------
// Rule registry completeness
// ---------------------------------------------------------------------------

describe('rule registry', () => {
  it('exports exactly 8 rules', () => {
    expect(BACKUP_DR_SECURITY_RULES).toHaveLength(8)
  })
  it('covers all expected rule IDs', () => {
    const ids = BACKUP_DR_SECURITY_RULES.map((r) => r.id)
    expect(ids).toEqual(expect.arrayContaining([
      'RCLONE_CONFIG_DRIFT',
      'RESTIC_BACKUP_DRIFT',
      'BORGBACKUP_DRIFT',
      'BACKUP_ENCRYPTION_CREDENTIAL_DRIFT',
      'RSYNC_DAEMON_DRIFT',
      'ENTERPRISE_BACKUP_DRIFT',
      'CLOUD_BACKUP_AGENT_DRIFT',
      'BACKUP_SCRIPT_DRIFT',
    ]))
  })
  it('has 4 HIGH, 3 MEDIUM, 1 LOW rules', () => {
    const severities = BACKUP_DR_SECURITY_RULES.map((r) => r.severity)
    expect(severities.filter((s) => s === 'high')).toHaveLength(4)
    expect(severities.filter((s) => s === 'medium')).toHaveLength(3)
    expect(severities.filter((s) => s === 'low')).toHaveLength(1)
  })
})
