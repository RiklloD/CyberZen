import { describe, expect, it } from 'vitest'
import {
  isOsLoginBannerFile,
  OS_SECURITY_HARDENING_RULES,
  scanOsSecurityHardeningDrift,
} from './osSecurityHardeningDrift'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function rule(id: string) {
  const r = OS_SECURITY_HARDENING_RULES.find((x) => x.id === id)
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
// SYSCTL_KERNEL_HARDENING_DRIFT
// ---------------------------------------------------------------------------

describe('SYSCTL_KERNEL_HARDENING_DRIFT', () => {
  it('matches sysctl.conf', () => {
    expect(match('SYSCTL_KERNEL_HARDENING_DRIFT', 'etc/sysctl.conf')).toBe(true)
  })
  it('matches sysctl.conf at root', () => {
    expect(match('SYSCTL_KERNEL_HARDENING_DRIFT', 'sysctl.conf')).toBe(true)
  })
  it('matches sysctl.conf.j2 template', () => {
    expect(match('SYSCTL_KERNEL_HARDENING_DRIFT', 'templates/sysctl.conf.j2')).toBe(true)
  })
  it('matches sysctl.conf-backup', () => {
    expect(match('SYSCTL_KERNEL_HARDENING_DRIFT', 'sysctl.conf-backup')).toBe(true)
  })
  it('matches .conf drop-in in sysctl.d/', () => {
    expect(match('SYSCTL_KERNEL_HARDENING_DRIFT', 'etc/sysctl.d/99-hardening.conf')).toBe(true)
  })
  it('matches drop-in in security/sysctl.d/', () => {
    expect(match('SYSCTL_KERNEL_HARDENING_DRIFT', 'security/sysctl.d/10-network-security.conf')).toBe(true)
  })
  it('matches drop-in in hardening/ dir', () => {
    expect(match('SYSCTL_KERNEL_HARDENING_DRIFT', 'hardening/80-yama.conf')).toBe(true)
  })
  it('matches drop-in in os-hardening/', () => {
    expect(match('SYSCTL_KERNEL_HARDENING_DRIFT', 'os-hardening/50-coredump.conf')).toBe(true)
  })
  it('does not match generic .conf outside sysctl dirs', () => {
    expect(match('SYSCTL_KERNEL_HARDENING_DRIFT', 'config/app.conf')).toBe(false)
  })
  it('does not match non-.conf in hardening dir', () => {
    expect(match('SYSCTL_KERNEL_HARDENING_DRIFT', 'hardening/README.md')).toBe(false)
  })
  it('does not match random sysctl-named dir', () => {
    expect(match('SYSCTL_KERNEL_HARDENING_DRIFT', 'docs/sysctl-guide.txt')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// SSH_SERVER_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('SSH_SERVER_CONFIG_DRIFT', () => {
  it('matches sshd_config', () => {
    expect(match('SSH_SERVER_CONFIG_DRIFT', 'etc/ssh/sshd_config')).toBe(true)
  })
  it('matches sshd_config at root', () => {
    expect(match('SSH_SERVER_CONFIG_DRIFT', 'sshd_config')).toBe(true)
  })
  it('matches ssh_config client config', () => {
    expect(match('SSH_SERVER_CONFIG_DRIFT', 'etc/ssh/ssh_config')).toBe(true)
  })
  it('matches sshd_config.j2 template', () => {
    expect(match('SSH_SERVER_CONFIG_DRIFT', 'templates/sshd_config.j2')).toBe(true)
  })
  it('matches sshd_config-hardened variant', () => {
    expect(match('SSH_SERVER_CONFIG_DRIFT', 'sshd_config-hardened')).toBe(true)
  })
  it('matches .conf drop-in in sshd_config.d/', () => {
    expect(match('SSH_SERVER_CONFIG_DRIFT', 'etc/ssh/sshd_config.d/10-hardening.conf')).toBe(true)
  })
  it('matches .conf in ssh/ dir', () => {
    expect(match('SSH_SERVER_CONFIG_DRIFT', 'ssh/custom.conf')).toBe(true)
  })
  it('matches .conf in openssh/ dir', () => {
    expect(match('SSH_SERVER_CONFIG_DRIFT', 'openssh/sshd.conf')).toBe(true)
  })
  it('does not match known_hosts', () => {
    expect(match('SSH_SERVER_CONFIG_DRIFT', 'etc/ssh/known_hosts')).toBe(false)
  })
  it('does not match authorized_keys', () => {
    expect(match('SSH_SERVER_CONFIG_DRIFT', '.ssh/authorized_keys')).toBe(false)
  })
  it('does not match random ssh-named file outside ssh dirs', () => {
    expect(match('SSH_SERVER_CONFIG_DRIFT', 'docs/ssh-hardening-guide.md')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// SUDOERS_PRIVILEGE_DRIFT
// ---------------------------------------------------------------------------

describe('SUDOERS_PRIVILEGE_DRIFT', () => {
  it('matches sudoers file', () => {
    expect(match('SUDOERS_PRIVILEGE_DRIFT', 'etc/sudoers')).toBe(true)
  })
  it('matches sudoers at root', () => {
    expect(match('SUDOERS_PRIVILEGE_DRIFT', 'sudoers')).toBe(true)
  })
  it('matches sudoers.tmp', () => {
    expect(match('SUDOERS_PRIVILEGE_DRIFT', 'sudoers.tmp')).toBe(true)
  })
  it('matches sudoers.j2 template', () => {
    expect(match('SUDOERS_PRIVILEGE_DRIFT', 'templates/sudoers.j2')).toBe(true)
  })
  it('matches sudoers-admin variant', () => {
    expect(match('SUDOERS_PRIVILEGE_DRIFT', 'sudoers-admin')).toBe(true)
  })
  it('matches sudoers.conf', () => {
    expect(match('SUDOERS_PRIVILEGE_DRIFT', 'sudoers.conf')).toBe(true)
  })
  it('matches drop-in file in sudoers.d/', () => {
    expect(match('SUDOERS_PRIVILEGE_DRIFT', 'etc/sudoers.d/90-admin')).toBe(true)
  })
  it('matches drop-in with no extension in etc/sudoers.d/', () => {
    expect(match('SUDOERS_PRIVILEGE_DRIFT', 'etc/sudoers.d/developers')).toBe(true)
  })
  it('matches file in sudo/ dir', () => {
    expect(match('SUDOERS_PRIVILEGE_DRIFT', 'sudo/policy')).toBe(true)
  })
  it('does not match unrelated file named sudo', () => {
    expect(match('SUDOERS_PRIVILEGE_DRIFT', 'docs/sudo-guide.md')).toBe(false)
  })
  it('does not match random config outside sudoers dirs', () => {
    expect(match('SUDOERS_PRIVILEGE_DRIFT', 'config/access.conf')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// GRUB_BOOTLOADER_SECURITY_DRIFT
// ---------------------------------------------------------------------------

describe('GRUB_BOOTLOADER_SECURITY_DRIFT', () => {
  it('matches grub.cfg', () => {
    expect(match('GRUB_BOOTLOADER_SECURITY_DRIFT', 'boot/grub/grub.cfg')).toBe(true)
  })
  it('matches grub.cfg at root', () => {
    expect(match('GRUB_BOOTLOADER_SECURITY_DRIFT', 'grub.cfg')).toBe(true)
  })
  it('matches grub.conf legacy', () => {
    expect(match('GRUB_BOOTLOADER_SECURITY_DRIFT', 'grub.conf')).toBe(true)
  })
  it('matches grub2.cfg', () => {
    expect(match('GRUB_BOOTLOADER_SECURITY_DRIFT', 'grub2.cfg')).toBe(true)
  })
  it('matches grubenv', () => {
    expect(match('GRUB_BOOTLOADER_SECURITY_DRIFT', 'boot/grub2/grubenv')).toBe(true)
  })
  it('matches user.cfg GRUB password file', () => {
    expect(match('GRUB_BOOTLOADER_SECURITY_DRIFT', 'user.cfg')).toBe(true)
  })
  it('matches /etc/default/grub path', () => {
    expect(match('GRUB_BOOTLOADER_SECURITY_DRIFT', 'etc/default/grub')).toBe(true)
  })
  it('matches grub.cfg.j2 template', () => {
    expect(match('GRUB_BOOTLOADER_SECURITY_DRIFT', 'templates/grub.cfg.j2')).toBe(true)
  })
  it('matches .cfg in grub.d/', () => {
    expect(match('GRUB_BOOTLOADER_SECURITY_DRIFT', 'etc/grub.d/40_custom.cfg')).toBe(true)
  })
  it('matches .conf in grub/ dir', () => {
    expect(match('GRUB_BOOTLOADER_SECURITY_DRIFT', 'grub/grub.conf')).toBe(true)
  })
  it('does not match random file named grub outside default/', () => {
    expect(match('GRUB_BOOTLOADER_SECURITY_DRIFT', 'docs/grub')).toBe(false)
  })
  it('does not match unrelated .cfg outside grub dirs', () => {
    expect(match('GRUB_BOOTLOADER_SECURITY_DRIFT', 'config/app.cfg')).toBe(false)
  })
  it('does not match user.cfg outside GRUB context (but base is globally unambiguous)', () => {
    // user.cfg is in GRUB_UNGATED — matches anywhere since it's unambiguous
    expect(match('GRUB_BOOTLOADER_SECURITY_DRIFT', 'user.cfg')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// SELINUX_POLICY_DRIFT
// ---------------------------------------------------------------------------

describe('SELINUX_POLICY_DRIFT', () => {
  it('matches semanage.conf', () => {
    expect(match('SELINUX_POLICY_DRIFT', 'etc/semanage.conf')).toBe(true)
  })
  it('matches selinux.conf', () => {
    expect(match('SELINUX_POLICY_DRIFT', 'selinux.conf')).toBe(true)
  })
  it('matches /etc/selinux/config', () => {
    expect(match('SELINUX_POLICY_DRIFT', 'etc/selinux/config')).toBe(true)
  })
  it('does not match config outside selinux path', () => {
    expect(match('SELINUX_POLICY_DRIFT', 'app/config')).toBe(false)
  })
  it('matches selinux-hardening.conf prefix', () => {
    expect(match('SELINUX_POLICY_DRIFT', 'selinux-hardening.conf')).toBe(true)
  })
  it('matches .te type-enforcement file in selinux/ dir', () => {
    expect(match('SELINUX_POLICY_DRIFT', 'selinux/myapp.te')).toBe(true)
  })
  it('matches .fc file-context file in etc/selinux/', () => {
    expect(match('SELINUX_POLICY_DRIFT', 'etc/selinux/targeted/contexts/files/file_contexts.fc')).toBe(true)
  })
  it('matches .pp policy package in selinux-policy/', () => {
    expect(match('SELINUX_POLICY_DRIFT', 'selinux-policy/myapp.pp')).toBe(true)
  })
  it('matches .cil policy in selinux/ dir', () => {
    expect(match('SELINUX_POLICY_DRIFT', 'selinux/base.cil')).toBe(true)
  })
  it('matches .conf in selinux-config/', () => {
    expect(match('SELINUX_POLICY_DRIFT', 'selinux-config/local.conf')).toBe(true)
  })
  it('does not match .te outside selinux dirs', () => {
    expect(match('SELINUX_POLICY_DRIFT', 'tests/myapp.te')).toBe(false)
  })
  it('does not match random .conf outside selinux dirs', () => {
    expect(match('SELINUX_POLICY_DRIFT', 'config/app.conf')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// OS_ACCESS_CONTROL_DRIFT
// ---------------------------------------------------------------------------

describe('OS_ACCESS_CONTROL_DRIFT', () => {
  it('matches hosts.allow', () => {
    expect(match('OS_ACCESS_CONTROL_DRIFT', 'etc/hosts.allow')).toBe(true)
  })
  it('matches hosts.deny', () => {
    expect(match('OS_ACCESS_CONTROL_DRIFT', 'etc/hosts.deny')).toBe(true)
  })
  it('matches at.allow', () => {
    expect(match('OS_ACCESS_CONTROL_DRIFT', 'at.allow')).toBe(true)
  })
  it('matches at.deny', () => {
    expect(match('OS_ACCESS_CONTROL_DRIFT', 'at.deny')).toBe(true)
  })
  it('matches cron.allow', () => {
    expect(match('OS_ACCESS_CONTROL_DRIFT', 'cron.allow')).toBe(true)
  })
  it('matches cron.deny', () => {
    expect(match('OS_ACCESS_CONTROL_DRIFT', 'cron.deny')).toBe(true)
  })
  it('matches securetty', () => {
    expect(match('OS_ACCESS_CONTROL_DRIFT', 'etc/securetty')).toBe(true)
  })
  it('matches nologin', () => {
    expect(match('OS_ACCESS_CONTROL_DRIFT', 'etc/nologin')).toBe(true)
  })
  it('matches ftpusers', () => {
    expect(match('OS_ACCESS_CONTROL_DRIFT', 'etc/ftpusers')).toBe(true)
  })
  it('matches .rhosts rsh trust file', () => {
    expect(match('OS_ACCESS_CONTROL_DRIFT', 'home/user/.rhosts')).toBe(true)
  })
  it('matches hosts.equiv', () => {
    expect(match('OS_ACCESS_CONTROL_DRIFT', 'etc/hosts.equiv')).toBe(true)
  })
  it('does not match hosts (unrelated)', () => {
    expect(match('OS_ACCESS_CONTROL_DRIFT', 'etc/hosts')).toBe(false)
  })
  it('does not match generic access file outside known names', () => {
    expect(match('OS_ACCESS_CONTROL_DRIFT', 'config/access-rules.yaml')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// NTP_TIMESYNC_SECURITY_DRIFT
// ---------------------------------------------------------------------------

describe('NTP_TIMESYNC_SECURITY_DRIFT', () => {
  it('matches ntp.conf', () => {
    expect(match('NTP_TIMESYNC_SECURITY_DRIFT', 'etc/ntp.conf')).toBe(true)
  })
  it('matches ntpd.conf', () => {
    expect(match('NTP_TIMESYNC_SECURITY_DRIFT', 'ntpd.conf')).toBe(true)
  })
  it('matches chrony.conf', () => {
    expect(match('NTP_TIMESYNC_SECURITY_DRIFT', 'etc/chrony.conf')).toBe(true)
  })
  it('matches chronyd.conf', () => {
    expect(match('NTP_TIMESYNC_SECURITY_DRIFT', 'chronyd.conf')).toBe(true)
  })
  it('matches timesyncd.conf', () => {
    expect(match('NTP_TIMESYNC_SECURITY_DRIFT', 'etc/systemd/timesyncd.conf')).toBe(true)
  })
  it('matches ntp.keys', () => {
    expect(match('NTP_TIMESYNC_SECURITY_DRIFT', 'ntp.keys')).toBe(true)
  })
  it('matches chrony.keys', () => {
    expect(match('NTP_TIMESYNC_SECURITY_DRIFT', 'chrony.keys')).toBe(true)
  })
  it('matches ntp.conf.j2 template', () => {
    expect(match('NTP_TIMESYNC_SECURITY_DRIFT', 'templates/ntp.conf.j2')).toBe(true)
  })
  it('matches chrony.conf.bak', () => {
    expect(match('NTP_TIMESYNC_SECURITY_DRIFT', 'chrony.conf.bak')).toBe(true)
  })
  it('matches ntp-servers.conf prefix', () => {
    expect(match('NTP_TIMESYNC_SECURITY_DRIFT', 'ntp-servers.conf')).toBe(true)
  })
  it('matches chrony-pools.conf prefix', () => {
    expect(match('NTP_TIMESYNC_SECURITY_DRIFT', 'chrony-pools.conf')).toBe(true)
  })
  it('matches .conf in ntp/ dir', () => {
    expect(match('NTP_TIMESYNC_SECURITY_DRIFT', 'ntp/local.conf')).toBe(true)
  })
  it('matches .conf in chrony/ dir', () => {
    expect(match('NTP_TIMESYNC_SECURITY_DRIFT', 'chrony/chrony.conf')).toBe(true)
  })
  it('matches .conf in timesync/ dir', () => {
    expect(match('NTP_TIMESYNC_SECURITY_DRIFT', 'timesync/peers.conf')).toBe(true)
  })
  it('does not match generic .conf outside ntp dirs', () => {
    expect(match('NTP_TIMESYNC_SECURITY_DRIFT', 'config/server.conf')).toBe(false)
  })
  it('does not match time-related log files', () => {
    expect(match('NTP_TIMESYNC_SECURITY_DRIFT', 'logs/ntp.log')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// OS_LOGIN_BANNER_DRIFT (via isOsLoginBannerFile + rule.match)
// ---------------------------------------------------------------------------

describe('OS_LOGIN_BANNER_DRIFT', () => {
  it('matches /etc/issue', () => {
    expect(match('OS_LOGIN_BANNER_DRIFT', 'etc/issue')).toBe(true)
  })
  it('matches issue at root', () => {
    expect(match('OS_LOGIN_BANNER_DRIFT', 'issue')).toBe(true)
  })
  it('matches issue.net', () => {
    expect(match('OS_LOGIN_BANNER_DRIFT', 'etc/issue.net')).toBe(true)
  })
  it('matches motd', () => {
    expect(match('OS_LOGIN_BANNER_DRIFT', 'etc/motd')).toBe(true)
  })
  it('matches fragment in motd.d/', () => {
    expect(match('OS_LOGIN_BANNER_DRIFT', 'etc/motd.d/10-security-notice')).toBe(true)
  })
  it('matches fragment in issue.d/', () => {
    expect(match('OS_LOGIN_BANNER_DRIFT', 'etc/issue.d/banner')).toBe(true)
  })
  it('matches script in update-motd.d/', () => {
    expect(match('OS_LOGIN_BANNER_DRIFT', 'etc/update-motd.d/00-header')).toBe(true)
  })
  it('matches file in login-banners/', () => {
    expect(match('OS_LOGIN_BANNER_DRIFT', 'login-banners/legal-notice.txt')).toBe(true)
  })
  it('matches file in banners/', () => {
    expect(match('OS_LOGIN_BANNER_DRIFT', 'banners/ssh-banner.txt')).toBe(true)
  })
  it('does not match /etc/hosts', () => {
    expect(match('OS_LOGIN_BANNER_DRIFT', 'etc/hosts')).toBe(false)
  })
  it('does not match README.md', () => {
    expect(match('OS_LOGIN_BANNER_DRIFT', 'README.md')).toBe(false)
  })
  it('does not match profile.d script by default', () => {
    expect(match('OS_LOGIN_BANNER_DRIFT', 'etc/profile.d/security.sh')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// isOsLoginBannerFile direct tests
// ---------------------------------------------------------------------------

describe('isOsLoginBannerFile', () => {
  it('returns true for issue', () => {
    expect(isOsLoginBannerFile('etc/issue', 'issue')).toBe(true)
  })
  it('returns true for issue.net', () => {
    expect(isOsLoginBannerFile('etc/issue.net', 'issue.net')).toBe(true)
  })
  it('returns true for motd', () => {
    expect(isOsLoginBannerFile('etc/motd', 'motd')).toBe(true)
  })
  it('returns true for file in motd.d/', () => {
    expect(isOsLoginBannerFile('etc/motd.d/10-notice', '10-notice')).toBe(true)
  })
  it('returns false for /etc/passwd', () => {
    expect(isOsLoginBannerFile('etc/passwd', 'passwd')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// scanOsSecurityHardeningDrift integration
// ---------------------------------------------------------------------------

describe('scanOsSecurityHardeningDrift', () => {
  it('returns clean result for empty input', () => {
    const r = scanOsSecurityHardeningDrift([])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
    expect(r.totalFindings).toBe(0)
    expect(r.findings).toHaveLength(0)
    expect(r.summary).toMatch(/no.*os security hardening/i)
  })

  it('returns clean result for unrelated files', () => {
    const r = scanOsSecurityHardeningDrift(['src/app.ts', 'package.json', 'README.md'])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })

  it('detects sshd_config as high finding', () => {
    const r = scanOsSecurityHardeningDrift(['etc/ssh/sshd_config'])
    expect(r.highCount).toBe(1)
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('medium')
    expect(r.findings[0]?.ruleId).toBe('SSH_SERVER_CONFIG_DRIFT')
  })

  it('detects sysctl.conf as high finding', () => {
    const r = scanOsSecurityHardeningDrift(['etc/sysctl.conf'])
    expect(r.highCount).toBe(1)
    expect(r.riskScore).toBe(15)
    const ids = r.findings.map((f) => f.ruleId)
    expect(ids).toContain('SYSCTL_KERNEL_HARDENING_DRIFT')
  })

  it('detects sudoers as high finding', () => {
    const r = scanOsSecurityHardeningDrift(['etc/sudoers'])
    expect(r.highCount).toBe(1)
    expect(r.findings[0]?.ruleId).toBe('SUDOERS_PRIVILEGE_DRIFT')
  })

  it('detects /etc/default/grub as high finding', () => {
    const r = scanOsSecurityHardeningDrift(['etc/default/grub'])
    expect(r.highCount).toBe(1)
    expect(r.findings[0]?.ruleId).toBe('GRUB_BOOTLOADER_SECURITY_DRIFT')
  })

  it('detects hosts.allow as medium finding', () => {
    const r = scanOsSecurityHardeningDrift(['etc/hosts.allow'])
    expect(r.mediumCount).toBe(1)
    expect(r.findings[0]?.ruleId).toBe('OS_ACCESS_CONTROL_DRIFT')
  })

  it('detects chrony.conf as medium finding', () => {
    const r = scanOsSecurityHardeningDrift(['etc/chrony.conf'])
    expect(r.mediumCount).toBe(1)
    expect(r.findings[0]?.ruleId).toBe('NTP_TIMESYNC_SECURITY_DRIFT')
  })

  it('detects /etc/selinux/config as medium finding', () => {
    const r = scanOsSecurityHardeningDrift(['etc/selinux/config'])
    expect(r.mediumCount).toBe(1)
    expect(r.findings[0]?.ruleId).toBe('SELINUX_POLICY_DRIFT')
  })

  it('detects /etc/issue as low finding', () => {
    const r = scanOsSecurityHardeningDrift(['etc/issue'])
    expect(r.lowCount).toBe(1)
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
    expect(r.findings[0]?.ruleId).toBe('OS_LOGIN_BANNER_DRIFT')
  })

  it('skips vendor directory paths', () => {
    const r = scanOsSecurityHardeningDrift([
      'vendor/os-hardening/sysctl.conf',
      'node_modules/some-pkg/sshd_config',
    ])
    expect(r.totalFindings).toBe(0)
  })

  it('accumulates matchCount across multiple files for the same rule', () => {
    const r = scanOsSecurityHardeningDrift([
      'etc/ssh/sshd_config',
      'etc/ssh/sshd_config.d/10-hardening.conf',
      'etc/ssh/sshd_config.d/20-ciphers.conf',
    ])
    const f = r.findings.find((x) => x.ruleId === 'SSH_SERVER_CONFIG_DRIFT')
    expect(f?.matchCount).toBe(3)
    expect(f?.matchedPath).toBe('etc/ssh/sshd_config')
  })

  it('only one finding per rule regardless of match count', () => {
    const r = scanOsSecurityHardeningDrift([
      'etc/sudoers',
      'etc/sudoers.d/90-admin',
      'etc/sudoers.d/50-devs',
    ])
    expect(r.findings.filter((f) => f.ruleId === 'SUDOERS_PRIVILEGE_DRIFT')).toHaveLength(1)
  })

  it('scores two high findings correctly', () => {
    const r = scanOsSecurityHardeningDrift(['etc/sysctl.conf', 'etc/ssh/sshd_config'])
    expect(r.riskScore).toBe(30) // 2 × 15
    expect(r.riskLevel).toBe('medium')
    expect(r.highCount).toBe(2)
  })

  it('scores all four high findings at cap 45', () => {
    const r = scanOsSecurityHardeningDrift([
      'etc/sysctl.conf',
      'etc/ssh/sshd_config',
      'etc/sudoers',
      'etc/default/grub',
    ])
    // 4 HIGH findings: 4 × 15 = 60 but cap at 45; score 45 → 'high' (not < 45)
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
    expect(r.highCount).toBe(4)
  })

  it('scores mixed findings: two high + two medium', () => {
    const r = scanOsSecurityHardeningDrift([
      'etc/sysctl.conf',
      'etc/ssh/sshd_config',
      'etc/hosts.allow',
      'etc/chrony.conf',
    ])
    // HIGH cap: min(2×15, 45) = 30; MEDIUM cap: min(2×8, 25) = 16; total = 46
    expect(r.riskScore).toBe(46)
    expect(r.riskLevel).toBe('high')
    expect(r.highCount).toBe(2)
    expect(r.mediumCount).toBe(2)
  })

  it('scores all 8 rules', () => {
    const r = scanOsSecurityHardeningDrift([
      'etc/sysctl.conf',
      'etc/ssh/sshd_config',
      'etc/sudoers',
      'etc/default/grub',
      'etc/selinux/config',
      'etc/hosts.allow',
      'etc/chrony.conf',
      'etc/issue',
    ])
    // HIGH: min(4×15, 45)=45; MEDIUM: min(3×8, 25)=24; LOW: min(1×4, 15)=4 → 73
    expect(r.riskScore).toBe(73)
    expect(r.riskLevel).toBe('high')
    expect(r.totalFindings).toBe(8)
  })

  it('summary mentions risk score and level for findings', () => {
    const r = scanOsSecurityHardeningDrift(['etc/ssh/sshd_config', 'etc/sudoers'])
    expect(r.summary).toMatch(/30\/100/)
    expect(r.summary).toMatch(/medium/i)
  })

  it('summary says clean for no findings', () => {
    const r = scanOsSecurityHardeningDrift(['src/index.ts'])
    expect(r.summary).toMatch(/no.*os security hardening/i)
  })

  it('handles Windows-style backslash paths', () => {
    const r = scanOsSecurityHardeningDrift(['etc\\ssh\\sshd_config'])
    expect(r.totalFindings).toBe(1)
    expect(r.findings[0]?.ruleId).toBe('SSH_SERVER_CONFIG_DRIFT')
  })

  it('matchedPath preserves original casing', () => {
    const r = scanOsSecurityHardeningDrift(['Etc/SSH/sshd_config'])
    expect(r.findings[0]?.matchedPath).toBe('Etc/SSH/sshd_config')
  })
})

// ---------------------------------------------------------------------------
// Risk level boundary tests
// ---------------------------------------------------------------------------

describe('risk level boundaries', () => {
  it('score 0 → none', () => {
    const r = scanOsSecurityHardeningDrift([])
    expect(r.riskLevel).toBe('none')
  })

  it('score 4 (1 LOW) → low', () => {
    const r = scanOsSecurityHardeningDrift(['etc/issue'])
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('score 15 (1 HIGH) → medium', () => {
    const r = scanOsSecurityHardeningDrift(['etc/sysctl.conf'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('medium')
  })

  it('score 45 (3 HIGH) → high (45 is not < 45 so boundary is "high")', () => {
    const r = scanOsSecurityHardeningDrift([
      'etc/sysctl.conf',
      'etc/ssh/sshd_config',
      'etc/sudoers',
    ])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('score 46 (2 HIGH + 2 MEDIUM) → high', () => {
    const r = scanOsSecurityHardeningDrift([
      'etc/sysctl.conf',
      'etc/ssh/sshd_config',
      'etc/hosts.allow',
      'etc/chrony.conf',
    ])
    expect(r.riskScore).toBe(46)
    expect(r.riskLevel).toBe('high')
  })

  it('score 73 (all 8 rules) → high', () => {
    const r = scanOsSecurityHardeningDrift([
      'etc/sysctl.conf',
      'etc/ssh/sshd_config',
      'etc/sudoers',
      'etc/default/grub',
      'etc/selinux/config',
      'etc/hosts.allow',
      'etc/chrony.conf',
      'etc/issue',
    ])
    // HIGH: min(4×15,45)=45; MEDIUM: min(3×8,25)=24; LOW: min(1×4,15)=4 → 73
    expect(r.riskScore).toBe(73)
    expect(r.riskLevel).toBe('high')
  })
})
