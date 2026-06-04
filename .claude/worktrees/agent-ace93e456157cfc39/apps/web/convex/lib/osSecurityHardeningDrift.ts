// WS-89 — Operating System Security Hardening Configuration Drift Detector:
// pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to OS-level security hardening configuration: Linux kernel security parameters
// (sysctl.conf), SSH server daemon configuration (sshd_config), sudo privilege
// escalation policy (sudoers/sudoers.d), GRUB bootloader security settings,
// SELinux mandatory-access-control policy, OS-level access control files
// (hosts.allow/deny, cron.allow, at.allow, securetty), NTP/time-synchronisation
// daemon configuration (critical for certificate validation and log forensics),
// and OS login banner/MOTD configuration (compliance-required warning banners).
//
// DISTINCT from:
//   WS-67  runtimeSecurityDrift    — auditd.conf/audit.rules (kernel audit);
//                                    AppArmor/seccomp in container/k8s context;
//                                    Falco/OPA runtime policy enforcement;
//                                    WS-89 covers host-level OS hardening config
//   WS-68  networkFirewallDrift    — iptables/nftables/UFW/firewalld packet-filter
//                                    rules; WS-89 covers TCP-wrappers (hosts.allow/
//                                    deny) and cron/at access control — a distinct
//                                    and older OS-level access control layer
//   WS-70  identityAccessDrift     — pam.d/ authentication stack, LDAP/sssd.conf,
//                                    Vault policies; WS-89 covers sudoers privilege
//                                    escalation and OS account security settings,
//                                    not identity provider configuration
//   WS-83  cfgMgmtSecurityDrift    — Ansible/Puppet/Chef/Salt toolchain configs;
//                                    those tools DEPLOY the files WS-89 monitors,
//                                    not the hardening configs themselves
//   WS-84  vpnRemoteAccessDrift    — OpenVPN/WireGuard/IPsec daemon configs;
//                                    WS-89 covers the SSH daemon (sshd_config),
//                                    which is a different remote-access primitive
//
// Covered rule groups (8 rules):
//
//   SYSCTL_KERNEL_HARDENING_DRIFT  — Kernel security parameters: ASLR, exec-shield,
//                                    source-route filtering, SYN cookies, core dump
//                                    suppression, Yama LSM (sysctl.conf, sysctl.d/)
//   SSH_SERVER_CONFIG_DRIFT        — OpenSSH daemon configuration: authentication
//                                    methods, cipher suites, key exchange, privilege
//                                    separation, X11 forwarding (sshd_config,
//                                    sshd_config.d/)
//   SUDOERS_PRIVILEGE_DRIFT        — Sudo privilege escalation policy: NOPASSWD
//                                    grants, rule ordering, host/user aliases
//                                    (sudoers, sudoers.d/ directory)
//   GRUB_BOOTLOADER_SECURITY_DRIFT — GRUB2 bootloader security: boot password,
//                                    kernel cmdline hardening (selinux=1, apparmor=1,
//                                    lockdown, init= override prevention), secure
//                                    boot config (/etc/default/grub, grub.cfg)
//   SELINUX_POLICY_DRIFT           — SELinux mode and policy: enforcing/permissive/
//                                    disabled mode, policy type, semanage rules,
//                                    type-enforcement policy files
//   OS_ACCESS_CONTROL_DRIFT        — OS-level service and login access control:
//                                    TCP-wrappers (hosts.allow/deny), cron.allow/
//                                    cron.deny, at.allow/at.deny, securetty, nologin
//   NTP_TIMESYNC_SECURITY_DRIFT    — NTP and time-sync daemon configuration:
//                                    chrony.conf, ntp.conf, timesyncd.conf — a
//                                    tampered time-sync config can invalidate TLS
//                                    certificates and corrupt log forensics
//   OS_LOGIN_BANNER_DRIFT          — OS login banner and MOTD: /etc/issue,
//                                    /etc/issue.net, /etc/motd — required by many
//                                    security frameworks (CIS, DISA STIG) for legal
//                                    notice before interactive login
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Vendor directory exclusion applied to all paths before rule evaluation.
//   • Same penalty/cap scoring model as WS-60–88 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (firstPath + matchCount).
//   • sysctl.conf/sshd_config/sudoers are globally unambiguous — ungated.
//   • /etc/default/grub is handled via path-segment detection (base='grub').
//   • All ungated Set entries stored lowercase (base is .toLowerCase()).
//   • SELinux 'config' file gated on path containing 'selinux' segment.
//   • hosts.allow/hosts.deny/at.allow/cron.allow are globally unambiguous.
//
// Exports:
//   isOsLoginBannerFile            — user contribution point (see JSDoc below)
//   OS_SECURITY_HARDENING_RULES    — readonly rule registry
//   scanOsSecurityHardeningDrift   — main scanner, returns OsSecurityHardeningDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type OsSecurityHardeningRuleId =
  | 'SYSCTL_KERNEL_HARDENING_DRIFT'
  | 'SSH_SERVER_CONFIG_DRIFT'
  | 'SUDOERS_PRIVILEGE_DRIFT'
  | 'GRUB_BOOTLOADER_SECURITY_DRIFT'
  | 'SELINUX_POLICY_DRIFT'
  | 'OS_ACCESS_CONTROL_DRIFT'
  | 'NTP_TIMESYNC_SECURITY_DRIFT'
  | 'OS_LOGIN_BANNER_DRIFT'

export type OsSecurityHardeningSeverity  = 'high' | 'medium' | 'low'
export type OsSecurityHardeningRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type OsSecurityHardeningFinding = {
  ruleId:         OsSecurityHardeningRuleId
  severity:       OsSecurityHardeningSeverity
  matchedPath:    string
  matchCount:     number
  description:    string
  recommendation: string
}

export type OsSecurityHardeningDriftResult = {
  riskScore:     number
  riskLevel:     OsSecurityHardeningRiskLevel
  totalFindings: number
  highCount:     number
  mediumCount:   number
  lowCount:      number
  findings:      OsSecurityHardeningFinding[]
  summary:       string
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

const SYSCTL_DIRS   = ['sysctl.d/', 'etc/sysctl.d/', 'security/sysctl.d/', 'hardening/', 'os-hardening/', 'kernel-hardening/']
const SSH_DIRS      = ['sshd/', 'ssh/', 'openssh/', 'ssh-config/', 'etc/ssh/', 'sshd_config.d/']
const SUDOERS_DIRS  = ['sudoers.d/', 'etc/sudoers.d/', 'sudo/', 'sudo-config/']
const GRUB_DIRS     = ['grub/', 'grub.d/', 'grub2/', 'grub2.d/', 'boot/grub/', 'boot/grub2/', 'etc/grub.d/', 'bootloader/', 'efi/']
const SELINUX_DIRS  = ['selinux/', '.selinux/', 'etc/selinux/', 'selinux-config/', 'selinux-policy/', 'mac/selinux/', 'mac/']
const NTP_DIRS      = ['ntp/', 'ntp-config/', 'chrony/', 'chrony-config/', 'ntpd/', 'etc/chrony/', 'etc/ntp/', 'timesync/', 'time-sync/', 'etc/systemd/']
const OS_BANNER_DIRS = ['issue.d/', 'motd.d/', 'etc/issue.d/', 'etc/motd.d/', 'login-banners/', 'banners/', 'update-motd.d/', 'etc/update-motd.d/']

function inAnyDir(pathLower: string, dirs: readonly string[]): boolean {
  return dirs.some((d) => pathLower.includes(d))
}

// ---------------------------------------------------------------------------
// Rule 1: SYSCTL_KERNEL_HARDENING_DRIFT (high)
// Kernel security parameters
// ---------------------------------------------------------------------------

const SYSCTL_UNGATED = new Set([
  'sysctl.conf',   // main Linux kernel parameter file — globally unambiguous
  'sysctl.d',      // directory name as path segment
])

function isSysctlKernelHardeningConfig(pathLower: string, base: string): boolean {
  if (SYSCTL_UNGATED.has(base)) return true

  // sysctl.conf.j2 / sysctl.conf.bak / sysctl.conf.ansible
  if (base.startsWith('sysctl.conf.') || base.startsWith('sysctl.conf-')) return true

  // numbered drop-ins in sysctl.d/ (e.g. 99-hardening.conf, 10-network-security.conf)
  if (inAnyDir(pathLower, SYSCTL_DIRS) && base.endsWith('.conf')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 2: SSH_SERVER_CONFIG_DRIFT (high)
// OpenSSH daemon configuration
// ---------------------------------------------------------------------------

const SSH_UNGATED = new Set([
  'sshd_config',      // OpenSSH daemon — globally unambiguous
  'ssh_config',       // OpenSSH client — globally unambiguous; client settings affect key exchange & ciphers
])

function isSshServerConfig(pathLower: string, base: string): boolean {
  if (SSH_UNGATED.has(base)) return true

  // template variants: sshd_config.j2, sshd_config.bak, sshd_config.prod
  if (base.startsWith('sshd_config.') || base.startsWith('sshd_config-')) return true

  // drop-ins in /etc/ssh/sshd_config.d/
  if (inAnyDir(pathLower, SSH_DIRS) && base.endsWith('.conf')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 3: SUDOERS_PRIVILEGE_DRIFT (high)
// Sudo privilege escalation policy
// ---------------------------------------------------------------------------

const SUDOERS_UNGATED = new Set([
  'sudoers',       // main sudo policy file — globally unambiguous
  'sudoers.tmp',   // transient write (visudo uses this)
])

function isSudoersConfig(pathLower: string, base: string): boolean {
  if (SUDOERS_UNGATED.has(base)) return true

  // template variants: sudoers.j2, sudoers.conf
  if (base.startsWith('sudoers.') || base.startsWith('sudoers-')) return true

  // sudoers.d/ drop-in files have no standard extension (e.g. /etc/sudoers.d/90-admin)
  if (inAnyDir(pathLower, SUDOERS_DIRS)) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 4: GRUB_BOOTLOADER_SECURITY_DRIFT (high)
// GRUB2 bootloader security configuration
// ---------------------------------------------------------------------------

const GRUB_UNGATED = new Set([
  'grub.cfg',     // GRUB2 generated config — globally unambiguous
  'grub.conf',    // legacy GRUB1 config — globally unambiguous
  'grub2.cfg',    // GRUB2 on Red Hat variant — globally unambiguous
  'grubenv',      // GRUB environment block — globally unambiguous
  'user.cfg',     // GRUB2 password hash store — globally unambiguous
])

function isGrubBootloaderConfig(pathLower: string, base: string): boolean {
  if (GRUB_UNGATED.has(base)) return true

  // /etc/default/grub — bare name 'grub', path contains 'default/'
  if (base === 'grub' && pathLower.includes('default/')) return true

  // grub.cfg.j2 / grub.conf.bak
  if (base.startsWith('grub.cfg.') || base.startsWith('grub.conf.') || base.startsWith('grub2.cfg.')) return true

  if (!inAnyDir(pathLower, GRUB_DIRS)) return false

  if (base.endsWith('.cfg') || base.endsWith('.conf') || base === 'grubenv') return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 5: SELINUX_POLICY_DRIFT (medium)
// SELinux mode and policy configuration
// ---------------------------------------------------------------------------

const SELINUX_UNGATED = new Set([
  'semanage.conf',   // SELinux policy management daemon config — globally unambiguous
  'selinux.conf',    // alternative top-level SELinux config name
])

function isSelinuxPolicyConfig(pathLower: string, base: string): boolean {
  if (SELINUX_UNGATED.has(base)) return true

  // /etc/selinux/config — base is 'config', path must contain 'selinux'
  if (base === 'config' && pathLower.includes('selinux')) return true

  // selinux-*.conf / selinux-policy-*.conf
  if (base.startsWith('selinux-') && base.endsWith('.conf')) return true

  if (!inAnyDir(pathLower, SELINUX_DIRS)) return false

  // Type-enforcement, file-context, interface, policy-package files
  if (
    base.endsWith('.conf') || base.endsWith('.te') ||
    base.endsWith('.fc')   || base.endsWith('.if') ||
    base.endsWith('.pp')   || base.endsWith('.cil')
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 6: OS_ACCESS_CONTROL_DRIFT (medium)
// TCP-wrappers, cron/at access control, login restrictions
// ---------------------------------------------------------------------------

const OS_ACCESS_UNGATED = new Set([
  'hosts.allow',  // TCP-wrappers allowlist — globally unambiguous
  'hosts.deny',   // TCP-wrappers blocklist — globally unambiguous
  'at.allow',     // at(1) scheduling allowlist — globally unambiguous
  'at.deny',      // at(1) scheduling blocklist — globally unambiguous
  'cron.allow',   // cron scheduling allowlist — globally unambiguous
  'cron.deny',    // cron scheduling blocklist — globally unambiguous
  'securetty',    // list of secure TTY devices for root login — globally unambiguous
  'nologin',      // prevents interactive logins when present — globally unambiguous
  'ftpusers',     // FTP user access control file — globally unambiguous
])

function isOsAccessControlFile(_pathLower: string, base: string): boolean {
  if (OS_ACCESS_UNGATED.has(base)) return true

  // .rhosts / hosts.equiv — rsh trust files, high-risk if committed
  if (base === '.rhosts' || base === 'hosts.equiv') return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 7: NTP_TIMESYNC_SECURITY_DRIFT (medium)
// NTP and time-synchronisation daemon configuration
// ---------------------------------------------------------------------------

const NTP_UNGATED = new Set([
  'ntp.conf',         // ntpd daemon config — globally unambiguous
  'ntpd.conf',        // alternative ntpd config name — globally unambiguous
  'chrony.conf',      // chrony daemon config — globally unambiguous
  'chronyd.conf',     // alternative chrony name — globally unambiguous
  'timesyncd.conf',   // systemd-timesyncd config — globally unambiguous
  'ntp.keys',         // NTP authentication keys — globally unambiguous
  'chrony.keys',      // chrony authentication keys — globally unambiguous
])

function isNtpTimesyncConfig(pathLower: string, base: string): boolean {
  if (NTP_UNGATED.has(base)) return true

  // template variants
  if (base.startsWith('ntp.conf.') || base.startsWith('chrony.conf.')) return true
  if (base.startsWith('ntp-') && base.endsWith('.conf')) return true
  if (base.startsWith('chrony-') && base.endsWith('.conf')) return true

  // timesyncd.conf drop-ins in systemd/
  if (pathLower.includes('systemd/') && (base === 'timesyncd.conf' || base.endsWith('.conf') && pathLower.includes('timesync'))) return true

  if (!inAnyDir(pathLower, NTP_DIRS)) return false

  if (base.endsWith('.conf') || base.endsWith('.keys')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 8: OS_LOGIN_BANNER_DRIFT (low) — USER CONTRIBUTION
// OS login banner and MOTD configuration
// ---------------------------------------------------------------------------

/**
 * Determine whether `path` is an OS login banner or message-of-the-day file.
 * Called for the LOW-severity OS_LOGIN_BANNER_DRIFT rule.
 *
 * The path is already confirmed NOT to be a vendor path. `base` is the
 * lowercase, normalised filename. `pathLower` is the full normalised path
 * in lowercase.
 *
 * Implement the body: decide whether to also flag shell scripts in profile.d/
 * that display security notices (broader coverage, more false positives), or
 * restrict to the canonical /etc/issue, /etc/issue.net, and /etc/motd files
 * only (narrowest, safest). Many compliance frameworks (CIS Benchmark, DISA
 * STIG) require a specific legal warning in /etc/issue.net; flagging only the
 * canonical files makes that traceable.
 *
 * Return true if the file should trigger the OS_LOGIN_BANNER_DRIFT finding.
 */
export function isOsLoginBannerFile(pathLower: string, base: string): boolean {
  // Globally unambiguous banner files
  if (base === 'issue' || base === 'issue.net' || base === 'motd') return true

  // motd.d/ and issue.d/ fragments (systemd and update-motd.d/ scripts)
  if (inAnyDir(pathLower, OS_BANNER_DIRS)) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

interface OsSecurityHardeningRule {
  id:             OsSecurityHardeningRuleId
  severity:       OsSecurityHardeningSeverity
  description:    string
  recommendation: string
  match:          (pathLower: string, base: string) => boolean
}

export const OS_SECURITY_HARDENING_RULES: readonly OsSecurityHardeningRule[] = [
  {
    id:             'SYSCTL_KERNEL_HARDENING_DRIFT',
    severity:       'high',
    description:    'Linux kernel security parameter configuration changed (sysctl.conf or sysctl.d/ drop-in). Kernel hardening settings like ASLR, SYN-cookie protection, source-route filtering, and Yama LSM controls can be degraded silently.',
    recommendation: 'Review the changed sysctl parameter file. Validate that ASLR (kernel.randomize_va_space=2), SYN-cookie (net.ipv4.tcp_syncookies=1), source-route filtering (net.ipv4.conf.all.accept_source_route=0), and Yama (kernel.yama.ptrace_scope≥1) settings are preserved. Use CIS Benchmark Level 2 as the authoritative reference.',
    match:          isSysctlKernelHardeningConfig,
  },
  {
    id:             'SSH_SERVER_CONFIG_DRIFT',
    severity:       'high',
    description:    'OpenSSH server or client configuration changed (sshd_config, ssh_config, or sshd_config.d/ drop-in). SSH daemon settings govern allowed authentication methods, cipher suites, MACs, and privilege separation — changes can weaken remote-access security.',
    recommendation: 'Review the changed SSH configuration. Ensure PermitRootLogin is disabled, PasswordAuthentication is off, Protocol 2 is enforced, weak ciphers (arcfour, 3des-cbc, blowfish-cbc) are excluded, and X11Forwarding is disabled unless explicitly required.',
    match:          isSshServerConfig,
  },
  {
    id:             'SUDOERS_PRIVILEGE_DRIFT',
    severity:       'high',
    description:    'Sudo privilege escalation policy changed (sudoers or sudoers.d/ drop-in). Sudoers rules control which users can run commands as root; a weakened policy (broad NOPASSWD, ALL=(ALL) grants) can enable privilege escalation.',
    recommendation: 'Review the changed sudoers rule. Ensure NOPASSWD is not granted to unprivileged users, wildcard commands are replaced with explicit paths, and Defaults rules enforce requiretty and logging. All sudoers changes should be peer-reviewed.',
    match:          isSudoersConfig,
  },
  {
    id:             'GRUB_BOOTLOADER_SECURITY_DRIFT',
    severity:       'high',
    description:    'GRUB bootloader configuration changed (grub.cfg, /etc/default/grub, or grub.d/ script). Boot-time configuration controls kernel cmdline parameters (selinux=1, apparmor=1, init=, lockdown=), GRUB password protection, and Secure Boot integration.',
    recommendation: 'Review the changed GRUB configuration. Ensure a GRUB superuser password is set, kernel cmdline includes security options (selinux=1 or apparmor=1, lockdown=integrity), and init= overrides are not present. Re-run grub-mkconfig after any security-related change.',
    match:          isGrubBootloaderConfig,
  },
  {
    id:             'SELINUX_POLICY_DRIFT',
    severity:       'medium',
    description:    'SELinux mode or policy configuration changed (/etc/selinux/config, semanage.conf, or type-enforcement policy files). A switch from enforcing to permissive/disabled removes mandatory access control protection across the entire system.',
    recommendation: 'Review the changed SELinux configuration. Ensure SELINUX=enforcing is set in /etc/selinux/config, SELINUXTYPE matches the intended policy (targeted or mls), and any new semanage rules have been reviewed for overly permissive contexts.',
    match:          isSelinuxPolicyConfig,
  },
  {
    id:             'OS_ACCESS_CONTROL_DRIFT',
    severity:       'medium',
    description:    'OS-level service access control configuration changed (hosts.allow, hosts.deny, cron.allow, at.allow, securetty, or .rhosts). TCP-wrappers and cron/at access control files define which hosts and users may connect to daemons or schedule jobs.',
    recommendation: 'Review the changed access control file. Ensure hosts.deny blocks unexpected hosts before hosts.allow permits them, cron.allow/at.allow list only authorized users, securetty lists only physical terminal devices, and .rhosts files are not committed to version control.',
    match:          isOsAccessControlFile,
  },
  {
    id:             'NTP_TIMESYNC_SECURITY_DRIFT',
    severity:       'medium',
    description:    'NTP or time-synchronisation daemon configuration changed (chrony.conf, ntp.conf, or timesyncd.conf). A tampered time-sync config can redirect time sources to attacker-controlled servers, invalidating TLS certificates and corrupting log forensic timelines.',
    recommendation: 'Review the changed NTP configuration. Ensure NTP sources are trusted, authenticated servers (NTS or symmetric key auth enabled), the restrict directive limits control-channel access, and no rogue pool or server entries have been added. Verify chrony or ntpd is running and synced after any change.',
    match:          isNtpTimesyncConfig,
  },
  {
    id:             'OS_LOGIN_BANNER_DRIFT',
    severity:       'low',
    description:    'OS login banner or MOTD configuration changed (/etc/issue, /etc/issue.net, /etc/motd, or motd.d/ fragment). Many compliance frameworks (CIS Benchmark, DISA STIG) require a specific legal warning banner before interactive login; removal or weakening may constitute a compliance gap.',
    recommendation: 'Review the changed banner file. Ensure the legal notice informs users that the system is monitored, unauthorised access is prohibited, and sessions may be recorded. Do not include system or version information that aids attacker reconnaissance.',
    match:          isOsLoginBannerFile,
  },
]

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

const PENALTY: Record<OsSecurityHardeningSeverity, number> = { high: 15, medium: 8, low: 4 }
const CAP:     Record<OsSecurityHardeningSeverity, number> = { high: 45, medium: 25, low: 15 }
const SCORE_MAX = 100

function computeRiskLevel(score: number): OsSecurityHardeningRiskLevel {
  if (score === 0)  return 'none'
  if (score < 15)   return 'low'
  if (score < 45)   return 'medium'
  if (score < 80)   return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

export function scanOsSecurityHardeningDrift(changedFiles: string[]): OsSecurityHardeningDriftResult {
  const clean = changedFiles
    .map((f) => f.replace(/\\/g, '/'))
    .filter((f) => !isVendor(f))

  const findings: OsSecurityHardeningFinding[] = []

  for (const rule of OS_SECURITY_HARDENING_RULES) {
    let firstPath  = ''
    let matchCount = 0

    for (const path of clean) {
      const pathLower = path.toLowerCase()
      const base      = pathLower.split('/').pop() ?? pathLower
      if (rule.match(pathLower, base)) {
        matchCount++
        if (!firstPath) firstPath = path
      }
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

  // Penalty/cap scoring
  const accumulated: Record<OsSecurityHardeningSeverity, number> = { high: 0, medium: 0, low: 0 }
  for (const f of findings) {
    accumulated[f.severity] = Math.min(
      accumulated[f.severity] + PENALTY[f.severity],
      CAP[f.severity],
    )
  }
  const raw   = accumulated.high + accumulated.medium + accumulated.low
  const score = Math.min(raw, SCORE_MAX)

  const highCount   = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount    = findings.filter((f) => f.severity === 'low').length

  const riskLevel = computeRiskLevel(score)

  let summary: string
  if (findings.length === 0) {
    summary = 'No OS security hardening configuration changes detected.'
  } else {
    const parts: string[] = []
    if (highCount)   parts.push(`${highCount} high-severity`)
    if (mediumCount) parts.push(`${mediumCount} medium-severity`)
    if (lowCount)    parts.push(`${lowCount} low-severity`)
    summary = `OS security hardening drift detected: ${parts.join(', ')} finding${findings.length !== 1 ? 's' : ''} (risk score ${score}/100, level: ${riskLevel}).`
  }

  return {
    riskScore:     score,
    riskLevel,
    totalFindings: findings.length,
    highCount,
    mediumCount,
    lowCount,
    findings,
    summary,
  }
}
