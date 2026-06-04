// WS-76 — Email Security Configuration Drift Detector:
// pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to email server and mail transport security configuration files. This scanner
// focuses on the *mail transport layer* — configurations that control how email
// is sent, received, authenticated, filtered, and routed: MTA core configs,
// DKIM signing keys, SASL authentication, anti-spam filters, TLS parameters,
// relay restrictions, access control policies, and header/body filter rules.
//
// DISTINCT from:
//   WS-60  securityConfigDrift       — application-level TLS/session/CORS
//                                      options inside backend service code
//   WS-66  certPkiDrift              — certificate and PKI key material;
//                                      WS-76 covers mail-specific TLS params
//   WS-68  networkFirewallDrift      — OS-level firewall (iptables, nftables);
//                                      WS-76 covers mail relay restriction maps
//   WS-75  webServerSecurityDrift    — HTTP/S ingress edge (nginx, Apache,
//                                      Traefik); WS-76 covers SMTP/IMAP edge
//
// Covered rule groups (8 rules):
//
//   SMTP_SERVER_CONFIG_DRIFT         — MTA core configs (Postfix/Sendmail/Exim/Dovecot)
//   DKIM_SIGNING_CONFIG_DRIFT        — DKIM key material and OpenDKIM/DMARC configs
//   MAIL_AUTH_SASL_DRIFT             — SASL authentication for mail relay (user)
//   ANTISPAM_FILTER_DRIFT            — SpamAssassin / Rspamd / Amavis anti-spam
//   MAIL_TLS_SECURITY_DRIFT          — SMTP/IMAP/POP3 TLS configuration
//   MAIL_RELAY_RESTRICTIONS_DRIFT    — Relay routing, virtual domain, transport maps
//   MAIL_ACCESS_POLICY_DRIFT         — Sender/recipient/client access control
//   MAIL_HEADER_FILTER_DRIFT         — Header/body checks and milter policies
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Vendor directory exclusion applied to all paths.
//   • Same penalty/cap scoring model as WS-60–75 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (matchedPath + matchCount).
//   • sendmail.cf / sendmail.mc / exim.conf / exim4.conf / dovecot.conf are
//     globally unambiguous MTA filenames.
//   • opendkim.conf / opendmarc.conf are globally unambiguous signing configs.
//   • amavisd.conf / amavis.conf are globally unambiguous Amavis configs.
//   • main.cf / master.cf gated on postfix/ dir to avoid ambiguity.
//   • isMailAuthSaslConfig is the user contribution — see JSDoc below.
//
// Exports:
//   isMailAuthSaslConfig     — user contribution point (see JSDoc below)
//   EMAIL_SECURITY_RULES     — readonly rule registry
//   scanEmailSecurityDrift   — main scanner, returns EmailSecurityDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type EmailSecurityRuleId =
  | 'SMTP_SERVER_CONFIG_DRIFT'
  | 'DKIM_SIGNING_CONFIG_DRIFT'
  | 'MAIL_AUTH_SASL_DRIFT'
  | 'ANTISPAM_FILTER_DRIFT'
  | 'MAIL_TLS_SECURITY_DRIFT'
  | 'MAIL_RELAY_RESTRICTIONS_DRIFT'
  | 'MAIL_ACCESS_POLICY_DRIFT'
  | 'MAIL_HEADER_FILTER_DRIFT'

export type EmailSecuritySeverity = 'high' | 'medium' | 'low'
export type EmailSecurityRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type EmailSecurityDriftFinding = {
  ruleId: EmailSecurityRuleId
  severity: EmailSecuritySeverity
  matchedPath: string
  matchCount: number
  description: string
  recommendation: string
}

export type EmailSecurityDriftResult = {
  riskScore: number
  riskLevel: EmailSecurityRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: EmailSecurityDriftFinding[]
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
]

function isVendor(p: string): boolean {
  return VENDOR_DIRS.some((v) => p.includes(v))
}

// ---------------------------------------------------------------------------
// Directory sets used for gating ambiguous filenames
// ---------------------------------------------------------------------------

const POSTFIX_DIRS   = ['postfix/', 'postfix.d/']
const DOVECOT_DIRS   = ['dovecot/', 'dovecot.d/']
const DKIM_DIRS      = ['dkim/', 'opendkim/', 'keys/dkim/', 'dkim-keys/']
const SASL_DIRS      = ['sasl/', 'postfix/sasl/', 'cyrus-sasl/', 'sasl2/']
const RSPAMD_DIRS    = ['rspamd/', 'rspamd/local.d/', 'rspamd/override.d/']
const MILTER_DIRS    = ['milter/', 'milters/', 'opendkim/', 'opendmarc/']
const MAIL_DIRS      = [
  'mail/', 'email/', 'smtp/', 'postfix/', 'dovecot/',
  'exim/', 'sendmail/', 'mailserver/', 'mailconfig/',
]
const SPAMASSASSIN_DIRS = [
  'spamassassin/', 'mail/spamassassin/', '.spamassassin/',
  'mail/spamassassin/', 'spam/',
]

function inAnyDir(pathLower: string, dirs: readonly string[]): boolean {
  return dirs.some((d) => pathLower.includes(d))
}

// ---------------------------------------------------------------------------
// Rule 1: SMTP_SERVER_CONFIG_DRIFT (high)
// Core MTA (Mail Transfer Agent) configuration files
// ---------------------------------------------------------------------------

const SMTP_UNGATED = new Set([
  'sendmail.cf',
  'sendmail.mc',
  'exim.conf',
  'exim4.conf',
  'dovecot.conf',
])

function isSmtpServerConfig(pathLower: string, base: string): boolean {
  if (SMTP_UNGATED.has(base)) return true

  // Postfix-gated: main.cf and master.cf require postfix/ context
  if (inAnyDir(pathLower, POSTFIX_DIRS)) {
    if (base === 'main.cf' || base === 'master.cf') return true
    if (base.endsWith('.cf') && base !== 'local.cf') return true
  }

  // Dovecot sub-configs (e.g. dovecot/10-master.conf, dovecot/10-ssl.conf)
  if (inAnyDir(pathLower, DOVECOT_DIRS) && base.endsWith('.conf')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 2: DKIM_SIGNING_CONFIG_DRIFT (high)
// DKIM signing key material and OpenDKIM/OpenDMARC daemon configs
// ---------------------------------------------------------------------------

function isDkimSigningConfig(pathLower: string, base: string): boolean {
  // Globally unambiguous daemon configs
  if (base === 'opendkim.conf' || base === 'opendmarc.conf') return true

  // DKIM directory context: key material and DNS record files
  if (inAnyDir(pathLower, DKIM_DIRS)) {
    if (base.endsWith('.private')) return true
    if (base.endsWith('.key')) return true
    // DKIM DNS TXT record files (e.g. mail._domainkey.txt)
    if (base.endsWith('.txt') && base.includes('domainkey')) return true
    if (base === 'signing.conf' || base === 'dkim.conf') return true
    if (base.endsWith('.conf')) return true
  }

  // dkim- prefixed config files (e.g. dkim-selector.conf)
  if (base.startsWith('dkim-') && (base.endsWith('.conf') || base.endsWith('.key'))) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 3: MAIL_AUTH_SASL_DRIFT (high)  — USER CONTRIBUTION
//
// Detects changes to SASL (Simple Authentication and Security Layer)
// authentication configuration files used for mail relay auth. SASL is the
// mechanism by which SMTP clients authenticate to the mail server before
// relaying — a misconfigured SASL policy can open an open relay or break
// all outbound mail.
//
// User contribution: implement the detection logic for your SASL stack.
//
// Considerations when implementing:
//   1. Scope: Limit to mail-SASL context (not all SASL consumers).
//      `smtpd.conf` in `sasl/` is very specific; `sasl.conf` outside
//      mail dirs could match OpenLDAP, HTTP auth, or SSH.
//   2. Implementations: Postfix uses Cyrus SASL (smtpd.conf in sasl/),
//      Dovecot has its own SASL, Exim has inline SASL. saslauthd is the
//      Cyrus SASL auth daemon used by many MTAs.
//   3. Strategy options:
//      a. Strict: only canonical SASL filenames (smtpd.conf in sasl/ dir,
//         saslauthd.conf, cyrus.conf) — fewest false positives.
//      b. Broad: any *.conf in any sasl/ directory — catches more configs
//         but may flag non-mail SASL (e.g. OpenLDAP sasl/).
//      c. Hybrid (recommended): canonical names ungated + sasl.conf gated
//         on mail-adjacent dirs.
//
// Parameters:
//   pathLower — fully lowercased, forward-slash normalised path
//   base      — lowercased basename (filename without directory)
//
// Returns true if the file looks like a mail SASL configuration file.
// ---------------------------------------------------------------------------

export function isMailAuthSaslConfig(pathLower: string, base: string): boolean {
  // Canonical Cyrus SASL daemon config — globally specific to SASL
  if (base === 'saslauthd.conf') return true

  // Cyrus IMAP server config (also manages SASL for mail auth)
  if (base === 'cyrus.conf') return true

  // smtpd.conf inside a sasl/ directory — this is the primary Postfix+SASL
  // configuration file that controls what SASL mechanisms Postfix advertises
  if (base === 'smtpd.conf' && inAnyDir(pathLower, SASL_DIRS)) return true

  // Any *.conf inside a SASL-specific directory
  if (inAnyDir(pathLower, SASL_DIRS) && base.endsWith('.conf')) return true

  // sasl.conf gated on mail-adjacent directory to avoid matching
  // OpenLDAP / Apache httpd sasl.conf which live outside mail dirs
  if (base === 'sasl.conf' && inAnyDir(pathLower, MAIL_DIRS)) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 4: ANTISPAM_FILTER_DRIFT (medium)
// SpamAssassin, Rspamd, Amavis, and ClamAV content filtering
// ---------------------------------------------------------------------------

const SPAMASSASSIN_UNGATED = new Set(['amavisd.conf', 'amavis.conf', 'rspamd.conf'])

function isAntiSpamFilterConfig(pathLower: string, base: string): boolean {
  if (SPAMASSASSIN_UNGATED.has(base)) return true

  // SpamAssassin local ruleset — local.cf outside spamassassin dirs can be generic
  if (inAnyDir(pathLower, SPAMASSASSIN_DIRS)) {
    if (base === 'local.cf' || base === 'spamassassin.conf' || base.endsWith('.cf')) return true
  }

  // sa-update channel / standalone configs
  if (base === 'sa-update.conf' || base === 'spamassassin.conf') return true

  // Rspamd configs in rspamd/ subdirs
  if (inAnyDir(pathLower, RSPAMD_DIRS) && base.endsWith('.conf')) return true

  // ClamAV in mail context (clamd is used as Amavis content scanner)
  if (base === 'clamd.conf' && inAnyDir(pathLower, MAIL_DIRS)) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 5: MAIL_TLS_SECURITY_DRIFT (medium)
// SMTP/IMAP/POP3 TLS configuration (mail transport TLS, not web TLS)
// Distinct from WS-75 (nginx SSL termination) and WS-66 (PKI cert material).
// ---------------------------------------------------------------------------

const MAIL_TLS_UNGATED = new Set([
  'smtp-tls.conf',
  'smtpd-tls.conf',
  'dovecot-ssl.conf',
  'imapd-ssl.conf',
  'pop3d-ssl.conf',
  'imapd.conf',
  'pop3d.conf',
])

function isMailTlsConfig(pathLower: string, base: string): boolean {
  if (MAIL_TLS_UNGATED.has(base)) return true

  // TLS-named files inside Postfix TLS directory
  if (pathLower.includes('postfix/tls/') && base.endsWith('.conf')) return true

  // TLS/SSL named files inside mail-adjacent directories
  if (
    inAnyDir(pathLower, MAIL_DIRS) &&
    (base.includes('tls') || base.includes('ssl')) &&
    base.endsWith('.conf')
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 6: MAIL_RELAY_RESTRICTIONS_DRIFT (medium)
// Mail relay routing, virtual domain, and transport map configs.
// All gated on postfix/ directory (Postfix-specific lookup tables).
// ---------------------------------------------------------------------------

const RELAY_MAP_NAMES = new Set([
  'relay_domains',
  'transport',
  'virtual',
  'relay_recipients',
  'canonical',
  'relocated',
  'virtual_alias_maps',
  'transport_maps',
])

function isMailRelayRestrictionsConfig(pathLower: string, base: string): boolean {
  // Postfix lookup tables — gated to avoid matching unrelated 'transport' files
  if (inAnyDir(pathLower, POSTFIX_DIRS) && RELAY_MAP_NAMES.has(base)) return true

  // Smarthost/relay config in mail dirs
  if (base === 'smarthost.conf' && inAnyDir(pathLower, MAIL_DIRS)) return true
  if (base === 'relayhost.conf' && inAnyDir(pathLower, MAIL_DIRS)) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 7: MAIL_ACCESS_POLICY_DRIFT (medium)
// Postfix sender/recipient/client access control tables.
// All gated on postfix/ directory — the Postfix access map filenames
// ('access', 'sender_access') are too generic without path context.
// ---------------------------------------------------------------------------

const ACCESS_MAP_NAMES = new Set([
  'access',
  'client_access',
  'sender_access',
  'recipient_access',
  'helo_access',
  'restrictions.cf',
  'restrictions.conf',
  'blacklist_senders',
  'whitelist_senders',
  'blocked_senders',
])

function isMailAccessPolicyConfig(pathLower: string, base: string): boolean {
  if (inAnyDir(pathLower, POSTFIX_DIRS) && ACCESS_MAP_NAMES.has(base)) return true
  return false
}

// ---------------------------------------------------------------------------
// Rule 8: MAIL_HEADER_FILTER_DRIFT (low)
// Email header/body content check policies and milter configurations.
// ---------------------------------------------------------------------------

const HEADER_FILTER_NAMES = new Set([
  'header_checks',
  'body_checks',
  'mime_header_checks',
  'nested_header_checks',
  'smtp_header_checks',
])

function isMailHeaderFilterConfig(pathLower: string, base: string): boolean {
  // Postfix content filter tables
  if (inAnyDir(pathLower, POSTFIX_DIRS) && HEADER_FILTER_NAMES.has(base)) return true

  // Milter daemon configs (OpenDKIM, OpenDMARC, Rspamd milter)
  if (inAnyDir(pathLower, MILTER_DIRS) && base.endsWith('.conf')) return true

  // Generic content filter config in mail dirs
  if (base === 'content_filter.conf' && inAnyDir(pathLower, MAIL_DIRS)) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

export const EMAIL_SECURITY_RULES: ReadonlyArray<{
  id: EmailSecurityRuleId
  severity: EmailSecuritySeverity
  description: string
  recommendation: string
  match: (pathLower: string, base: string) => boolean
}> = [
  {
    id: 'SMTP_SERVER_CONFIG_DRIFT',
    severity: 'high',
    description: 'MTA configuration change detected (Postfix/Sendmail/Exim/Dovecot).',
    recommendation:
      'Audit MTA config for open-relay settings, VRFY/EXPN exposure, and auth requirements before deployment.',
    match: isSmtpServerConfig,
  },
  {
    id: 'DKIM_SIGNING_CONFIG_DRIFT',
    severity: 'high',
    description: 'DKIM signing key or OpenDKIM/DMARC configuration change detected.',
    recommendation:
      'Verify DKIM selector matches DNS TXT record and private key has not been rotated without updating DNS.',
    match: isDkimSigningConfig,
  },
  {
    id: 'MAIL_AUTH_SASL_DRIFT',
    severity: 'high',
    description: 'SASL mail relay authentication configuration change detected.',
    recommendation:
      'Review SASL mechanism list (disable PLAIN/LOGIN over unencrypted connections) and restrict authenticated relay to known IPs.',
    match: isMailAuthSaslConfig,
  },
  {
    id: 'ANTISPAM_FILTER_DRIFT',
    severity: 'medium',
    description: 'Anti-spam or content filter configuration change detected (SpamAssassin/Rspamd/Amavis).',
    recommendation:
      'Ensure spam thresholds, RBL lookups, and DKIM/SPF check policies remain appropriately strict.',
    match: isAntiSpamFilterConfig,
  },
  {
    id: 'MAIL_TLS_SECURITY_DRIFT',
    severity: 'medium',
    description: 'Mail transport TLS configuration change detected (SMTP/IMAP/POP3 TLS).',
    recommendation:
      'Confirm TLS version floor is TLS 1.2+, weak cipher suites are disabled, and STARTTLS is mandatory for relay.',
    match: isMailTlsConfig,
  },
  {
    id: 'MAIL_RELAY_RESTRICTIONS_DRIFT',
    severity: 'medium',
    description: 'Mail relay routing or virtual domain configuration change detected.',
    recommendation:
      'Verify relay_domains, transport maps, and virtual aliases do not inadvertently enable open relay.',
    match: isMailRelayRestrictionsConfig,
  },
  {
    id: 'MAIL_ACCESS_POLICY_DRIFT',
    severity: 'medium',
    description: 'Mail access control policy change detected (sender/recipient/client ACL).',
    recommendation:
      'Review access maps for overly permissive entries; ensure blocklists and allowlists are current.',
    match: isMailAccessPolicyConfig,
  },
  {
    id: 'MAIL_HEADER_FILTER_DRIFT',
    severity: 'low',
    description: 'Email header/body filter or milter configuration change detected.',
    recommendation:
      'Audit header_checks and body_checks regexes for gaps that could allow spoofed headers or malformed MIME through.',
    match: isMailHeaderFilterConfig,
  },
]

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

const SEVERITY_PENALTIES: Record<EmailSecuritySeverity, { per: number; cap: number }> = {
  high:   { per: 15, cap: 45 },
  medium: { per: 8,  cap: 25 },
  low:    { per: 4,  cap: 15 },
}

function computeRiskScore(findings: EmailSecurityDriftFinding[]): number {
  let score = 0
  for (const f of findings) {
    const { per, cap } = SEVERITY_PENALTIES[f.severity]
    score += Math.min(f.matchCount * per, cap)
  }
  return Math.min(score, 100)
}

function computeRiskLevel(score: number): EmailSecurityRiskLevel {
  if (score === 0) return 'none'
  if (score < 20)  return 'low'
  if (score < 45)  return 'medium'
  if (score < 70)  return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Main scanner
// ---------------------------------------------------------------------------

export function scanEmailSecurityDrift(changedFiles: string[]): EmailSecurityDriftResult {
  // Normalise path separators (Windows → POSIX) and lowercase
  const normalise = (p: string) => p.replace(/\\/g, '/').toLowerCase()

  const findings: EmailSecurityDriftFinding[] = []

  for (const rule of EMAIL_SECURITY_RULES) {
    let firstPath = ''
    let matchCount = 0

    for (const raw of changedFiles) {
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
  const ORDER: Record<EmailSecuritySeverity, number> = { high: 0, medium: 1, low: 2 }
  findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity])

  const riskScore = computeRiskScore(findings)
  const riskLevel = computeRiskLevel(riskScore)
  const highCount   = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount    = findings.filter((f) => f.severity === 'low').length

  const summary =
    findings.length === 0
      ? 'No email security configuration changes detected.'
      : `${findings.length} email security rule${findings.length === 1 ? '' : 's'} triggered ` +
        `(${[
          highCount   ? `${highCount} high`   : '',
          mediumCount ? `${mediumCount} medium` : '',
          lowCount    ? `${lowCount} low`    : '',
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
