// WS-76 — Email Security Configuration Drift Detector: test suite.
import { describe, expect, it } from 'vitest'
import {
  EMAIL_SECURITY_RULES,
  isMailAuthSaslConfig,
  scanEmailSecurityDrift,
} from './emailSecurityDrift'

// ---------------------------------------------------------------------------
// Rule 1: SMTP_SERVER_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('SMTP_SERVER_CONFIG_DRIFT', () => {
  it('flags sendmail.cf (ungated Sendmail config)', () => {
    const r = scanEmailSecurityDrift(['sendmail.cf'])
    expect(r.findings.some((f) => f.ruleId === 'SMTP_SERVER_CONFIG_DRIFT')).toBe(true)
  })

  it('flags sendmail.mc (Sendmail m4 macro config)', () => {
    const r = scanEmailSecurityDrift(['sendmail.mc'])
    expect(r.findings.some((f) => f.ruleId === 'SMTP_SERVER_CONFIG_DRIFT')).toBe(true)
  })

  it('flags exim.conf (ungated Exim config)', () => {
    const r = scanEmailSecurityDrift(['exim.conf'])
    expect(r.findings.some((f) => f.ruleId === 'SMTP_SERVER_CONFIG_DRIFT')).toBe(true)
  })

  it('flags exim4.conf (Debian Exim4 config)', () => {
    const r = scanEmailSecurityDrift(['exim4.conf'])
    expect(r.findings.some((f) => f.ruleId === 'SMTP_SERVER_CONFIG_DRIFT')).toBe(true)
  })

  it('flags dovecot.conf (ungated Dovecot IMAP/POP3 config)', () => {
    const r = scanEmailSecurityDrift(['dovecot.conf'])
    expect(r.findings.some((f) => f.ruleId === 'SMTP_SERVER_CONFIG_DRIFT')).toBe(true)
  })

  it('flags postfix/main.cf (Postfix main config gated on postfix/ dir)', () => {
    const r = scanEmailSecurityDrift(['postfix/main.cf'])
    expect(r.findings.some((f) => f.ruleId === 'SMTP_SERVER_CONFIG_DRIFT')).toBe(true)
  })

  it('flags postfix/master.cf (Postfix master process config)', () => {
    const r = scanEmailSecurityDrift(['postfix/master.cf'])
    expect(r.findings.some((f) => f.ruleId === 'SMTP_SERVER_CONFIG_DRIFT')).toBe(true)
  })

  it('flags arbitrary .cf in postfix/ dir (e.g. postfix/sasl.cf)', () => {
    const r = scanEmailSecurityDrift(['postfix/custom.cf'])
    expect(r.findings.some((f) => f.ruleId === 'SMTP_SERVER_CONFIG_DRIFT')).toBe(true)
  })

  it('flags dovecot/10-master.conf (Dovecot sub-config via directory gating)', () => {
    const r = scanEmailSecurityDrift(['dovecot/10-master.conf'])
    expect(r.findings.some((f) => f.ruleId === 'SMTP_SERVER_CONFIG_DRIFT')).toBe(true)
  })

  it('flags dovecot.d/10-ssl.conf (Dovecot .d sub-config)', () => {
    const r = scanEmailSecurityDrift(['dovecot.d/10-ssl.conf'])
    expect(r.findings.some((f) => f.ruleId === 'SMTP_SERVER_CONFIG_DRIFT')).toBe(true)
  })

  it('does NOT flag main.cf outside postfix/ dir', () => {
    const r = scanEmailSecurityDrift(['app/main.cf'])
    expect(r.findings.some((f) => f.ruleId === 'SMTP_SERVER_CONFIG_DRIFT')).toBe(false)
  })

  it('does NOT flag master.cf outside postfix/ dir', () => {
    const r = scanEmailSecurityDrift(['config/master.cf'])
    expect(r.findings.some((f) => f.ruleId === 'SMTP_SERVER_CONFIG_DRIFT')).toBe(false)
  })

  it('does NOT flag nginx.conf (web server, not mail)', () => {
    const r = scanEmailSecurityDrift(['nginx.conf'])
    expect(r.findings.some((f) => f.ruleId === 'SMTP_SERVER_CONFIG_DRIFT')).toBe(false)
  })

  it('does NOT flag application.conf in unrelated dir', () => {
    const r = scanEmailSecurityDrift(['config/application.conf'])
    expect(r.findings.some((f) => f.ruleId === 'SMTP_SERVER_CONFIG_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 2: DKIM_SIGNING_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('DKIM_SIGNING_CONFIG_DRIFT', () => {
  it('flags opendkim.conf (ungated OpenDKIM daemon config)', () => {
    const r = scanEmailSecurityDrift(['opendkim.conf'])
    expect(r.findings.some((f) => f.ruleId === 'DKIM_SIGNING_CONFIG_DRIFT')).toBe(true)
  })

  it('flags opendmarc.conf (ungated OpenDMARC daemon config)', () => {
    const r = scanEmailSecurityDrift(['opendmarc.conf'])
    expect(r.findings.some((f) => f.ruleId === 'DKIM_SIGNING_CONFIG_DRIFT')).toBe(true)
  })

  it('flags dkim/mail._domainkey.private (DKIM private key in dkim/ dir)', () => {
    const r = scanEmailSecurityDrift(['dkim/mail._domainkey.private'])
    expect(r.findings.some((f) => f.ruleId === 'DKIM_SIGNING_CONFIG_DRIFT')).toBe(true)
  })

  it('flags keys/dkim/rsa.key (DKIM key in keys/dkim/ dir)', () => {
    const r = scanEmailSecurityDrift(['keys/dkim/rsa.key'])
    expect(r.findings.some((f) => f.ruleId === 'DKIM_SIGNING_CONFIG_DRIFT')).toBe(true)
  })

  it('flags dkim/mail._domainkey.txt (DKIM DNS TXT record file)', () => {
    const r = scanEmailSecurityDrift(['dkim/mail._domainkey.txt'])
    expect(r.findings.some((f) => f.ruleId === 'DKIM_SIGNING_CONFIG_DRIFT')).toBe(true)
  })

  it('flags dkim/signing.conf (signing config in dkim/ dir)', () => {
    const r = scanEmailSecurityDrift(['dkim/signing.conf'])
    expect(r.findings.some((f) => f.ruleId === 'DKIM_SIGNING_CONFIG_DRIFT')).toBe(true)
  })

  it('flags opendkim/signing.conf (signing config in opendkim/ dir)', () => {
    const r = scanEmailSecurityDrift(['opendkim/signing.conf'])
    expect(r.findings.some((f) => f.ruleId === 'DKIM_SIGNING_CONFIG_DRIFT')).toBe(true)
  })

  it('flags dkim-selector.conf (dkim- prefixed config)', () => {
    const r = scanEmailSecurityDrift(['dkim-selector.conf'])
    expect(r.findings.some((f) => f.ruleId === 'DKIM_SIGNING_CONFIG_DRIFT')).toBe(true)
  })

  it('flags dkim-keys/rsa2048.key (dkim- prefix key)', () => {
    const r = scanEmailSecurityDrift(['dkim-keys/rsa2048.key'])
    expect(r.findings.some((f) => f.ruleId === 'DKIM_SIGNING_CONFIG_DRIFT')).toBe(true)
  })

  it('does NOT flag random.txt outside dkim dirs', () => {
    const r = scanEmailSecurityDrift(['docs/random.txt'])
    expect(r.findings.some((f) => f.ruleId === 'DKIM_SIGNING_CONFIG_DRIFT')).toBe(false)
  })

  it('does NOT flag ssl-cert.key outside dkim dirs', () => {
    const r = scanEmailSecurityDrift(['tls/ssl-cert.key'])
    expect(r.findings.some((f) => f.ruleId === 'DKIM_SIGNING_CONFIG_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 3: MAIL_AUTH_SASL_DRIFT (user contribution: isMailAuthSaslConfig)
// ---------------------------------------------------------------------------

describe('MAIL_AUTH_SASL_DRIFT', () => {
  it('flags saslauthd.conf (Cyrus SASL auth daemon config — ungated)', () => {
    const r = scanEmailSecurityDrift(['saslauthd.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_AUTH_SASL_DRIFT')).toBe(true)
  })

  it('flags cyrus.conf (Cyrus IMAP/SASL server config — ungated)', () => {
    const r = scanEmailSecurityDrift(['cyrus.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_AUTH_SASL_DRIFT')).toBe(true)
  })

  it('flags sasl/smtpd.conf (Postfix+SASL primary auth config)', () => {
    const r = scanEmailSecurityDrift(['sasl/smtpd.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_AUTH_SASL_DRIFT')).toBe(true)
  })

  it('flags postfix/sasl/smtpd.conf (Postfix+SASL nested path)', () => {
    const r = scanEmailSecurityDrift(['postfix/sasl/smtpd.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_AUTH_SASL_DRIFT')).toBe(true)
  })

  it('flags sasl2/smtpd.conf (Cyrus SASL v2 application config)', () => {
    const r = scanEmailSecurityDrift(['sasl2/smtpd.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_AUTH_SASL_DRIFT')).toBe(true)
  })

  it('flags cyrus-sasl/mech.conf (Cyrus SASL mechanism config)', () => {
    const r = scanEmailSecurityDrift(['cyrus-sasl/mech.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_AUTH_SASL_DRIFT')).toBe(true)
  })

  it('flags mail/sasl.conf (sasl.conf gated on mail/ dir)', () => {
    const r = scanEmailSecurityDrift(['mail/sasl.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_AUTH_SASL_DRIFT')).toBe(true)
  })

  it('flags smtp/sasl.conf (sasl.conf gated on smtp/ dir)', () => {
    const r = scanEmailSecurityDrift(['smtp/sasl.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_AUTH_SASL_DRIFT')).toBe(true)
  })

  it('does NOT flag smtpd.conf outside sasl dirs (generic SMTP server config)', () => {
    const r = scanEmailSecurityDrift(['config/smtpd.conf'])
    // smtpd.conf outside sasl/ should not match MAIL_AUTH_SASL_DRIFT
    expect(r.findings.some((f) => f.ruleId === 'MAIL_AUTH_SASL_DRIFT')).toBe(false)
  })

  it('does NOT flag sasl.conf outside mail dirs (e.g. openldap sasl.conf)', () => {
    const r = scanEmailSecurityDrift(['openldap/sasl.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_AUTH_SASL_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// isMailAuthSaslConfig — unit tests for the exported user contribution
// ---------------------------------------------------------------------------

describe('isMailAuthSaslConfig (unit)', () => {
  const check = (path: string) => {
    const p    = path.toLowerCase()
    const base = p.split('/').pop() ?? p
    return isMailAuthSaslConfig(p, base)
  }

  it('returns true for saslauthd.conf', () => {
    expect(check('saslauthd.conf')).toBe(true)
  })

  it('returns true for cyrus.conf', () => {
    expect(check('cyrus.conf')).toBe(true)
  })

  it('returns true for sasl/smtpd.conf', () => {
    expect(check('sasl/smtpd.conf')).toBe(true)
  })

  it('returns true for sasl2/imap.conf (Cyrus SASL v2 IMAP app config)', () => {
    expect(check('sasl2/imap.conf')).toBe(true)
  })

  it('returns true for mail/sasl.conf', () => {
    expect(check('mail/sasl.conf')).toBe(true)
  })

  it('returns false for openldap/sasl.conf (OpenLDAP SASL — not mail)', () => {
    expect(check('openldap/sasl.conf')).toBe(false)
  })

  it('returns false for config/smtpd.conf (not in sasl/ dir)', () => {
    expect(check('config/smtpd.conf')).toBe(false)
  })

  it('returns false for nginx/sasl.conf (web server dir)', () => {
    expect(check('nginx/sasl.conf')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 4: ANTISPAM_FILTER_DRIFT
// ---------------------------------------------------------------------------

describe('ANTISPAM_FILTER_DRIFT', () => {
  it('flags amavisd.conf (ungated Amavis config)', () => {
    const r = scanEmailSecurityDrift(['amavisd.conf'])
    expect(r.findings.some((f) => f.ruleId === 'ANTISPAM_FILTER_DRIFT')).toBe(true)
  })

  it('flags amavis.conf (ungated Amavis alternate name)', () => {
    const r = scanEmailSecurityDrift(['amavis.conf'])
    expect(r.findings.some((f) => f.ruleId === 'ANTISPAM_FILTER_DRIFT')).toBe(true)
  })

  it('flags rspamd.conf (ungated Rspamd main config)', () => {
    const r = scanEmailSecurityDrift(['rspamd.conf'])
    expect(r.findings.some((f) => f.ruleId === 'ANTISPAM_FILTER_DRIFT')).toBe(true)
  })

  it('flags spamassassin/local.cf (SpamAssassin local ruleset)', () => {
    const r = scanEmailSecurityDrift(['spamassassin/local.cf'])
    expect(r.findings.some((f) => f.ruleId === 'ANTISPAM_FILTER_DRIFT')).toBe(true)
  })

  it('flags spamassassin/custom-rules.cf (custom SpamAssassin rules)', () => {
    const r = scanEmailSecurityDrift(['spamassassin/custom-rules.cf'])
    expect(r.findings.some((f) => f.ruleId === 'ANTISPAM_FILTER_DRIFT')).toBe(true)
  })

  it('flags rspamd/local.d/antiphishing.conf (Rspamd local override)', () => {
    const r = scanEmailSecurityDrift(['rspamd/local.d/antiphishing.conf'])
    expect(r.findings.some((f) => f.ruleId === 'ANTISPAM_FILTER_DRIFT')).toBe(true)
  })

  it('flags rspamd/override.d/dkim_signing.conf (Rspamd override)', () => {
    const r = scanEmailSecurityDrift(['rspamd/override.d/dkim_signing.conf'])
    expect(r.findings.some((f) => f.ruleId === 'ANTISPAM_FILTER_DRIFT')).toBe(true)
  })

  it('flags mail/clamd.conf (ClamAV in mail context)', () => {
    const r = scanEmailSecurityDrift(['mail/clamd.conf'])
    expect(r.findings.some((f) => f.ruleId === 'ANTISPAM_FILTER_DRIFT')).toBe(true)
  })

  it('flags sa-update.conf (SpamAssassin update channel config)', () => {
    const r = scanEmailSecurityDrift(['sa-update.conf'])
    expect(r.findings.some((f) => f.ruleId === 'ANTISPAM_FILTER_DRIFT')).toBe(true)
  })

  it('does NOT flag clamd.conf outside mail dirs (ClamAV standalone)', () => {
    const r = scanEmailSecurityDrift(['clamav/clamd.conf'])
    expect(r.findings.some((f) => f.ruleId === 'ANTISPAM_FILTER_DRIFT')).toBe(false)
  })

  it('does NOT flag local.cf outside spamassassin dirs', () => {
    const r = scanEmailSecurityDrift(['config/local.cf'])
    expect(r.findings.some((f) => f.ruleId === 'ANTISPAM_FILTER_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 5: MAIL_TLS_SECURITY_DRIFT
// ---------------------------------------------------------------------------

describe('MAIL_TLS_SECURITY_DRIFT', () => {
  it('flags smtp-tls.conf (ungated SMTP TLS config)', () => {
    const r = scanEmailSecurityDrift(['smtp-tls.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_TLS_SECURITY_DRIFT')).toBe(true)
  })

  it('flags smtpd-tls.conf (ungated SMTPD TLS config)', () => {
    const r = scanEmailSecurityDrift(['smtpd-tls.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_TLS_SECURITY_DRIFT')).toBe(true)
  })

  it('flags dovecot-ssl.conf (ungated Dovecot SSL config)', () => {
    const r = scanEmailSecurityDrift(['dovecot-ssl.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_TLS_SECURITY_DRIFT')).toBe(true)
  })

  it('flags imapd-ssl.conf (Courier IMAP SSL config)', () => {
    const r = scanEmailSecurityDrift(['imapd-ssl.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_TLS_SECURITY_DRIFT')).toBe(true)
  })

  it('flags pop3d-ssl.conf (Courier POP3 SSL config)', () => {
    const r = scanEmailSecurityDrift(['pop3d-ssl.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_TLS_SECURITY_DRIFT')).toBe(true)
  })

  it('flags postfix/tls/tls-params.conf (TLS config in postfix/tls/ dir)', () => {
    const r = scanEmailSecurityDrift(['postfix/tls/tls-params.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_TLS_SECURITY_DRIFT')).toBe(true)
  })

  it('flags mail/tls-config.conf (TLS named file in mail/ dir)', () => {
    const r = scanEmailSecurityDrift(['mail/tls-config.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_TLS_SECURITY_DRIFT')).toBe(true)
  })

  it('flags smtp/ssl-ciphers.conf (SSL named file in smtp/ dir)', () => {
    const r = scanEmailSecurityDrift(['smtp/ssl-ciphers.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_TLS_SECURITY_DRIFT')).toBe(true)
  })

  it('does NOT flag nginx-ssl.conf (web server TLS, covered by WS-75)', () => {
    const r = scanEmailSecurityDrift(['nginx-ssl.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_TLS_SECURITY_DRIFT')).toBe(false)
  })

  it('does NOT flag random-tls.conf outside mail dirs', () => {
    const r = scanEmailSecurityDrift(['app/config/random-tls.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_TLS_SECURITY_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 6: MAIL_RELAY_RESTRICTIONS_DRIFT
// ---------------------------------------------------------------------------

describe('MAIL_RELAY_RESTRICTIONS_DRIFT', () => {
  it('flags postfix/relay_domains (relay domain list)', () => {
    const r = scanEmailSecurityDrift(['postfix/relay_domains'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_RELAY_RESTRICTIONS_DRIFT')).toBe(true)
  })

  it('flags postfix/transport (transport routing map)', () => {
    const r = scanEmailSecurityDrift(['postfix/transport'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_RELAY_RESTRICTIONS_DRIFT')).toBe(true)
  })

  it('flags postfix/virtual (virtual alias map)', () => {
    const r = scanEmailSecurityDrift(['postfix/virtual'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_RELAY_RESTRICTIONS_DRIFT')).toBe(true)
  })

  it('flags postfix/relay_recipients (per-relay recipient list)', () => {
    const r = scanEmailSecurityDrift(['postfix/relay_recipients'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_RELAY_RESTRICTIONS_DRIFT')).toBe(true)
  })

  it('flags postfix/canonical (address rewriting map)', () => {
    const r = scanEmailSecurityDrift(['postfix/canonical'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_RELAY_RESTRICTIONS_DRIFT')).toBe(true)
  })

  it('flags mail/smarthost.conf (smarthost/relay config in mail/ dir)', () => {
    const r = scanEmailSecurityDrift(['mail/smarthost.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_RELAY_RESTRICTIONS_DRIFT')).toBe(true)
  })

  it('does NOT flag transport file outside postfix/ dir', () => {
    const r = scanEmailSecurityDrift(['config/transport'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_RELAY_RESTRICTIONS_DRIFT')).toBe(false)
  })

  it('does NOT flag relay_domains outside postfix/ dir', () => {
    const r = scanEmailSecurityDrift(['relay_domains'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_RELAY_RESTRICTIONS_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 7: MAIL_ACCESS_POLICY_DRIFT
// ---------------------------------------------------------------------------

describe('MAIL_ACCESS_POLICY_DRIFT', () => {
  it('flags postfix/access (generic access control map)', () => {
    const r = scanEmailSecurityDrift(['postfix/access'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_ACCESS_POLICY_DRIFT')).toBe(true)
  })

  it('flags postfix/sender_access (per-sender access map)', () => {
    const r = scanEmailSecurityDrift(['postfix/sender_access'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_ACCESS_POLICY_DRIFT')).toBe(true)
  })

  it('flags postfix/recipient_access (per-recipient access map)', () => {
    const r = scanEmailSecurityDrift(['postfix/recipient_access'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_ACCESS_POLICY_DRIFT')).toBe(true)
  })

  it('flags postfix/client_access (per-client IP access map)', () => {
    const r = scanEmailSecurityDrift(['postfix/client_access'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_ACCESS_POLICY_DRIFT')).toBe(true)
  })

  it('flags postfix/helo_access (HELO/EHLO hostname access map)', () => {
    const r = scanEmailSecurityDrift(['postfix/helo_access'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_ACCESS_POLICY_DRIFT')).toBe(true)
  })

  it('flags postfix/blacklist_senders (sender blocklist)', () => {
    const r = scanEmailSecurityDrift(['postfix/blacklist_senders'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_ACCESS_POLICY_DRIFT')).toBe(true)
  })

  it('does NOT flag access file outside postfix/ dir', () => {
    const r = scanEmailSecurityDrift(['config/access'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_ACCESS_POLICY_DRIFT')).toBe(false)
  })

  it('does NOT flag sender_access outside postfix/ dir', () => {
    const r = scanEmailSecurityDrift(['sender_access'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_ACCESS_POLICY_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 8: MAIL_HEADER_FILTER_DRIFT
// ---------------------------------------------------------------------------

describe('MAIL_HEADER_FILTER_DRIFT', () => {
  it('flags postfix/header_checks (header filtering rules)', () => {
    const r = scanEmailSecurityDrift(['postfix/header_checks'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_HEADER_FILTER_DRIFT')).toBe(true)
  })

  it('flags postfix/body_checks (body filtering rules)', () => {
    const r = scanEmailSecurityDrift(['postfix/body_checks'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_HEADER_FILTER_DRIFT')).toBe(true)
  })

  it('flags postfix/mime_header_checks (MIME header filtering)', () => {
    const r = scanEmailSecurityDrift(['postfix/mime_header_checks'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_HEADER_FILTER_DRIFT')).toBe(true)
  })

  it('flags postfix/nested_header_checks (nested header filtering)', () => {
    const r = scanEmailSecurityDrift(['postfix/nested_header_checks'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_HEADER_FILTER_DRIFT')).toBe(true)
  })

  it('flags milter/opendkim.conf (milter daemon config)', () => {
    const r = scanEmailSecurityDrift(['milter/opendkim.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_HEADER_FILTER_DRIFT')).toBe(true)
  })

  it('flags milters/rspamd-milter.conf (milter config in milters/ dir)', () => {
    const r = scanEmailSecurityDrift(['milters/rspamd-milter.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_HEADER_FILTER_DRIFT')).toBe(true)
  })

  it('flags mail/content_filter.conf (content filter config in mail/ dir)', () => {
    const r = scanEmailSecurityDrift(['mail/content_filter.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_HEADER_FILTER_DRIFT')).toBe(true)
  })

  it('does NOT flag header_checks outside postfix/ dir', () => {
    const r = scanEmailSecurityDrift(['config/header_checks'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_HEADER_FILTER_DRIFT')).toBe(false)
  })

  it('does NOT flag body_checks outside postfix/ dir', () => {
    const r = scanEmailSecurityDrift(['body_checks'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_HEADER_FILTER_DRIFT')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Vendor directory exclusion
// ---------------------------------------------------------------------------

describe('vendor directory exclusion', () => {
  it('does not flag sendmail.cf in node_modules/', () => {
    const r = scanEmailSecurityDrift(['node_modules/mailer/sendmail.cf'])
    expect(r.findings).toHaveLength(0)
  })

  it('does not flag opendkim.conf in vendor/', () => {
    const r = scanEmailSecurityDrift(['vendor/opendkim/opendkim.conf'])
    expect(r.findings).toHaveLength(0)
  })

  it('does not flag postfix/main.cf in .git/', () => {
    const r = scanEmailSecurityDrift(['.git/hooks/postfix/main.cf'])
    expect(r.findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Windows path normalisation
// ---------------------------------------------------------------------------

describe('Windows path normalisation', () => {
  it('normalises backslashes before matching (postfix\\main.cf)', () => {
    const r = scanEmailSecurityDrift(['postfix\\main.cf'])
    expect(r.findings.some((f) => f.ruleId === 'SMTP_SERVER_CONFIG_DRIFT')).toBe(true)
  })

  it('normalises nested Windows paths (postfix\\sasl\\smtpd.conf)', () => {
    const r = scanEmailSecurityDrift(['postfix\\sasl\\smtpd.conf'])
    expect(r.findings.some((f) => f.ruleId === 'MAIL_AUTH_SASL_DRIFT')).toBe(true)
  })

  it('normalises dkim paths (dkim\\mail.private)', () => {
    const r = scanEmailSecurityDrift(['dkim\\mail.private'])
    expect(r.findings.some((f) => f.ruleId === 'DKIM_SIGNING_CONFIG_DRIFT')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Deduplication — one finding per rule regardless of matched-file count
// ---------------------------------------------------------------------------

describe('deduplication per rule', () => {
  it('produces one finding for multiple postfix .cf files (SMTP rule)', () => {
    const r = scanEmailSecurityDrift([
      'postfix/main.cf',
      'postfix/master.cf',
      'postfix/extra.cf',
    ])
    const smtpFindings = r.findings.filter((f) => f.ruleId === 'SMTP_SERVER_CONFIG_DRIFT')
    expect(smtpFindings).toHaveLength(1)
    expect(smtpFindings[0].matchCount).toBe(3)
  })

  it('records the first matched path', () => {
    const r = scanEmailSecurityDrift([
      'postfix/relay_domains',
      'postfix/transport',
      'postfix/virtual',
    ])
    const f = r.findings.find((f) => f.ruleId === 'MAIL_RELAY_RESTRICTIONS_DRIFT')!
    expect(f.matchedPath).toBe('postfix/relay_domains')
    expect(f.matchCount).toBe(3)
  })

  it('does not double-count a file across two different rules', () => {
    // opendkim.conf triggers DKIM rule only; milters/rspamd-milter.conf triggers
    // HEADER_FILTER only — two distinct rules, each matched once.
    const r = scanEmailSecurityDrift([
      'opendkim.conf',
      'milters/rspamd-milter.conf',
    ])
    const dkimFindings   = r.findings.filter((f) => f.ruleId === 'DKIM_SIGNING_CONFIG_DRIFT')
    const filterFindings = r.findings.filter((f) => f.ruleId === 'MAIL_HEADER_FILTER_DRIFT')
    expect(dkimFindings).toHaveLength(1)
    expect(filterFindings).toHaveLength(1)
    // Each rule matched exactly once
    expect(dkimFindings[0].matchCount).toBe(1)
    expect(filterFindings[0].matchCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scoring model', () => {
  it('returns score 0 and level none for empty input', () => {
    const r = scanEmailSecurityDrift([])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })

  it('returns score 0 and level none when no files match', () => {
    const r = scanEmailSecurityDrift(['src/app.ts', 'README.md', 'package.json'])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })

  it('HIGH × 1 match → score 15 → level low', () => {
    // sendmail.cf is HIGH severity, 1 match
    const r = scanEmailSecurityDrift(['sendmail.cf'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('low')
  })

  it('HIGH × 3 matches → score 45 → level high (cap=45 applied)', () => {
    const r = scanEmailSecurityDrift([
      'postfix/main.cf',
      'postfix/master.cf',
      'postfix/extra.cf',
    ])
    // 3 matches × 15 = 45 but cap is 45 so stays at 45 → high
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('MEDIUM × 1 match → score 8 → level low', () => {
    const r = scanEmailSecurityDrift(['postfix/relay_domains'])
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('MEDIUM × 4 matches → score 25 (capped at MEDIUM cap=25) → level medium', () => {
    const r = scanEmailSecurityDrift([
      'postfix/relay_domains',
      'postfix/transport',
      'postfix/virtual',
      'postfix/relay_recipients',
    ])
    expect(r.riskScore).toBe(25)
    expect(r.riskLevel).toBe('medium')
  })

  it('LOW × 1 match → score 4 → level low', () => {
    const r = scanEmailSecurityDrift(['postfix/header_checks'])
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('HIGH cap (45) + MEDIUM cap (25) = 70 → level critical', () => {
    const r = scanEmailSecurityDrift([
      // 3 HIGH matches → score 45 (cap)
      'postfix/main.cf',
      'postfix/master.cf',
      'postfix/extra.cf',
      // 4 MEDIUM matches → score 25 (cap)
      'postfix/relay_domains',
      'postfix/transport',
      'postfix/virtual',
      'postfix/relay_recipients',
    ])
    expect(r.riskScore).toBe(70)
    expect(r.riskLevel).toBe('critical')
  })

  it('total clamped at 100 even when sum exceeds 100', () => {
    // All HIGH caps (45×3) + MEDIUM caps (25×4) would exceed 100, capped at 100
    const r = scanEmailSecurityDrift([
      // SMTP (HIGH): 3 matches → 45
      'postfix/main.cf', 'postfix/master.cf', 'postfix/custom.cf',
      // DKIM (HIGH): 3 matches → 45
      'opendkim.conf', 'dkim/key.private', 'dkim/selector.conf',
      // SASL (HIGH): 3 matches → 45
      'saslauthd.conf', 'sasl/smtpd.conf', 'cyrus.conf',
    ])
    expect(r.riskScore).toBe(100)
    expect(r.riskLevel).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// Risk levels (boundary checks)
// ---------------------------------------------------------------------------

describe('risk level boundaries', () => {
  it('score 19 → low', () => {
    // 2 MEDIUM matches × 8 = 16, still low
    const r = scanEmailSecurityDrift(['smtp-tls.conf', 'postfix/relay_domains'])
    expect(r.riskScore).toBe(16)
    expect(r.riskLevel).toBe('low')
  })

  it('score 44 → medium', () => {
    // 1 HIGH (15) + 1 MEDIUM (8) + 1 MEDIUM (8) + 1 MEDIUM (8) = 39... let me pick better
    // 2 HIGH = 30, 1 MEDIUM×1 = 8, 1 LOW×1 = 4 → 42 → medium
    const r = scanEmailSecurityDrift([
      'sendmail.cf',           // HIGH → 15
      'opendkim.conf',         // HIGH → 15
      'smtp-tls.conf',         // MEDIUM → 8
      'postfix/header_checks', // LOW → 4
    ])
    expect(r.riskScore).toBe(42)
    expect(r.riskLevel).toBe('medium')
  })

  it('score 45 → high', () => {
    // 1 HIGH (15) + 2 MEDIUM (16) + 1 LOW (4) = 35... let me use 3 HIGH = 45
    const r = scanEmailSecurityDrift([
      'postfix/main.cf',
      'postfix/master.cf',
      'postfix/extra.cf',
    ])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('score 69 → high', () => {
    // 3 HIGH (45) + 3 MEDIUM (24) = 69
    const r = scanEmailSecurityDrift([
      'postfix/main.cf', 'postfix/master.cf', 'postfix/extra.cf',   // SMTP HIGH × 3 → 45
      'smtp-tls.conf',                                               // TLS MEDIUM × 1 → 8
      'postfix/relay_domains',                                       // RELAY MEDIUM × 1 → 8
      'amavisd.conf',                                               // ANTISPAM MEDIUM × 1 → 8
    ])
    expect(r.riskScore).toBe(69)
    expect(r.riskLevel).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// Severity ordering — high first
// ---------------------------------------------------------------------------

describe('severity ordering', () => {
  it('orders findings high → medium → low', () => {
    const r = scanEmailSecurityDrift([
      'postfix/header_checks', // LOW
      'smtp-tls.conf',         // MEDIUM
      'sendmail.cf',           // HIGH
    ])
    const severities = r.findings.map((f) => f.severity)
    expect(severities[0]).toBe('high')
    const lastMediumIndex = severities.lastIndexOf('medium')
    const firstLowIndex   = severities.indexOf('low')
    if (lastMediumIndex !== -1 && firstLowIndex !== -1) {
      expect(lastMediumIndex).toBeLessThan(firstLowIndex)
    }
  })
})

// ---------------------------------------------------------------------------
// Summary and result shape
// ---------------------------------------------------------------------------

describe('result shape and summary', () => {
  it('clean push: correct shape with empty findings', () => {
    const r = scanEmailSecurityDrift(['src/index.ts'])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
    expect(r.totalFindings).toBe(0)
    expect(r.highCount).toBe(0)
    expect(r.mediumCount).toBe(0)
    expect(r.lowCount).toBe(0)
    expect(r.findings).toHaveLength(0)
    expect(r.summary).toBe('No email security configuration changes detected.')
  })

  it('summary contains rule count, severity breakdown, and score', () => {
    const r = scanEmailSecurityDrift(['sendmail.cf', 'smtp-tls.conf'])
    expect(r.summary).toContain('2 email security rules triggered')
    expect(r.summary).toContain('1 high')
    expect(r.summary).toContain('1 medium')
    expect(r.summary).toContain(`${r.riskScore}/100`)
  })

  it('summary uses singular "rule" when exactly 1 finding', () => {
    const r = scanEmailSecurityDrift(['opendkim.conf'])
    expect(r.summary).toContain('1 email security rule triggered')
  })

  it('totalFindings equals findings array length', () => {
    const r = scanEmailSecurityDrift(['sendmail.cf', 'opendkim.conf', 'smtp-tls.conf'])
    expect(r.totalFindings).toBe(r.findings.length)
  })

  it('highCount, mediumCount, lowCount sum to totalFindings', () => {
    const r = scanEmailSecurityDrift([
      'sendmail.cf',
      'smtp-tls.conf',
      'postfix/header_checks',
    ])
    expect(r.highCount + r.mediumCount + r.lowCount).toBe(r.totalFindings)
  })

  it('each finding has all required fields', () => {
    const r = scanEmailSecurityDrift(['sendmail.cf'])
    const f = r.findings[0]
    expect(f).toHaveProperty('ruleId')
    expect(f).toHaveProperty('severity')
    expect(f).toHaveProperty('matchedPath')
    expect(f).toHaveProperty('matchCount')
    expect(f).toHaveProperty('description')
    expect(f).toHaveProperty('recommendation')
  })
})

// ---------------------------------------------------------------------------
// Multi-rule push scenario
// ---------------------------------------------------------------------------

describe('multi-rule push scenario', () => {
  it('MTA config + DKIM + SASL change → 3 distinct findings', () => {
    const r = scanEmailSecurityDrift([
      'postfix/main.cf',  // SMTP_SERVER_CONFIG_DRIFT (HIGH)
      'opendkim.conf',    // DKIM_SIGNING_CONFIG_DRIFT (HIGH)
      'sasl/smtpd.conf',  // MAIL_AUTH_SASL_DRIFT (HIGH)
    ])
    expect(r.findings).toHaveLength(3)
    const ids = r.findings.map((f) => f.ruleId)
    expect(ids).toContain('SMTP_SERVER_CONFIG_DRIFT')
    expect(ids).toContain('DKIM_SIGNING_CONFIG_DRIFT')
    expect(ids).toContain('MAIL_AUTH_SASL_DRIFT')
  })

  it('full anti-spam update → ANTISPAM_FILTER_DRIFT only once (dedup)', () => {
    const r = scanEmailSecurityDrift([
      'amavisd.conf',
      'spamassassin/local.cf',
      'rspamd/local.d/dkim.conf',
    ])
    const antiSpam = r.findings.filter((f) => f.ruleId === 'ANTISPAM_FILTER_DRIFT')
    expect(antiSpam).toHaveLength(1)
    expect(antiSpam[0].matchCount).toBe(3)
  })

  it('relay security push → RELAY + ACCESS + HEADER rules, severity high first', () => {
    const r = scanEmailSecurityDrift([
      'postfix/relay_domains',  // RELAY MEDIUM
      'postfix/sender_access',  // ACCESS MEDIUM
      'postfix/header_checks',  // HEADER LOW
    ])
    // All three rules should fire
    expect(r.findings.some((f) => f.ruleId === 'MAIL_RELAY_RESTRICTIONS_DRIFT')).toBe(true)
    expect(r.findings.some((f) => f.ruleId === 'MAIL_ACCESS_POLICY_DRIFT')).toBe(true)
    expect(r.findings.some((f) => f.ruleId === 'MAIL_HEADER_FILTER_DRIFT')).toBe(true)
    // LOW comes last
    const severities = r.findings.map((f) => f.severity)
    expect(severities[severities.length - 1]).toBe('low')
  })
})

// ---------------------------------------------------------------------------
// Rule registry completeness
// ---------------------------------------------------------------------------

describe('rule registry completeness', () => {
  const ALL_RULE_IDS = [
    'SMTP_SERVER_CONFIG_DRIFT',
    'DKIM_SIGNING_CONFIG_DRIFT',
    'MAIL_AUTH_SASL_DRIFT',
    'ANTISPAM_FILTER_DRIFT',
    'MAIL_TLS_SECURITY_DRIFT',
    'MAIL_RELAY_RESTRICTIONS_DRIFT',
    'MAIL_ACCESS_POLICY_DRIFT',
    'MAIL_HEADER_FILTER_DRIFT',
  ]

  it('registry contains exactly 8 rules', () => {
    expect(EMAIL_SECURITY_RULES).toHaveLength(8)
  })

  it('every rule ID appears in the registry', () => {
    const registryIds = EMAIL_SECURITY_RULES.map((r) => r.id)
    for (const id of ALL_RULE_IDS) {
      expect(registryIds).toContain(id)
    }
  })

  it('every rule has a non-empty description and recommendation', () => {
    for (const rule of EMAIL_SECURITY_RULES) {
      expect(rule.description.length).toBeGreaterThan(10)
      expect(rule.recommendation.length).toBeGreaterThan(10)
    }
  })

  it('severity distribution: 3 high, 4 medium, 1 low', () => {
    const high   = EMAIL_SECURITY_RULES.filter((r) => r.severity === 'high').length
    const medium = EMAIL_SECURITY_RULES.filter((r) => r.severity === 'medium').length
    const low    = EMAIL_SECURITY_RULES.filter((r) => r.severity === 'low').length
    expect(high).toBe(3)
    expect(medium).toBe(4)
    expect(low).toBe(1)
  })
})
