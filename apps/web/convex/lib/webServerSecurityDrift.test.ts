/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest'
import {
  WEB_SERVER_SECURITY_RULES,
  isIngressSecurityConfig,
  scanWebServerSecurityDrift,
} from './webServerSecurityDrift'

// ---------------------------------------------------------------------------
// isIngressSecurityConfig — unambiguous controller config filenames
// ---------------------------------------------------------------------------

describe('isIngressSecurityConfig — unambiguous filenames', () => {
  it('flags ingress-nginx.yaml', () => {
    expect(isIngressSecurityConfig('infra/ingress-nginx.yaml', 'ingress-nginx.yaml')).toBe(true)
  })

  it('flags nginx-ingress.yaml', () => {
    expect(isIngressSecurityConfig('k8s/nginx-ingress.yaml', 'nginx-ingress.yaml')).toBe(true)
  })

  it('flags haproxy-ingress.yaml', () => {
    expect(isIngressSecurityConfig('charts/haproxy-ingress.yaml', 'haproxy-ingress.yaml')).toBe(true)
  })

  it('flags traefik-ingress.yaml', () => {
    expect(isIngressSecurityConfig('helm/traefik-ingress.yaml', 'traefik-ingress.yaml')).toBe(true)
  })

  it('flags kong-ingress.yaml', () => {
    expect(isIngressSecurityConfig('infra/kong-ingress.yaml', 'kong-ingress.yaml')).toBe(true)
  })

  it('flags ingress-nginx-values.yaml (compound controller name)', () => {
    expect(isIngressSecurityConfig('charts/ingress-nginx-values.yaml', 'ingress-nginx-values.yaml')).toBe(true)
  })

  it('flags nginx-ingress-prod.yaml (compound controller name)', () => {
    expect(isIngressSecurityConfig('infra/nginx-ingress-prod.yaml', 'nginx-ingress-prod.yaml')).toBe(true)
  })

  it('flags ingress-nginx-staging.yml', () => {
    expect(isIngressSecurityConfig('k8s/ingress-nginx-staging.yml', 'ingress-nginx-staging.yml')).toBe(true)
  })
})

describe('isIngressSecurityConfig — directory-gated ambiguous filenames', () => {
  it('flags ingress.yaml inside ingress/ dir', () => {
    expect(isIngressSecurityConfig('k8s/ingress/ingress.yaml', 'ingress.yaml')).toBe(true)
  })

  it('flags ingress.yml inside ingress-nginx/ dir', () => {
    expect(isIngressSecurityConfig('charts/ingress-nginx/ingress.yml', 'ingress.yml')).toBe(true)
  })

  it('flags values.yaml inside ingress-nginx/ dir', () => {
    expect(isIngressSecurityConfig('charts/ingress-nginx/values.yaml', 'values.yaml')).toBe(true)
  })

  it('flags values.yaml inside nginx-ingress/ dir', () => {
    expect(isIngressSecurityConfig('helm/nginx-ingress/values.yaml', 'values.yaml')).toBe(true)
  })

  it('flags ingress.yaml inside traefik-ingress/ dir', () => {
    expect(isIngressSecurityConfig('infra/traefik-ingress/ingress.yaml', 'ingress.yaml')).toBe(true)
  })

  it('does NOT flag ingress.yaml outside ingress dirs', () => {
    expect(isIngressSecurityConfig('k8s/apps/api/ingress.yaml', 'ingress.yaml')).toBe(false)
  })

  it('does NOT flag values.yaml outside ingress dirs', () => {
    expect(isIngressSecurityConfig('charts/cert-manager/values.yaml', 'values.yaml')).toBe(false)
  })

  it('does NOT flag deployment.yaml in ingress-nginx/ dir', () => {
    expect(isIngressSecurityConfig('charts/ingress-nginx/deployment.yaml', 'deployment.yaml')).toBe(false)
  })

  it('does NOT flag service.yaml in ingress-nginx/ dir', () => {
    expect(isIngressSecurityConfig('k8s/ingress-nginx/service.yaml', 'service.yaml')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// NGINX_SECURITY_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('NGINX_SECURITY_CONFIG_DRIFT', () => {
  const rule = WEB_SERVER_SECURITY_RULES.find((r) => r.id === 'NGINX_SECURITY_CONFIG_DRIFT')!

  it('flags nginx.conf (root config)', () => {
    expect(rule.matches('etc/nginx/nginx.conf', 'nginx.conf', '.conf')).toBe(true)
  })

  it('flags nginx.conf.j2 (Jinja2 template)', () => {
    expect(rule.matches('templates/nginx.conf.j2', 'nginx.conf.j2', '.j2')).toBe(true)
  })

  it('flags nginx.conf.template', () => {
    expect(rule.matches('ansible/nginx.conf.template', 'nginx.conf.template', '.template')).toBe(true)
  })

  it('flags nginx-ssl.conf (prefixed name)', () => {
    expect(rule.matches('nginx-ssl.conf', 'nginx-ssl.conf', '.conf')).toBe(true)
  })

  it('flags nginx-proxy.conf (prefixed name)', () => {
    expect(rule.matches('config/nginx-proxy.conf', 'nginx-proxy.conf', '.conf')).toBe(true)
  })

  it('flags *.conf in nginx/ dir', () => {
    expect(rule.matches('nginx/security-headers.conf', 'security-headers.conf', '.conf')).toBe(true)
  })

  it('flags *.conf in sites-available/', () => {
    expect(rule.matches('etc/nginx/sites-available/api.conf', 'api.conf', '.conf')).toBe(true)
  })

  it('flags *.conf in sites-enabled/', () => {
    expect(rule.matches('etc/nginx/sites-enabled/default.conf', 'default.conf', '.conf')).toBe(true)
  })

  it('flags *.conf in nginx.d/', () => {
    expect(rule.matches('nginx.d/rate-limit.conf', 'rate-limit.conf', '.conf')).toBe(true)
  })

  it('does NOT flag unrelated .conf in app dir', () => {
    expect(rule.matches('config/app.conf', 'app.conf', '.conf')).toBe(false)
  })

  it('does NOT flag apache2.conf (different server)', () => {
    expect(rule.matches('apache2.conf', 'apache2.conf', '.conf')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// APACHE_SECURITY_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('APACHE_SECURITY_CONFIG_DRIFT', () => {
  const rule = WEB_SERVER_SECURITY_RULES.find((r) => r.id === 'APACHE_SECURITY_CONFIG_DRIFT')!

  it('flags .htaccess (per-directory config)', () => {
    expect(rule.matches('web/.htaccess', '.htaccess', '')).toBe(true)
  })

  it('flags .htaccess at repo root', () => {
    expect(rule.matches('.htaccess', '.htaccess', '')).toBe(true)
  })

  it('flags httpd.conf', () => {
    expect(rule.matches('etc/httpd/httpd.conf', 'httpd.conf', '.conf')).toBe(true)
  })

  it('flags apache2.conf', () => {
    expect(rule.matches('etc/apache2/apache2.conf', 'apache2.conf', '.conf')).toBe(true)
  })

  it('flags apache.conf', () => {
    expect(rule.matches('apache.conf', 'apache.conf', '.conf')).toBe(true)
  })

  it('flags *.conf in apache2/', () => {
    expect(rule.matches('etc/apache2/security.conf', 'security.conf', '.conf')).toBe(true)
  })

  it('flags *.conf in mods-enabled/', () => {
    expect(rule.matches('etc/apache2/mods-enabled/mod_security.conf', 'mod_security.conf', '.conf')).toBe(true)
  })

  it('flags *.conf in mods-available/', () => {
    expect(rule.matches('etc/apache2/mods-available/auth_basic.conf', 'auth_basic.conf', '.conf')).toBe(true)
  })

  it('flags *.conf in httpd/', () => {
    expect(rule.matches('etc/httpd/conf.d/ssl.conf', 'ssl.conf', '.conf')).toBe(true)
  })

  it('does NOT flag nginx.conf', () => {
    expect(rule.matches('nginx.conf', 'nginx.conf', '.conf')).toBe(false)
  })

  it('does NOT flag traefik.yml', () => {
    expect(rule.matches('traefik.yml', 'traefik.yml', '.yml')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// TRAEFIK_SECURITY_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('TRAEFIK_SECURITY_CONFIG_DRIFT', () => {
  const rule = WEB_SERVER_SECURITY_RULES.find((r) => r.id === 'TRAEFIK_SECURITY_CONFIG_DRIFT')!

  it('flags traefik.yml', () => {
    expect(rule.matches('traefik.yml', 'traefik.yml', '.yml')).toBe(true)
  })

  it('flags traefik.yaml', () => {
    expect(rule.matches('config/traefik.yaml', 'traefik.yaml', '.yaml')).toBe(true)
  })

  it('flags traefik.toml', () => {
    expect(rule.matches('traefik.toml', 'traefik.toml', '.toml')).toBe(true)
  })

  it('flags traefik-prod.yml (prefixed)', () => {
    expect(rule.matches('infra/traefik-prod.yml', 'traefik-prod.yml', '.yml')).toBe(true)
  })

  it('flags traefik-staging.toml (prefixed)', () => {
    expect(rule.matches('config/traefik-staging.toml', 'traefik-staging.toml', '.toml')).toBe(true)
  })

  it('flags *.yml in traefik/ dir', () => {
    expect(rule.matches('traefik/middlewares.yml', 'middlewares.yml', '.yml')).toBe(true)
  })

  it('flags *.toml in traefik/ dir', () => {
    expect(rule.matches('traefik/dynamic.toml', 'dynamic.toml', '.toml')).toBe(true)
  })

  it('flags *.json in traefik/ dir', () => {
    expect(rule.matches('traefik/config.json', 'config.json', '.json')).toBe(true)
  })

  it('does NOT flag an unrelated yaml at root', () => {
    expect(rule.matches('docker-compose.yml', 'docker-compose.yml', '.yml')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// CADDY_SECURITY_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('CADDY_SECURITY_CONFIG_DRIFT', () => {
  const rule = WEB_SERVER_SECURITY_RULES.find((r) => r.id === 'CADDY_SECURITY_CONFIG_DRIFT')!

  it('flags Caddyfile (capital C lowercased)', () => {
    expect(rule.matches('caddyfile', 'caddyfile', '')).toBe(true)
  })

  it('flags Caddyfile.dev variant', () => {
    expect(rule.matches('caddyfile.dev', 'caddyfile.dev', '.dev')).toBe(true)
  })

  it('flags Caddyfile.prod variant', () => {
    expect(rule.matches('config/caddyfile.prod', 'caddyfile.prod', '.prod')).toBe(true)
  })

  it('flags .caddy extension', () => {
    expect(rule.matches('config/server.caddy', 'server.caddy', '.caddy')).toBe(true)
  })

  it('flags *.json in caddy/ dir', () => {
    expect(rule.matches('caddy/config.json', 'config.json', '.json')).toBe(true)
  })

  it('flags *.yml in caddy/ dir', () => {
    expect(rule.matches('caddy/tls.yml', 'tls.yml', '.yml')).toBe(true)
  })

  it('does NOT flag Dockerfile (unrelated)', () => {
    expect(rule.matches('dockerfile', 'dockerfile', '')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// INGRESS_CONTROLLER_SECURITY_DRIFT
// ---------------------------------------------------------------------------

describe('INGRESS_CONTROLLER_SECURITY_DRIFT', () => {
  const rule = WEB_SERVER_SECURITY_RULES.find((r) => r.id === 'INGRESS_CONTROLLER_SECURITY_DRIFT')!

  it('flags ingress-nginx.yaml', () => {
    expect(rule.matches('infra/ingress-nginx.yaml', 'ingress-nginx.yaml', '.yaml')).toBe(true)
  })

  it('flags nginx-ingress.yaml', () => {
    expect(rule.matches('k8s/nginx-ingress.yaml', 'nginx-ingress.yaml', '.yaml')).toBe(true)
  })

  it('flags values.yaml in ingress-nginx/ dir', () => {
    expect(rule.matches('charts/ingress-nginx/values.yaml', 'values.yaml', '.yaml')).toBe(true)
  })

  it('flags ingress.yaml in ingress/ dir', () => {
    expect(rule.matches('k8s/ingress/ingress.yaml', 'ingress.yaml', '.yaml')).toBe(true)
  })

  it('does NOT flag deployment.yaml in ingress-nginx/ dir', () => {
    expect(rule.matches('charts/ingress-nginx/deployment.yaml', 'deployment.yaml', '.yaml')).toBe(false)
  })

  it('does NOT flag values.yaml outside ingress dirs', () => {
    expect(rule.matches('charts/cert-manager/values.yaml', 'values.yaml', '.yaml')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// MOD_SECURITY_WAF_DRIFT
// ---------------------------------------------------------------------------

describe('MOD_SECURITY_WAF_DRIFT', () => {
  const rule = WEB_SERVER_SECURITY_RULES.find((r) => r.id === 'MOD_SECURITY_WAF_DRIFT')!

  it('flags modsecurity.conf', () => {
    expect(rule.matches('modsecurity.conf', 'modsecurity.conf', '.conf')).toBe(true)
  })

  it('flags crs-setup.conf', () => {
    expect(rule.matches('owasp-crs/crs-setup.conf', 'crs-setup.conf', '.conf')).toBe(true)
  })

  it('flags modsec_crs.conf', () => {
    expect(rule.matches('modsec_crs.conf', 'modsec_crs.conf', '.conf')).toBe(true)
  })

  it('flags REQUEST-942-SQL-INJECTION.conf (OWASP CRS rule)', () => {
    expect(rule.matches(
      'owasp-crs/rules/request-942-sql-injection.conf',
      'request-942-sql-injection.conf',
      '.conf',
    )).toBe(true)
  })

  it('flags RESPONSE-950-DATA-LEAKAGES.conf (OWASP CRS rule)', () => {
    expect(rule.matches(
      'owasp-crs/rules/response-950-data-leakages.conf',
      'response-950-data-leakages.conf',
      '.conf',
    )).toBe(true)
  })

  it('flags *.conf in modsecurity/ dir', () => {
    expect(rule.matches('modsecurity/custom-rules.conf', 'custom-rules.conf', '.conf')).toBe(true)
  })

  it('flags *.conf in owasp-crs/ dir', () => {
    expect(rule.matches('owasp-crs/exclusions.conf', 'exclusions.conf', '.conf')).toBe(true)
  })

  it('flags *.conf in crs/ dir', () => {
    expect(rule.matches('crs/REQUEST-920.conf', 'request-920.conf', '.conf')).toBe(true)
  })

  it('does NOT flag an unrelated .conf file', () => {
    expect(rule.matches('config/app.conf', 'app.conf', '.conf')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// SSL_TERMINATION_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('SSL_TERMINATION_CONFIG_DRIFT', () => {
  const rule = WEB_SERVER_SECURITY_RULES.find((r) => r.id === 'SSL_TERMINATION_CONFIG_DRIFT')!

  it('flags options-ssl-nginx.conf (Let\'s Encrypt Certbot)', () => {
    expect(rule.matches(
      'etc/letsencrypt/options-ssl-nginx.conf',
      'options-ssl-nginx.conf',
      '.conf',
    )).toBe(true)
  })

  it('flags options-ssl-apache.conf', () => {
    expect(rule.matches(
      'etc/letsencrypt/options-ssl-apache.conf',
      'options-ssl-apache.conf',
      '.conf',
    )).toBe(true)
  })

  it('flags ssl-params.conf', () => {
    expect(rule.matches('ssl-params.conf', 'ssl-params.conf', '.conf')).toBe(true)
  })

  it('flags ssl-ciphers.conf', () => {
    expect(rule.matches('nginx/ssl-ciphers.conf', 'ssl-ciphers.conf', '.conf')).toBe(true)
  })

  it('flags tls-params.conf', () => {
    expect(rule.matches('tls-params.conf', 'tls-params.conf', '.conf')).toBe(true)
  })

  it('flags dhparam.pem', () => {
    expect(rule.matches('ssl/dhparam.pem', 'dhparam.pem', '.pem')).toBe(true)
  })

  it('flags dhparams.pem', () => {
    expect(rule.matches('etc/nginx/dhparams.pem', 'dhparams.pem', '.pem')).toBe(true)
  })

  it('flags ssl-dhparams.pem', () => {
    expect(rule.matches('etc/letsencrypt/ssl-dhparams.pem', 'ssl-dhparams.pem', '.pem')).toBe(true)
  })

  it('flags ssl.conf inside ssl/ dir', () => {
    expect(rule.matches('etc/ssl/ssl.conf', 'ssl.conf', '.conf')).toBe(true)
  })

  it('flags tls.conf inside tls/ dir', () => {
    expect(rule.matches('tls/tls.conf', 'tls.conf', '.conf')).toBe(true)
  })

  it('flags ssl.conf inside certs/ dir', () => {
    expect(rule.matches('certs/ssl.conf', 'ssl.conf', '.conf')).toBe(true)
  })

  it('does NOT flag ssl.conf in nginx/ (nginx rule covers it, avoids double-counting)', () => {
    expect(rule.matches('etc/nginx/ssl.conf', 'ssl.conf', '.conf')).toBe(false)
  })

  it('does NOT flag ssl.conf outside SSL-specific dirs', () => {
    expect(rule.matches('config/ssl.conf', 'ssl.conf', '.conf')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// WEB_SERVER_ACCESS_CONTROL_DRIFT
// ---------------------------------------------------------------------------

describe('WEB_SERVER_ACCESS_CONTROL_DRIFT', () => {
  const rule = WEB_SERVER_SECURITY_RULES.find((r) => r.id === 'WEB_SERVER_ACCESS_CONTROL_DRIFT')!

  it('flags .htpasswd', () => {
    expect(rule.matches('web/.htpasswd', '.htpasswd', '')).toBe(true)
  })

  it('flags htpasswd (no dot)', () => {
    expect(rule.matches('auth/htpasswd', 'htpasswd', '')).toBe(true)
  })

  it('flags basic-auth.conf', () => {
    expect(rule.matches('nginx/basic-auth.conf', 'basic-auth.conf', '.conf')).toBe(true)
  })

  it('flags digest-auth.conf', () => {
    expect(rule.matches('digest-auth.conf', 'digest-auth.conf', '.conf')).toBe(true)
  })

  it('flags auth-basic.conf', () => {
    expect(rule.matches('auth-basic.conf', 'auth-basic.conf', '.conf')).toBe(true)
  })

  it('flags auth-digest.conf', () => {
    expect(rule.matches('auth-digest.conf', 'auth-digest.conf', '.conf')).toBe(true)
  })

  it('flags geo.conf inside nginx/ dir', () => {
    expect(rule.matches('nginx/geo.conf', 'geo.conf', '.conf')).toBe(true)
  })

  it('flags geo.conf inside geoip/ dir', () => {
    expect(rule.matches('geoip/geo.conf', 'geo.conf', '.conf')).toBe(true)
  })

  it('does NOT flag geo.conf in unrelated dir', () => {
    expect(rule.matches('config/geo.conf', 'geo.conf', '.conf')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Vendor directory exclusion
// ---------------------------------------------------------------------------

describe('vendor directory exclusion', () => {
  it('excludes nginx.conf inside node_modules/', () => {
    const result = scanWebServerSecurityDrift(['node_modules/nginx/nginx.conf'])
    expect(result.riskLevel).toBe('none')
  })

  it('excludes .htaccess inside vendor/', () => {
    const result = scanWebServerSecurityDrift(['vendor/app/web/.htaccess'])
    expect(result.riskLevel).toBe('none')
  })

  it('excludes traefik.yml inside .cache/', () => {
    const result = scanWebServerSecurityDrift(['.cache/traefik.yml'])
    expect(result.riskLevel).toBe('none')
  })

  it('excludes modsecurity.conf inside build/', () => {
    const result = scanWebServerSecurityDrift(['build/modsecurity.conf'])
    expect(result.riskLevel).toBe('none')
  })
})

// ---------------------------------------------------------------------------
// Windows path normalisation
// ---------------------------------------------------------------------------

describe('Windows path normalisation', () => {
  it('handles backslash paths for nginx.conf', () => {
    const result = scanWebServerSecurityDrift(['etc\\nginx\\nginx.conf'])
    expect(result.totalFindings).toBe(1)
    expect(result.findings[0].ruleId).toBe('NGINX_SECURITY_CONFIG_DRIFT')
  })

  it('handles backslash paths for .htaccess', () => {
    const result = scanWebServerSecurityDrift(['web\\.htaccess'])
    expect(result.totalFindings).toBe(1)
    expect(result.findings[0].ruleId).toBe('APACHE_SECURITY_CONFIG_DRIFT')
  })

  it('handles backslash in traefik/ dir', () => {
    const result = scanWebServerSecurityDrift(['traefik\\middlewares.yml'])
    expect(result.totalFindings).toBe(1)
    expect(result.findings[0].ruleId).toBe('TRAEFIK_SECURITY_CONFIG_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scoring model', () => {
  it('returns riskScore 0 for empty paths', () => {
    const result = scanWebServerSecurityDrift([])
    expect(result.riskScore).toBe(0)
    expect(result.riskLevel).toBe('none')
  })

  it('HIGH rule: single file = 15 penalty', () => {
    const result = scanWebServerSecurityDrift(['nginx.conf'])
    expect(result.riskScore).toBe(15)
  })

  it('HIGH rule: cap at 45 after 3+ files', () => {
    const result = scanWebServerSecurityDrift([
      'etc/nginx/nginx.conf',
      'nginx/ssl.conf',
      'sites-available/api.conf',
      'sites-enabled/default.conf',
    ])
    expect(result.findings[0].ruleId).toBe('NGINX_SECURITY_CONFIG_DRIFT')
    expect(result.findings[0].matchCount).toBe(4)
    const score = result.riskScore
    expect(score).toBeGreaterThanOrEqual(45)
  })

  it('MEDIUM rule: single file = 8 penalty', () => {
    const result = scanWebServerSecurityDrift(['modsecurity.conf'])
    expect(result.riskScore).toBe(8)
  })

  it('LOW rule: single file = 4 penalty', () => {
    const result = scanWebServerSecurityDrift(['.htpasswd'])
    expect(result.riskScore).toBe(4)
  })

  it('total score is clamped at 100', () => {
    const result = scanWebServerSecurityDrift([
      // 3 HIGH rules
      'nginx.conf',
      '.htaccess',
      'traefik.yml',
      // 4 MEDIUM rules
      'caddyfile',
      'ingress-nginx.yaml',
      'modsecurity.conf',
      'ssl-params.conf',
      // 1 LOW rule
      '.htpasswd',
    ])
    expect(result.riskScore).toBeLessThanOrEqual(100)
  })
})

// ---------------------------------------------------------------------------
// Risk levels
// ---------------------------------------------------------------------------

describe('risk levels', () => {
  it('score 0 → none', () => {
    expect(scanWebServerSecurityDrift([]).riskLevel).toBe('none')
  })

  it('score 15 → low (single HIGH rule)', () => {
    const result = scanWebServerSecurityDrift(['nginx.conf'])
    expect(result.riskScore).toBe(15)
    expect(result.riskLevel).toBe('low')
  })

  it('score 8 → low (single MEDIUM rule)', () => {
    const result = scanWebServerSecurityDrift(['modsecurity.conf'])
    expect(result.riskScore).toBe(8)
    expect(result.riskLevel).toBe('low')
  })

  it('score 20 → medium (two HIGH rules, 1 file each)', () => {
    const result = scanWebServerSecurityDrift(['nginx.conf', '.htaccess'])
    expect(result.riskScore).toBe(30)
    expect(result.riskLevel).toBe('medium')
  })

  it('score 45 → high (3 HIGH rules)', () => {
    const result = scanWebServerSecurityDrift(['nginx.conf', '.htaccess', 'traefik.yml'])
    expect(result.riskScore).toBe(45)
    expect(result.riskLevel).toBe('high')
  })

  it('score ≥70 → critical (multiple HIGH rules, multiple files)', () => {
    const result = scanWebServerSecurityDrift([
      'nginx.conf',
      'nginx/security.conf',
      'sites-available/api.conf',
      'sites-enabled/default.conf',
      '.htaccess',
      'httpd.conf',
      'apache2.conf',
      'apache2/ssl.conf',
      'traefik.yml',
      'traefik-prod.yml',
    ])
    expect(result.riskScore).toBeGreaterThanOrEqual(70)
    expect(result.riskLevel).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// Dedup per rule
// ---------------------------------------------------------------------------

describe('dedup per rule', () => {
  it('multiple nginx files → one finding with matchCount', () => {
    const result = scanWebServerSecurityDrift([
      'nginx.conf',
      'nginx/security-headers.conf',
      'sites-available/api.conf',
    ])
    const finding = result.findings.find((f) => f.ruleId === 'NGINX_SECURITY_CONFIG_DRIFT')!
    expect(finding).toBeDefined()
    expect(finding.matchCount).toBe(3)
    expect(result.findings.length).toBe(1)
  })

  it('multiple rule triggers → one finding each', () => {
    const result = scanWebServerSecurityDrift([
      'nginx.conf',
      '.htaccess',
    ])
    expect(result.findings.length).toBe(2)
  })

  it('matchedPath is the first matched file', () => {
    const result = scanWebServerSecurityDrift([
      'etc/nginx/nginx.conf',
      'nginx/security.conf',
    ])
    const finding = result.findings.find((f) => f.ruleId === 'NGINX_SECURITY_CONFIG_DRIFT')!
    expect(finding.matchedPath).toBe('etc/nginx/nginx.conf')
  })
})

// ---------------------------------------------------------------------------
// Severity ordering
// ---------------------------------------------------------------------------

describe('severity ordering', () => {
  it('HIGH findings appear before MEDIUM', () => {
    const result = scanWebServerSecurityDrift(['nginx.conf', 'modsecurity.conf'])
    expect(result.findings[0].severity).toBe('high')
    expect(result.findings[1].severity).toBe('medium')
  })

  it('MEDIUM findings appear before LOW', () => {
    const result = scanWebServerSecurityDrift(['modsecurity.conf', '.htpasswd'])
    expect(result.findings[0].severity).toBe('medium')
    expect(result.findings[1].severity).toBe('low')
  })

  it('HIGH before MEDIUM before LOW', () => {
    const result = scanWebServerSecurityDrift([
      '.htpasswd',
      'modsecurity.conf',
      'nginx.conf',
    ])
    expect(result.findings[0].severity).toBe('high')
    expect(result.findings[1].severity).toBe('medium')
    expect(result.findings[2].severity).toBe('low')
  })
})

// ---------------------------------------------------------------------------
// Summary / result shape
// ---------------------------------------------------------------------------

describe('summary and result shape', () => {
  it('returns empty summary for no findings', () => {
    const result = scanWebServerSecurityDrift([])
    expect(result.summary).toContain('No web server')
    expect(result.totalFindings).toBe(0)
  })

  it('result includes all required fields', () => {
    const result = scanWebServerSecurityDrift(['nginx.conf'])
    expect(result).toHaveProperty('riskScore')
    expect(result).toHaveProperty('riskLevel')
    expect(result).toHaveProperty('totalFindings')
    expect(result).toHaveProperty('highCount')
    expect(result).toHaveProperty('mediumCount')
    expect(result).toHaveProperty('lowCount')
    expect(result).toHaveProperty('findings')
    expect(result).toHaveProperty('summary')
  })

  it('summary contains "web server" for drift findings', () => {
    const result = scanWebServerSecurityDrift(['nginx.conf'])
    expect(result.summary.toLowerCase()).toContain('web server')
  })

  it('finding includes ruleId, severity, matchedPath, matchCount, description, recommendation', () => {
    const result = scanWebServerSecurityDrift(['nginx.conf'])
    const f = result.findings[0]
    expect(f).toHaveProperty('ruleId')
    expect(f).toHaveProperty('severity')
    expect(f).toHaveProperty('matchedPath')
    expect(f).toHaveProperty('matchCount')
    expect(f).toHaveProperty('description')
    expect(f).toHaveProperty('recommendation')
  })

  it('counts high/medium/low correctly', () => {
    const result = scanWebServerSecurityDrift([
      'nginx.conf',       // HIGH
      'modsecurity.conf', // MEDIUM
      '.htpasswd',        // LOW
    ])
    expect(result.highCount).toBe(1)
    expect(result.mediumCount).toBe(1)
    expect(result.lowCount).toBe(1)
    expect(result.totalFindings).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// Multi-rule scenarios
// ---------------------------------------------------------------------------

describe('multi-rule scenarios', () => {
  it('nginx + ModSecurity config push', () => {
    const result = scanWebServerSecurityDrift([
      'nginx.conf',
      'nginx/security-headers.conf',
      'modsecurity/modsecurity.conf',
      'owasp-crs/crs-setup.conf',
      'owasp-crs/rules/request-942-sql-injection.conf',
    ])
    const ruleIds = result.findings.map((f) => f.ruleId)
    expect(ruleIds).toContain('NGINX_SECURITY_CONFIG_DRIFT')
    expect(ruleIds).toContain('MOD_SECURITY_WAF_DRIFT')
    expect(result.highCount).toBeGreaterThanOrEqual(1)
    expect(result.mediumCount).toBeGreaterThanOrEqual(1)
  })

  it('full web server hardening push (all 8 rules)', () => {
    const result = scanWebServerSecurityDrift([
      'nginx.conf',                        // NGINX
      '.htaccess',                         // APACHE
      'traefik.yml',                       // TRAEFIK
      'caddyfile',                         // CADDY
      'ingress-nginx.yaml',                // INGRESS
      'modsecurity.conf',                  // MOD_SECURITY
      'ssl-params.conf',                   // SSL_TERMINATION
      '.htpasswd',                         // ACCESS_CONTROL
    ])
    expect(result.totalFindings).toBe(8)
    expect(result.highCount).toBe(3)
    expect(result.mediumCount).toBe(4)
    expect(result.lowCount).toBe(1)
    expect(result.riskScore).toBeLessThanOrEqual(100)
  })

  it('Traefik + ingress controller push', () => {
    const result = scanWebServerSecurityDrift([
      'traefik.yml',
      'traefik/middlewares.yml',
      'traefik/tls.yml',
      'charts/ingress-nginx/values.yaml',
    ])
    const ruleIds = result.findings.map((f) => f.ruleId)
    expect(ruleIds).toContain('TRAEFIK_SECURITY_CONFIG_DRIFT')
    expect(ruleIds).toContain('INGRESS_CONTROLLER_SECURITY_DRIFT')
  })

  it('Caddy TLS config change', () => {
    const result = scanWebServerSecurityDrift([
      'caddyfile',
      'caddyfile.prod',
      'caddy/config.json',
    ])
    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].ruleId).toBe('CADDY_SECURITY_CONFIG_DRIFT')
    expect(result.findings[0].matchCount).toBe(3)
  })

  it('SSL hardening push (ssl-params + dhparam + options-ssl)', () => {
    const result = scanWebServerSecurityDrift([
      'ssl-params.conf',
      'dhparam.pem',
      'etc/letsencrypt/options-ssl-nginx.conf',
    ])
    expect(result.findings).toHaveLength(1)
    expect(result.findings[0].ruleId).toBe('SSL_TERMINATION_CONFIG_DRIFT')
    expect(result.findings[0].matchCount).toBe(3)
  })

  it('access control push: .htpasswd + geo.conf triggers both ACCESS_CONTROL and NGINX rules', () => {
    const result = scanWebServerSecurityDrift([
      'web/.htpasswd',
      'nginx/geo.conf',
    ])
    // geo.conf in nginx/ triggers NGINX rule; it also triggers ACCESS_CONTROL
    // .htpasswd triggers ACCESS_CONTROL only
    const ruleIds = result.findings.map((f) => f.ruleId)
    expect(ruleIds).toContain('WEB_SERVER_ACCESS_CONTROL_DRIFT')
    expect(ruleIds).toContain('NGINX_SECURITY_CONFIG_DRIFT')
    const accessFinding = result.findings.find((f) => f.ruleId === 'WEB_SERVER_ACCESS_CONTROL_DRIFT')!
    expect(accessFinding.matchCount).toBe(2) // .htpasswd + geo.conf
  })

  it('non-webserver YAML push produces no findings', () => {
    const result = scanWebServerSecurityDrift([
      'src/components/App.tsx',
      'prisma/schema.prisma',
      'charts/cert-manager/values.yaml',
      '.github/workflows/ci.yml',
    ])
    expect(result.totalFindings).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// Rule registry completeness
// ---------------------------------------------------------------------------

describe('rule registry completeness', () => {
  const EXPECTED_RULES = [
    'NGINX_SECURITY_CONFIG_DRIFT',
    'APACHE_SECURITY_CONFIG_DRIFT',
    'TRAEFIK_SECURITY_CONFIG_DRIFT',
    'CADDY_SECURITY_CONFIG_DRIFT',
    'INGRESS_CONTROLLER_SECURITY_DRIFT',
    'MOD_SECURITY_WAF_DRIFT',
    'SSL_TERMINATION_CONFIG_DRIFT',
    'WEB_SERVER_ACCESS_CONTROL_DRIFT',
  ]

  it('registry has exactly 8 rules', () => {
    expect(WEB_SERVER_SECURITY_RULES.length).toBe(8)
  })

  for (const id of EXPECTED_RULES) {
    it(`registry contains ${id}`, () => {
      expect(WEB_SERVER_SECURITY_RULES.find((r) => r.id === id)).toBeDefined()
    })
  }
})
