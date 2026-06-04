// WS-75 — Web Server & Reverse Proxy Security Configuration Drift Detector:
// pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to web server and reverse proxy security configuration files. This scanner
// focuses on the *edge ingress layer* — configurations that control how HTTP/S
// traffic enters the infrastructure: TLS cipher suites, security header
// injection, reverse-proxy routing, rate limiting, authentication middleware,
// WAF rules, and access control.
//
// DISTINCT from:
//   WS-60  securityConfigDrift       — application-level TLS/CORS/JWT/session
//                                      configs inside backend service code
//   WS-63  kubernetesRbacDrift       — Kubernetes RBAC, NetworkPolicy, and
//                                      PodSecurity; WS-75 covers ingress
//                                      controller security configs
//   WS-68  networkFirewallDrift      — OS-level firewall (iptables, nftables,
//                                      UFW) and HAProxy stream-level configs
//   WS-72  serviceMeshSecurityDrift  — Istio/Envoy east-west service mesh;
//                                      WS-75 covers the north-south HTTP edge
//
// Covered rule groups (8 rules):
//
//   NGINX_SECURITY_CONFIG_DRIFT        — nginx.conf and virtual-host configs
//   APACHE_SECURITY_CONFIG_DRIFT       — .htaccess, httpd.conf, Apache modules
//   TRAEFIK_SECURITY_CONFIG_DRIFT      — traefik.yml/yaml/toml static configs
//   CADDY_SECURITY_CONFIG_DRIFT        — Caddyfile and Caddy JSON API configs
//   INGRESS_CONTROLLER_SECURITY_DRIFT  — K8s ingress controller configs (user)
//   MOD_SECURITY_WAF_DRIFT             — ModSecurity / OWASP CRS WAF rules
//   SSL_TERMINATION_CONFIG_DRIFT       — cipher suites and TLS termination params
//   WEB_SERVER_ACCESS_CONTROL_DRIFT    — .htpasswd, geo IP allow/deny configs
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Vendor directory exclusion applied to all paths.
//   • Same penalty/cap scoring model as WS-60–74 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (matchedPath + matchCount).
//   • .htaccess is globally unambiguous — Apache per-directory config only.
//   • traefik.yml/yaml/toml are globally unambiguous filenames.
//   • Caddyfile (all variants) is globally unambiguous.
//   • isIngressSecurityConfig is the user contribution — see JSDoc below.
//
// Exports:
//   isIngressSecurityConfig    — user contribution point (see JSDoc below)
//   WEB_SERVER_SECURITY_RULES  — readonly rule registry
//   scanWebServerSecurityDrift — main scanner, returns WebServerSecurityDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type WebServerSecurityRuleId =
  | 'NGINX_SECURITY_CONFIG_DRIFT'
  | 'APACHE_SECURITY_CONFIG_DRIFT'
  | 'TRAEFIK_SECURITY_CONFIG_DRIFT'
  | 'CADDY_SECURITY_CONFIG_DRIFT'
  | 'INGRESS_CONTROLLER_SECURITY_DRIFT'
  | 'MOD_SECURITY_WAF_DRIFT'
  | 'SSL_TERMINATION_CONFIG_DRIFT'
  | 'WEB_SERVER_ACCESS_CONTROL_DRIFT'

export type WebServerSecuritySeverity = 'high' | 'medium' | 'low'
export type WebServerSecurityRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type WebServerSecurityDriftFinding = {
  ruleId: WebServerSecurityRuleId
  severity: WebServerSecuritySeverity
  matchedPath: string
  matchCount: number
  description: string
  recommendation: string
}

export type WebServerSecurityDriftResult = {
  riskScore: number
  riskLevel: WebServerSecurityRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: WebServerSecurityDriftFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VENDOR_DIRS = [
  'node_modules/', '.git/', 'dist/', 'build/', '.next/', '.nuxt/',
  'vendor/', 'bower_components/', 'coverage/', '__pycache__/',
  '.terraform/', 'cdk.out/', '.cdk/', '.gradle/', '.m2/',
  'target/', 'out/', '.idea/', '.vscode/', '.cache/',
]

const HIGH_PENALTY_PER = 15
const HIGH_PENALTY_CAP = 45
const MED_PENALTY_PER  = 8
const MED_PENALTY_CAP  = 25
const LOW_PENALTY_PER  = 4
const LOW_PENALTY_CAP  = 15

// Nginx-specific virtual-host and config include directories.
const NGINX_DIRS = ['nginx/', 'nginx.d/', 'sites-available/', 'sites-enabled/']

// Apache-specific directories including module enable/disable dirs.
const APACHE_DIRS = ['apache2/', 'apache/', 'httpd/', 'mods-enabled/', 'mods-available/']

// ModSecurity / OWASP CRS rule directories.
const MOD_SEC_DIRS = ['modsecurity/', 'modsec/', 'owasp-crs/', 'crs/']

// ---------------------------------------------------------------------------
// Detection helpers — NGINX_SECURITY_CONFIG_DRIFT
// ---------------------------------------------------------------------------

function isNginxSecurityConfig(pathLower: string, base: string): boolean {
  // nginx.conf — the root nginx configuration file. Controls worker processes,
  // SSL protocols, cipher suites, HSTS headers, proxy settings, and rate
  // limiting. Globally unambiguous.
  if (base === 'nginx.conf') return true

  // Jinja2 / template variants deployed via Ansible or similar tooling.
  if (base === 'nginx.conf.j2' || base === 'nginx.conf.template') return true

  // nginx-*.conf — env-specific virtualhost overrides (nginx-ssl.conf,
  // nginx-proxy.conf, nginx-hardened.conf, etc.).
  if (base.startsWith('nginx-') && base.endsWith('.conf')) return true

  // .conf files inside nginx-specific directories including Debian-style
  // sites-available / sites-enabled virtualhost directories.
  if (base.endsWith('.conf') || base.endsWith('.conf.j2') || base.endsWith('.conf.template')) {
    for (const dir of NGINX_DIRS) {
      if (pathLower.includes(dir)) return true
    }
  }

  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — APACHE_SECURITY_CONFIG_DRIFT
// ---------------------------------------------------------------------------

function isApacheSecurityConfig(pathLower: string, base: string): boolean {
  // .htaccess — Apache per-directory config file. Can override
  // authentication, access control, URL rewriting, and MIME types.
  // Globally unambiguous — no other web server uses this filename.
  if (base === '.htaccess') return true

  // Core Apache server configuration files.
  if (base === 'httpd.conf' || base === 'apache2.conf' || base === 'apache.conf') return true

  // .conf files inside Apache-specific directories. mods-enabled / mods-available
  // hold module activation symlinks (mod_security, mod_auth_basic, mod_ssl).
  if (base.endsWith('.conf')) {
    for (const dir of APACHE_DIRS) {
      if (pathLower.includes(dir)) return true
    }
  }

  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — TRAEFIK_SECURITY_CONFIG_DRIFT
// ---------------------------------------------------------------------------

const TRAEFIK_UNGATED = new Set(['traefik.yml', 'traefik.yaml', 'traefik.toml'])

function isTraefikSecurityConfig(pathLower: string, base: string): boolean {
  // traefik.yml/yaml/toml — Traefik static configuration. Controls TLS
  // options, certificate resolvers (Let's Encrypt), middleware definitions,
  // entry point security, and the Traefik API/dashboard exposure.
  // These filenames are globally unambiguous.
  if (TRAEFIK_UNGATED.has(base)) return true

  // traefik-*.yml/yaml/toml — environment-specific or override configs.
  if (
    base.startsWith('traefik-') &&
    (base.endsWith('.yml') || base.endsWith('.yaml') || base.endsWith('.toml'))
  ) return true

  // Any YAML/TOML/JSON inside a traefik/ directory (dynamic config files,
  // middleware definitions, TLS cert store configs).
  if (pathLower.includes('traefik/')) {
    if (base.endsWith('.yml') || base.endsWith('.yaml') || base.endsWith('.toml') || base.endsWith('.json')) {
      return true
    }
  }

  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — CADDY_SECURITY_CONFIG_DRIFT
// ---------------------------------------------------------------------------

function isCaddySecurityConfig(pathLower: string, base: string): boolean {
  // Caddyfile — Caddy's primary configuration format. Controls automatic TLS
  // (ACME), reverse proxy security, security headers, and access policies.
  // Globally unambiguous — Caddy is the only server using this filename.
  if (base === 'caddyfile') return true

  // Caddyfile.* — environment-specific variants (Caddyfile.dev, Caddyfile.prod,
  // Caddyfile.staging).
  if (base.startsWith('caddyfile.')) return true

  // .caddy extension — less common but used in some Caddy v2 deployments.
  if (base.endsWith('.caddy')) return true

  // JSON/YAML inside a caddy/ directory — Caddy's JSON API config format.
  if (
    pathLower.includes('caddy/') &&
    (base.endsWith('.json') || base.endsWith('.yml') || base.endsWith('.yaml'))
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// INGRESS_CONTROLLER_SECURITY_DRIFT — user contribution point
// ---------------------------------------------------------------------------

/**
 * isIngressSecurityConfig — determines whether a changed file is a Kubernetes
 * ingress controller security configuration rather than a generic manifest.
 *
 * Context: K8s ingress-related files span several categories:
 *   (a) Ingress controller deployment configs — ConfigMap patches, Helm values,
 *       or raw YAML manifests that configure the ingress controller itself
 *       (ingress-nginx, Traefik, HAProxy, Kong). These control TLS termination,
 *       SSL ciphers, security header injection, rate limiting, WAF integration,
 *       and authentication middleware. High security value.
 *
 *   (b) Application Ingress objects — Kubernetes Ingress resources that define
 *       per-service routes and may carry security annotations such as:
 *       nginx.ingress.kubernetes.io/ssl-redirect: "true"
 *       nginx.ingress.kubernetes.io/auth-url: ...
 *       nginx.ingress.kubernetes.io/whitelist-source-range: ...
 *       Changes here affect how TLS and auth are enforced for specific services.
 *
 *   (c) Generic Kubernetes manifests — Deployment, Service, or ConfigMap files
 *       that happen to live in an ingress-related directory but don't configure
 *       ingress security directly (e.g., the ingress controller's own RBAC).
 *
 *   (d) Helm values files — values.yaml inside an ingress-nginx/ Helm chart
 *       directory controls TLS options, SSL protocols, and controller-wide
 *       security settings. High security value but `values.yaml` is a generic
 *       filename shared across all Helm charts.
 *
 * Design trade-offs:
 *   • Filename-only (precise, low recall): flag `ingress-nginx.yaml`,
 *     `nginx-ingress.yaml`, `haproxy-ingress.yaml` ungated. Catches
 *     explicitly-named controller configs but misses `ingress.yaml` and
 *     Helm values files that configure controller security.
 *
 *   • Directory-only (broad recall, noisier): flag any YAML/JSON in
 *     `ingress/`, `ingress-nginx/`, `nginx-ingress/`, `traefik-ingress/`.
 *     Catches Helm values and per-app ingress objects but also flags
 *     non-security Deployment and ServiceAccount manifests.
 *
 *   • Hybrid (recommended): unambiguous controller config names ungated;
 *     `ingress.yaml` and `values.yaml` gated on ingress-specific dirs.
 *     Optionally: Helm-prefixed names like `ingress-nginx-values.yaml`.
 *
 * Implement to return true for files that directly configure ingress
 * controller security: TLS passthrough, SSL redirect, authentication
 * middleware, rate limiting, or controller-wide security settings.
 * Return false for generic Kubernetes RBAC or Service manifests.
 */
export function isIngressSecurityConfig(pathLower: string, base: string): boolean {
  // Unambiguous ingress controller config filenames — no directory gate needed.
  if (
    base === 'ingress-nginx.yaml' ||
    base === 'nginx-ingress.yaml' ||
    base === 'haproxy-ingress.yaml' ||
    base === 'traefik-ingress.yaml' ||
    base === 'kong-ingress.yaml'
  ) return true

  // The controller may use compound names with environment suffixes.
  if (
    (base.startsWith('ingress-nginx-') || base.startsWith('nginx-ingress-')) &&
    (base.endsWith('.yaml') || base.endsWith('.yml'))
  ) return true

  // ingress.yaml / values.yaml gated on ingress-controller-specific dirs.
  const INGRESS_DIRS = [
    'ingress/', 'ingress-nginx/', 'nginx-ingress/',
    'traefik-ingress/', 'haproxy-ingress/', 'kong-ingress/',
  ]
  if (
    (base === 'ingress.yaml' || base === 'ingress.yml' || base === 'values.yaml') &&
    INGRESS_DIRS.some((d) => pathLower.includes(d))
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — MOD_SECURITY_WAF_DRIFT
// ---------------------------------------------------------------------------

function isModSecurityWafConfig(pathLower: string, base: string): boolean {
  // modsecurity.conf — the primary ModSecurity engine configuration. Controls
  // SecRuleEngine mode (Detection/Prevention/Off) and default action.
  if (base === 'modsecurity.conf') return true

  // crs-setup.conf — OWASP Core Rule Set setup file. Configures anomaly scoring
  // thresholds and paranoia level. Ungated — globally unambiguous.
  if (base === 'crs-setup.conf' || base === 'modsec_crs.conf') return true

  // OWASP CRS numbered rule files: REQUEST-xxx-*.conf / RESPONSE-xxx-*.conf.
  // These are the pattern-match WAF rules — disabling or relaxing them widens
  // the attack surface.
  if (
    (base.startsWith('request-') || base.startsWith('response-')) &&
    base.endsWith('.conf')
  ) return true

  // .conf files inside ModSecurity / OWASP CRS directories.
  if (base.endsWith('.conf')) {
    for (const dir of MOD_SEC_DIRS) {
      if (pathLower.includes(dir)) return true
    }
  }

  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — SSL_TERMINATION_CONFIG_DRIFT
// ---------------------------------------------------------------------------

function isSslTerminationConfig(pathLower: string, base: string): boolean {
  // Let's Encrypt Certbot-generated SSL parameter includes — globally unambiguous.
  if (base === 'options-ssl-nginx.conf' || base === 'options-ssl-apache.conf') return true

  // Explicit TLS cipher suite and parameter files.
  if (base === 'ssl-params.conf' || base === 'ssl-ciphers.conf' || base === 'tls-params.conf') return true

  // Diffie-Hellman parameters file — affects forward secrecy strength.
  if (base === 'dhparam.pem' || base === 'dhparams.pem' || base === 'ssl-dhparams.pem') return true

  // ssl.conf / tls.conf gated on dedicated SSL/TLS directories. Webserver
  // directories (nginx/, apache/, httpd/) are intentionally excluded because
  // those files are already caught by their respective NGINX/APACHE rules —
  // and catching them twice would misrepresent the finding count.
  const SSL_DIRS = ['ssl/', 'tls/', 'certs/']
  if (base === 'ssl.conf' || base === 'tls.conf') {
    for (const dir of SSL_DIRS) {
      if (pathLower.includes(dir)) return true
    }
  }

  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — WEB_SERVER_ACCESS_CONTROL_DRIFT
// ---------------------------------------------------------------------------

function isWebServerAccessControl(pathLower: string, base: string): boolean {
  // .htpasswd — Apache HTTP Basic Authentication password file. Stores
  // bcrypt/MD5/SHA1 hashed credentials for protected directories or locations.
  // Globally unambiguous — only Apache uses this filename convention.
  if (base === '.htpasswd') return true

  // htpasswd — same file without leading dot (some tooling omits the dot).
  if (base === 'htpasswd') return true

  // Explicit auth configuration files — unambiguous enough to flag ungated.
  if (
    base === 'basic-auth.conf' ||
    base === 'digest-auth.conf' ||
    base === 'auth-basic.conf' ||
    base === 'auth-digest.conf'
  ) return true

  // geo.conf — nginx geo module: maps client IP ranges to variables used for
  // allow/deny decisions. Gated on nginx or geoip dirs to avoid collisions.
  if (base === 'geo.conf' && (pathLower.includes('nginx/') || pathLower.includes('geoip/'))) {
    return true
  }

  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

type WebServerSecurityRule = {
  id: WebServerSecurityRuleId
  severity: WebServerSecuritySeverity
  description: string
  recommendation: string
  matches: (pathLower: string, base: string, ext: string) => boolean
}

export const WEB_SERVER_SECURITY_RULES: readonly WebServerSecurityRule[] = [
  {
    id: 'NGINX_SECURITY_CONFIG_DRIFT',
    severity: 'high',
    description: 'nginx web server or reverse proxy configuration files were modified — nginx.conf, virtualhost files in sites-available/sites-enabled, or files inside nginx/ or nginx.d/ directories. The nginx configuration controls TLS protocol versions (ssl_protocols), cipher suite selection (ssl_ciphers), HSTS header injection (add_header Strict-Transport-Security), HTTP security headers (X-Frame-Options, X-Content-Type-Options, Content-Security-Policy), proxy pass headers, rate limiting zones (limit_req_zone), and access restrictions. Misconfiguration can disable TLS 1.2+, weaken cipher suites to include vulnerable ones (RC4, DES, EXPORT ciphers), remove security headers, or expose upstream backend addresses.',
    recommendation: 'Verify that ssl_protocols does not include SSLv3, TLSv1, or TLSv1.1. Confirm that ssl_ciphers follows current best practice (ECDHE-RSA-AES256-GCM-SHA384 or similar) and excludes weak ciphers. Check that all security headers (HSTS, X-Frame-Options, X-Content-Type-Options, CSP) are still present in virtualhost blocks. Ensure that proxy_hide_header and proxy_pass_header directives do not leak server version or internal routing information. Review any new location blocks for unintended open access.',
    matches: (p, b) => isNginxSecurityConfig(p, b),
  },
  {
    id: 'APACHE_SECURITY_CONFIG_DRIFT',
    severity: 'high',
    description: 'Apache HTTP Server configuration files were modified — .htaccess per-directory config, httpd.conf/apache2.conf, or module configuration files in mods-enabled/mods-available or apache2/apache/httpd directories. .htaccess changes can override authentication requirements, enable directory listing (Options Indexes), add unsafe MIME type associations, override SSL settings via mod_ssl, or enable dangerous options like FollowSymLinks without SymLinksIfOwnerMatch. httpd.conf changes can weaken server-wide TLS configuration, expose the server version string, or disable mod_security WAF integration.',
    recommendation: 'Review .htaccess changes for removal of AuthType/AuthName/Require directives that protect restricted paths, addition of Options Indexes that enables directory listing, and Header or mod_headers changes that remove security headers. For httpd.conf/apache2.conf, verify that SSLProtocol does not include deprecated versions, that ServerTokens is set to Prod or Minimal, and that ServerSignature is Off. Confirm that mods-enabled changes do not disable mod_security, mod_auth_digest, or mod_ssl without a compensating control.',
    matches: (p, b) => isApacheSecurityConfig(p, b),
  },
  {
    id: 'TRAEFIK_SECURITY_CONFIG_DRIFT',
    severity: 'high',
    description: 'Traefik reverse proxy static configuration files were modified — traefik.yml, traefik.yaml, or traefik.toml, environment-specific overrides (traefik-*.yml/toml), or files inside a traefik/ directory. Traefik static config controls TLS options (minimum version, cipher suites), certificate resolvers (ACME/Let\'s Encrypt), entry point security (redirect HTTP→HTTPS, mTLS), the Traefik API/dashboard exposure (api.insecure: true is a critical misconfiguration), and the redirect scheme. Dynamic config files in traefik/ directories define middleware (auth, rate limiting, IP allowlists) that may be applied globally.',
    recommendation: 'Verify that api.insecure is not set to true, which exposes the Traefik management API on port 8080 without authentication. Confirm that tls.options does not downgrade minVersion below TLS 1.2. Check that entryPoints.web (HTTP) redirects to entryPoints.websecure (HTTPS) and has not been changed to serve plaintext traffic. Review any middleware changes for removal of BasicAuth, DigestAuth, or IPAllowList middleware that previously protected services. Confirm ACME certificate resolver configuration still targets the production ACME endpoint.',
    matches: (p, b) => isTraefikSecurityConfig(p, b),
  },
  {
    id: 'CADDY_SECURITY_CONFIG_DRIFT',
    severity: 'medium',
    description: 'Caddy web server configuration files were modified — Caddyfile or environment-specific variants (Caddyfile.dev, Caddyfile.prod), files with the .caddy extension, or Caddy JSON API configuration files inside a caddy/ directory. Caddy provides automatic TLS via ACME by default, but Caddyfile changes can disable automatic HTTPS (http:// instead of https://), override TLS minimum version or cipher suites, remove security header directives (header blocks), change reverse proxy upstream targets, or modify request/response transformation rules that strip or inject security-sensitive headers.',
    recommendation: 'Confirm that Caddyfile site addresses still use the HTTPS scheme or bare domain (which enables automatic TLS). Verify that tls directives do not specify a minimum protocol older than tls1.2 or cipher suites that include known-weak options. Check header blocks to ensure security headers (Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options) are still present. Review reverse_proxy directive changes to confirm upstream addresses have not changed to plaintext HTTP endpoints for services that should use TLS internally.',
    matches: (p, b) => isCaddySecurityConfig(p, b),
  },
  {
    id: 'INGRESS_CONTROLLER_SECURITY_DRIFT',
    severity: 'medium',
    description: 'Kubernetes ingress controller security configuration files were modified — ingress-nginx or nginx-ingress controller deployment YAML, Helm values files in ingress controller directories, or Kubernetes Ingress resources that define security annotations. Ingress controller configs set cluster-wide TLS defaults, minimum SSL protocols, HSTS policy, and per-service security annotations including ssl-redirect, auth-url (OAuth2 authentication), whitelist-source-range (IP allowlisting), rate limiting, and WAF plugin integration. Changes to Helm values (values.yaml) in ingress-nginx/ directories control controller-wide TLS cipher suites and SSL protocols applied to every ingress in the cluster.',
    recommendation: 'Review nginx.ingress.kubernetes.io/ssl-redirect annotations to ensure HTTPS redirect has not been disabled for services that require TLS. Verify that ssl-protocols in controller ConfigMap or Helm values does not include TLSv1 or TLSv1.1. Check that auth-url/auth-signin annotations have not been removed from ingresses protecting authenticated resources. Confirm that whitelist-source-range changes appropriately restrict access and do not open previously restricted endpoints to 0.0.0.0/0. Review global ConfigMap changes for cipher-suite or HSTS max-age relaxation.',
    matches: (p, b) => isIngressSecurityConfig(p, b),
  },
  {
    id: 'MOD_SECURITY_WAF_DRIFT',
    severity: 'medium',
    description: 'ModSecurity WAF engine or OWASP Core Rule Set (CRS) configuration files were modified — modsecurity.conf (engine settings), crs-setup.conf (CRS paranoia level and anomaly scoring thresholds), OWASP CRS numbered rule files (REQUEST-xxx-*.conf, RESPONSE-xxx-*.conf), or files inside modsecurity/ or owasp-crs/ directories. Changes to modsecurity.conf can switch SecRuleEngine from On (enforcement) to DetectionOnly or Off, completely disabling WAF protection. CRS rule file changes may add exclusions that disable SQL injection, XSS, command injection, or local/remote file inclusion protections for specific paths or parameters.',
    recommendation: 'Verify that modsecurity.conf still sets SecRuleEngine On (or at minimum DetectionOnly) and has not been switched to Off. Confirm that the anomaly scoring thresholds in crs-setup.conf have not been raised to values that effectively disable blocking (e.g., inbound_anomaly_score_threshold raised from 5 to 9999). Review SecRuleRemoveById, SecRuleRemoveByTag, and ctl:ruleRemoveById directives in rule files for removals of SQLI (942xxx), XSS (941xxx), or RCE (932xxx/930xxx) rule groups. Confirm that SecRequestBodyLimit has not been raised excessively, which can facilitate large-body DoS.',
    matches: (p, b) => isModSecurityWafConfig(p, b),
  },
  {
    id: 'SSL_TERMINATION_CONFIG_DRIFT',
    severity: 'medium',
    description: 'SSL/TLS termination parameter configuration files were modified — explicit cipher suite files (ssl-params.conf, ssl-ciphers.conf, tls-params.conf), ACME/Let\'s Encrypt Certbot-generated SSL options files (options-ssl-nginx.conf, options-ssl-apache.conf), Diffie-Hellman parameter files (dhparam.pem), or ssl.conf/tls.conf files in webserver or TLS-specific directories. These files centralize cipher suite selection, TLS minimum version enforcement, and DH group strength across all virtual hosts that include them. A change to a shared ssl-params.conf can simultaneously weaken TLS for every site served by the web server.',
    recommendation: 'Verify that ssl-params.conf or tls-params.conf still specifies a minimum TLS version of TLSv1.2 or higher and excludes NULL, RC4, DES, 3DES, EXPORT, and MD5-signed cipher suites. If dhparam.pem was replaced, confirm the new DH group is at least 2048 bits and was generated from a trusted source — changes to DH parameters can indicate supply chain compromise if the file was replaced with a weak or backdoored group. Confirm that options-ssl-nginx.conf changes do not relax Certbot-enforced settings below the ACME/Let\'s Encrypt security baseline.',
    matches: (p, b) => isSslTerminationConfig(p, b),
  },
  {
    id: 'WEB_SERVER_ACCESS_CONTROL_DRIFT',
    severity: 'low',
    description: 'Web server access control configuration files were modified — .htpasswd (Apache Basic Authentication password database), digest-auth.conf or basic-auth.conf files configuring authentication for location blocks, or the nginx geo.conf module file used for IP-based allow/deny decisions. .htpasswd changes can add, remove, or replace credential entries controlling who can access Basic-Auth-protected resources. geo.conf changes can reclassify IP ranges as allowed or blocked, expanding or restricting access to geo-restricted APIs or admin panels.',
    recommendation: 'For .htpasswd changes, verify that no accounts were removed that should remain active, and that no new accounts were added without following the credential provisioning process. Confirm that password hashes use bcrypt (Apache 2.4+) rather than legacy MD5/SHA1 hashes that are trivially crackable. For geo.conf changes, verify that IP ranges classified as allowed match the expected source address space (office IPs, VPN exit nodes, partner networks) and that 0.0.0.0/0 has not been added to any allowlist variable. For auth config file changes, confirm that Require valid-user or Require group directives still restrict access appropriately.',
    matches: (p, b) => isWebServerAccessControl(p, b),
  },
]

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

function penaltyFor(sev: WebServerSecuritySeverity, count: number): number {
  switch (sev) {
    case 'high':   return Math.min(count * HIGH_PENALTY_PER, HIGH_PENALTY_CAP)
    case 'medium': return Math.min(count * MED_PENALTY_PER,  MED_PENALTY_CAP)
    case 'low':    return Math.min(count * LOW_PENALTY_PER,  LOW_PENALTY_CAP)
  }
}

function toRiskLevel(score: number): WebServerSecurityRiskLevel {
  if (score === 0) return 'none'
  if (score < 20)  return 'low'
  if (score < 45)  return 'medium'
  if (score < 70)  return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Main scanner
// ---------------------------------------------------------------------------

export function scanWebServerSecurityDrift(filePaths: string[]): WebServerSecurityDriftResult {
  if (filePaths.length === 0) return emptyResult()

  const paths = filePaths
    .map((p) => p.replace(/\\/g, '/'))
    .filter((p) => {
      const lower = p.toLowerCase()
      return !VENDOR_DIRS.some((d) => lower.includes(d))
    })

  if (paths.length === 0) return emptyResult()

  const accumulated = new Map<WebServerSecurityRuleId, { firstPath: string; count: number }>()

  for (const path of paths) {
    const pathLower = path.toLowerCase()
    const base = pathLower.split('/').at(-1) ?? pathLower
    const ext  = base.includes('.') ? `.${base.split('.').at(-1)}` : ''

    for (const rule of WEB_SERVER_SECURITY_RULES) {
      if (rule.matches(pathLower, base, ext)) {
        const existing = accumulated.get(rule.id)
        if (existing) {
          existing.count += 1
        } else {
          accumulated.set(rule.id, { firstPath: path, count: 1 })
        }
      }
    }
  }

  if (accumulated.size === 0) return emptyResult()

  const SEVERITY_ORDER: Record<WebServerSecuritySeverity, number> = { high: 0, medium: 1, low: 2 }
  const findings: WebServerSecurityDriftFinding[] = []

  for (const rule of WEB_SERVER_SECURITY_RULES) {
    const match = accumulated.get(rule.id)
    if (!match) continue
    findings.push({
      ruleId:         rule.id,
      severity:       rule.severity,
      matchedPath:    match.firstPath,
      matchCount:     match.count,
      description:    rule.description,
      recommendation: rule.recommendation,
    })
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])

  const highCount   = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount    = findings.filter((f) => f.severity === 'low').length

  let rawScore = 0
  for (const finding of findings) {
    rawScore += penaltyFor(finding.severity, finding.matchCount)
  }
  const riskScore = Math.min(rawScore, 100)
  const riskLevel = toRiskLevel(riskScore)

  const summary = buildSummary(riskLevel, highCount, mediumCount, lowCount, findings)

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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function emptyResult(): WebServerSecurityDriftResult {
  return {
    riskScore: 0,
    riskLevel: 'none',
    totalFindings: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    findings: [],
    summary: 'No web server or reverse proxy security configuration drift detected.',
  }
}

function buildSummary(
  level: WebServerSecurityRiskLevel,
  high: number,
  medium: number,
  low: number,
  findings: WebServerSecurityDriftFinding[],
): string {
  if (level === 'none') return 'No web server or reverse proxy security configuration drift detected.'

  const parts: string[] = []
  if (high > 0)   parts.push(`${high} high`)
  if (medium > 0) parts.push(`${medium} medium`)
  if (low > 0)    parts.push(`${low} low`)

  const topRule  = findings[0]
  const topLabel = topRule ? topRule.ruleId.replace(/_/g, ' ').toLowerCase() : 'web server security config'

  return `Web server and reverse proxy security drift detected (${parts.join(', ')} finding${findings.length !== 1 ? 's' : ''}). Most prominent: ${topLabel}. Review changes to nginx, Apache, Traefik, Caddy, ingress controller, WAF, and SSL termination configurations to ensure no security controls were weakened or removed.`
}
