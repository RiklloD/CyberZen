// WS-66 — Cryptographic Certificate & PKI Configuration Drift Detector: pure
// computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to cryptographic certificate, PKI trust-chain, and key-management
// configuration files. This scanner focuses on the *crypto trust layer* —
// cert-manager CRDs, CA/PKI certificate files, ACME/Let's Encrypt renewal
// configs, certificate pinning, SSH authorized keys, GPG keyrings,
// Sigstore/cosign signing configs, and TLS CA-bundle/trust-store files.
//
// DISTINCT from:
//   WS-30  — hardcoded secrets (API keys, passwords in source code)
//   WS-60  — application-level security config (JWT, CORS, CSP, TLS options)
//             WS-60 explicitly excludes .pem/.crt/.key cert files — WS-66 owns them
//   WS-62  — cloud-infrastructure security (IAM, KMS key policies, VPC rules)
//   WS-33  — IaC content-level rule checks (Terraform misconfiguration)
//
// Covered rule groups (8 rules):
//
//   CERT_MANAGER_CONFIG_DRIFT          — cert-manager Kubernetes Certificate/Issuer CRDs
//   PKI_CA_CONFIG_DRIFT                — CA certificate files and PKI configuration
//   LETS_ENCRYPT_CONFIG_DRIFT          — ACME / Let's Encrypt / certbot / lego renewal
//   CERTIFICATE_PINNING_CONFIG_DRIFT   — TrustKit, Android NSC, HPKP pinning configs  ← user contribution
//   SSH_AUTH_KEY_DRIFT                 — SSH authorized_keys, sshd_config, host keys
//   GPG_KEYRING_CONFIG_DRIFT           — GPG/PGP keyring files and gpg.conf
//   SIGSTORE_COSIGN_CONFIG_DRIFT       — cosign/Sigstore/Rekor/Fulcio signing configs
//   TLS_CERTIFICATE_BUNDLE_DRIFT       — CA bundle / trust-store files
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Paths inside vendor directories (node_modules, dist, .terraform, etc.) excluded.
//   • Same penalty/cap scoring model as WS-60–65 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (matchedPath + matchCount).
//   • Extension-aware gating: most rules require a recognised file extension so
//     generic source files that happen to contain "ca" or "cert" are excluded.
//
// Exports:
//   isCertificatePinningConfig  — user contribution point (see JSDoc below)
//   CERT_PKI_RULES              — readonly rule registry (for tests / introspection)
//   scanCertPkiDrift            — runs all 8 rules, returns CertPkiDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type CertPkiRuleId =
  | 'CERT_MANAGER_CONFIG_DRIFT'
  | 'PKI_CA_CONFIG_DRIFT'
  | 'LETS_ENCRYPT_CONFIG_DRIFT'
  | 'CERTIFICATE_PINNING_CONFIG_DRIFT'
  | 'SSH_AUTH_KEY_DRIFT'
  | 'GPG_KEYRING_CONFIG_DRIFT'
  | 'SIGSTORE_COSIGN_CONFIG_DRIFT'
  | 'TLS_CERTIFICATE_BUNDLE_DRIFT'

export type CertPkiSeverity = 'high' | 'medium' | 'low'
export type CertPkiRiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none'

export interface CertPkiDriftFinding {
  ruleId: CertPkiRuleId
  severity: CertPkiSeverity
  /** First file path that triggered this rule. */
  matchedPath: string
  /** Total changed files that triggered this rule. */
  matchCount: number
  description: string
  recommendation: string
}

export interface CertPkiDriftResult {
  /** 0 = clean, 100 = maximally risky. */
  riskScore: number
  riskLevel: CertPkiRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  /** One finding per triggered rule (deduped). */
  findings: CertPkiDriftFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// Path utilities (no external dependencies — runs in Convex V8 runtime)
// ---------------------------------------------------------------------------

function normalizePath(p: string): string {
  return p.replace(/\\/g, '/')
}

function getBasename(normalised: string): string {
  const parts = normalised.split('/')
  return parts[parts.length - 1] ?? ''
}

const VENDOR_DIRS = new Set([
  'node_modules', 'dist', 'build', 'vendor', '.yarn',
  '.git', 'coverage', 'out', '.next', '.nuxt',
  '.terraform', '.cdk', 'cdk.out', '__pycache__',
])

function isVendoredPath(normalised: string): boolean {
  return normalised.split('/').some((s) => VENDOR_DIRS.has(s.toLowerCase()))
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function startsWithAny(base: string, prefixes: readonly string[]): boolean {
  return prefixes.some((p) => base.startsWith(p))
}

/** Matches typical config file extensions. */
function isConfigFile(base: string): boolean {
  return /\.(json|yaml|yml|toml|ini|conf|cfg|tf|hcl|env)$/.test(base)
}

/** Matches cert/key material extensions. */
function isCertKeyFile(base: string): boolean {
  return /\.(pem|crt|cer|der|p12|pfx|ca|key|pub)$/.test(base)
}

/** Matches YAML or JSON config files (subset of isConfigFile). */
function isYamlJson(base: string): boolean {
  return /\.(yaml|yml|json)$/.test(base)
}

// ---------------------------------------------------------------------------
// CERT_MANAGER_CONFIG_DRIFT
// ---------------------------------------------------------------------------

const CERT_MANAGER_EXACT = new Set([
  'certificate.yaml', 'certificate.yml', 'certificate.json',
  'issuer.yaml', 'issuer.yml', 'issuer.json',
  'clusterissuer.yaml', 'clusterissuer.yml', 'clusterissuer.json',
  'cluster-issuer.yaml', 'cluster-issuer.yml', 'cluster-issuer.json',
  'certificaterequest.yaml', 'certificaterequest.yml', 'certificaterequest.json',
  'certificate-request.yaml', 'certificate-request.yml',
  'certificaterevocationlist.yaml', 'certificaterevocationlist.yml',
])

const CERT_MANAGER_PREFIXES = [
  'certificate', 'cert-manager', 'certmanager',
  'issuer', 'clusterissuer', 'cluster-issuer',
  'cert-request', 'certificate-request',
]

function isCertManagerConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  const pathLower = normalised.toLowerCase()

  // Any YAML/JSON file inside a /cert-manager/ directory
  if (pathLower.includes('/cert-manager/') && isYamlJson(base)) return true

  if (CERT_MANAGER_EXACT.has(base)) return true
  if (!startsWithAny(base, CERT_MANAGER_PREFIXES)) return false
  return isYamlJson(base)
}

// ---------------------------------------------------------------------------
// PKI_CA_CONFIG_DRIFT
// ---------------------------------------------------------------------------

const PKI_CA_EXACT = new Set([
  'ca.pem', 'ca.crt', 'ca.cer', 'ca.der', 'ca.p12',
  'ca-cert.pem', 'ca-cert.crt', 'ca-certificate.pem', 'ca-certificate.crt',
  'root-ca.crt', 'root-ca.pem', 'root_ca.crt', 'root_ca.pem',
  'intermediate-ca.crt', 'intermediate-ca.pem',
  'intermediate_ca.crt', 'intermediate_ca.pem',
  'ca-chain.crt', 'ca-chain.pem', 'ca_chain.crt', 'ca_chain.pem',
  'pki.json', 'pki.yaml', 'pki.yml', 'pki.tf',
  'pki-config.json', 'pki-config.yaml', 'pki_config.json', 'pki_config.yaml',
])

const PKI_CA_PREFIXES = [
  // 'ca' alone is excluded — too broad: would match cacert, caconfig, etc.
  // Exact-name matching handles ca.pem, ca.crt, etc. via PKI_CA_EXACT.
  'ca-', 'ca_',
  'root-ca', 'root_ca', 'intermediate-ca', 'intermediate_ca',
  'ca-cert', 'ca_cert', 'client-ca', 'client_ca',
  'pki', 'pki-config', 'pki_config',
]

function isPkiCaConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  const pathLower = normalised.toLowerCase()

  if (PKI_CA_EXACT.has(base)) return true

  // Files in /pki/ directory with cert or config extensions
  if (pathLower.includes('/pki/') && (isCertKeyFile(base) || isConfigFile(base))) return true

  if (!startsWithAny(base, PKI_CA_PREFIXES)) return false
  return isCertKeyFile(base) || isConfigFile(base)
}

// ---------------------------------------------------------------------------
// LETS_ENCRYPT_CONFIG_DRIFT
// ---------------------------------------------------------------------------

const ACME_EXACT = new Set([
  'acme.json', 'acme.yaml', 'acme.yml', 'acme.toml', 'acme.conf',
  'letsencrypt.json', 'lets-encrypt.json', 'letsencrypt.yaml', 'letsencrypt.yml',
])

const ACME_PREFIXES = [
  'acme', 'letsencrypt', 'lets-encrypt', 'lets_encrypt',
  'certbot', 'lego', 'acme-config', 'acme_config',
]

const ACME_DIRS = ['/letsencrypt/', '/certbot/', '/acme/', '/.acme/', '/le-certs/']

function isAcmeLetsEncryptConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  const pathLower = normalised.toLowerCase()

  if (ACME_EXACT.has(base)) return true

  // Traefik-style: .acme.json at root
  if (base === '.acme.json') return true

  // Files inside known ACME directories
  if (ACME_DIRS.some((d) => pathLower.includes(d)) && isConfigFile(base)) return true

  if (!startsWithAny(base, ACME_PREFIXES)) return false
  return isConfigFile(base)
}

// ---------------------------------------------------------------------------
// CERTIFICATE_PINNING_CONFIG_DRIFT — user contribution point
// ---------------------------------------------------------------------------

/**
 * Determine whether a normalised file path represents a certificate pinning
 * configuration file.
 *
 * Called by the CERTIFICATE_PINNING_CONFIG_DRIFT rule.
 *
 * Certificate pinning prevents MITM attacks by hard-coding expected server
 * certificate or public-key hashes into the client. Any change to a pinning
 * config can silently disable this protection or break connectivity when the
 * certificate rotates. Changes require coordinated deployment across mobile
 * client releases and server certificate management.
 *
 * Files to detect (examples by platform):
 *   iOS / TrustKit:
 *     TrustKit.plist, TrustKitConfig.plist, trustkit.json
 *   Android / Network Security Config:
 *     network-security-config.xml, res/xml/network_security_config.xml
 *   HTTP Public Key Pinning (HPKP — deprecated but still found):
 *     hpkp-config.json, public-key-pinning.json, hpkp.yaml
 *   Generic / cross-platform SDK:
 *     ssl-pinning.json, cert-pinning.json, certificate-pinning.json
 *     pinning-config.yaml, ssl-pins.json, cert-pins.json
 *   Server-side pin registry:
 *     pins.json, expected-certs.json, pinned-certs.yaml
 *
 * Trade-offs to consider:
 *   - Should `Info.plist` match? It can contain ATS (App Transport Security)
 *     pinning settings, but the generic name causes too many false positives.
 *     The current implementation excludes it; detect only named pinning files.
 *   - Should `res/xml/*.xml` files match? Only when their basename contains a
 *     pinning-related term (see implementation below).
 *   - HPKP header configs inside nginx/Apache configs are out of scope here
 *     because they are content-based, not path-based, detection targets.
 *   - Should `pinned-certs/` directory contents match? Yes, via directory gating.
 *
 * The current implementation detects files by exact name, by pinning-related
 * terms in the basename, or by location inside a pinning-specific directory.
 */
export function isCertificatePinningConfig(normalisedPath: string): boolean {
  const base = getBasename(normalisedPath).toLowerCase()
  const pathLower = normalisedPath.toLowerCase()

  // Android Network Security Config (exact, very specific)
  if (base === 'network-security-config.xml' || base === 'network_security_config.xml') return true

  // iOS TrustKit (exact names)
  if (base === 'trustkit.json' || base === 'trustkit.plist' ||
      base === 'trustkitconfig.plist' || base === 'trustkit-config.plist') return true

  // HPKP-specific exact names
  if (base === 'hpkp.json' || base === 'hpkp.yaml' || base === 'hpkp.yml') return true

  // Files whose basename contains a clear pinning term
  const PINNING_TERMS = [
    'certificate-pinning', 'cert-pinning', 'ssl-pinning', 'ssl_pinning',
    'cert_pinning', 'certificate_pinning', 'hpkp-config', 'hpkp_config',
    'public-key-pinning', 'public_key_pinning',
    'cert-pins', 'cert_pins', 'ssl-pins', 'ssl_pins',
  ]
  if (PINNING_TERMS.some((t) => base.includes(t))) {
    // Require a config/data extension or no extension (extensionless configs)
    const hasExt = base.includes('.')
    if (!hasExt) return true
    return /\.(json|yaml|yml|xml|plist|conf|cfg|toml)$/.test(base)
  }

  // Files inside a pinning-specific directory
  const PIN_DIRS = ['/pinning/', '/cert-pinning/', '/certificate-pinning/', '/pinned-certs/']
  if (PIN_DIRS.some((d) => pathLower.includes(d)) &&
      /\.(json|yaml|yml|xml|plist|conf|cfg)$/.test(base)) return true

  return false
}

// ---------------------------------------------------------------------------
// SSH_AUTH_KEY_DRIFT
// ---------------------------------------------------------------------------

const SSH_EXACT = new Set([
  'authorized_keys', 'authorized_keys2',
  'sshd_config', 'ssh_config',
  'known_hosts', 'known_hosts2',
  'ssh_host_rsa_key.pub', 'ssh_host_dsa_key.pub',
  'ssh_host_ecdsa_key.pub', 'ssh_host_ed25519_key.pub',
  'ssh_host_rsa_key', 'ssh_host_ecdsa_key', 'ssh_host_ed25519_key',
])

const SSH_PREFIXES = [
  'authorized-keys', 'authorized_keys',
  'sshd-config', 'sshd_config', 'ssh-config', 'ssh_config',
  'ssh-host-key', 'ssh_host_key',
]

function isSshAuthKeyConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  const pathLower = normalised.toLowerCase()

  if (SSH_EXACT.has(base)) return true

  // Files in the .ssh/ directory
  if (normalised.split('/').some((seg) => seg === '.ssh')) return true

  // /etc/ssh/ directory (system-wide SSH config)
  if (pathLower.includes('/etc/ssh/')) return true

  if (startsWithAny(base, SSH_PREFIXES)) {
    const hasExt = base.includes('.')
    if (!hasExt) return true
    return /\.(conf|cfg|yaml|yml|json|pub|key)$/.test(base)
  }

  return false
}

// ---------------------------------------------------------------------------
// GPG_KEYRING_CONFIG_DRIFT
// ---------------------------------------------------------------------------

const GPG_EXACT = new Set([
  'pubring.gpg', 'secring.gpg', 'trustdb.gpg', 'pubring.kbx',
  'gpg.conf', 'dirmngr.conf', 'gpg-agent.conf',
])

const GPG_CERT_EXTENSIONS_RE = /\.(gpg|pgp|asc|kbx)$/

const GPG_PREFIXES = [
  'gpg-key', 'gpg_key', 'pgp-key', 'pgp_key',
  'keyring', 'gpg-config', 'gpg_config', 'pgp-config', 'pgp_config',
]

const GPG_DIRS = ['.gnupg', 'gnupg', '.gpg']

function isGpgKeyringConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()

  if (GPG_EXACT.has(base)) return true

  // Files in a GnuPG directory
  if (normalised.split('/').some((seg) => GPG_DIRS.includes(seg.toLowerCase()))) return true

  // .gpg/.pgp/.asc files with GPG-related prefixes
  if (GPG_CERT_EXTENSIONS_RE.test(base) && startsWithAny(base, GPG_PREFIXES)) return true

  // gpg.conf-style: named exactly gpg.conf or variant
  if (startsWithAny(base, GPG_PREFIXES)) {
    return GPG_CERT_EXTENSIONS_RE.test(base) || isConfigFile(base)
  }

  return false
}

// ---------------------------------------------------------------------------
// SIGSTORE_COSIGN_CONFIG_DRIFT
// ---------------------------------------------------------------------------

const COSIGN_EXACT = new Set([
  'cosign.pub', 'cosign.key', 'cosign.yaml', 'cosign.json', 'cosign.tf',
  'sigstore.json', 'sigstore.yaml', 'sigstore.yml',
  'rekor.json', 'rekor.yaml', 'rekor.yml',
  'fulcio.json', 'fulcio.yaml', 'fulcio.yml',
  'provenance.json',
])

const COSIGN_PREFIXES = [
  'cosign', 'sigstore', 'rekor', 'fulcio',
  'slsa', 'in-toto', 'in_toto', 'intoto',
]

const COSIGN_DIRS = ['/cosign/', '/sigstore/', '/slsa/', '/.sigstore/']
const COSIGN_EXT_RE = /\.(json|yaml|yml|pub|key|tf|jsonl)$/

function isSigstoreCosignConfig(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  const pathLower = normalised.toLowerCase()

  if (COSIGN_EXACT.has(base)) return true

  // .intoto.jsonl provenance files
  if (base.endsWith('.intoto.jsonl') || base.endsWith('.provenance.json')) return true

  // Files inside cosign/sigstore/slsa directories
  if (COSIGN_DIRS.some((d) => pathLower.includes(d)) && COSIGN_EXT_RE.test(base)) return true

  if (!startsWithAny(base, COSIGN_PREFIXES)) return false
  return COSIGN_EXT_RE.test(base)
}

// ---------------------------------------------------------------------------
// TLS_CERTIFICATE_BUNDLE_DRIFT
// ---------------------------------------------------------------------------

const TLS_BUNDLE_EXACT = new Set([
  'ca-certificates.crt', 'ca-certificates.pem',
  'cacert.pem', 'cacerts.pem', 'cacert.crt', 'cacerts.crt',
  'ca-bundle.crt', 'ca-bundle.pem',
  'trusted-certs.pem', 'trusted-certs.crt',
  'root-certs.pem', 'root-certs.crt',
  'truststore.jks', 'truststore.p12', 'truststore.bks', 'truststore.pem',
  'keystore.jks', 'keystore.p12',
])

const TLS_BUNDLE_PREFIXES = [
  'ca-bundle', 'ca_bundle', 'ca-certificates', 'ca_certificates',
  'trusted-certs', 'trusted_certs', 'root-certs', 'root_certs',
  'trust-store', 'trust_store', 'truststore',
  'system-certs', 'system_certs',
]

const TLS_BUNDLE_EXT_RE = /\.(crt|pem|cer|jks|p12|bks)$/

const TLS_BUNDLE_DIRS = [
  '/trusted-certs/', '/trust-store/', '/truststore/',
  '/ca-store/', '/ca-certs/', '/system-certs/',
]

function isTlsCertificateBundle(normalised: string): boolean {
  const base = getBasename(normalised).toLowerCase()
  const pathLower = normalised.toLowerCase()

  if (TLS_BUNDLE_EXACT.has(base)) return true

  // Files in trust-store specific directories
  if (TLS_BUNDLE_DIRS.some((d) => pathLower.includes(d)) && TLS_BUNDLE_EXT_RE.test(base)) return true

  if (!startsWithAny(base, TLS_BUNDLE_PREFIXES)) return false
  return TLS_BUNDLE_EXT_RE.test(base)
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

interface CertPkiRule {
  id: CertPkiRuleId
  severity: CertPkiSeverity
  description: string
  recommendation: string
  matches(normalised: string): boolean
}

export const CERT_PKI_RULES: readonly CertPkiRule[] = [
  {
    id: 'CERT_MANAGER_CONFIG_DRIFT',
    severity: 'high',
    description:
      'cert-manager Certificate or Issuer CRD resource modified — cert-manager CRD changes alter which domains receive certificates, which Issuers/ClusterIssuers sign them, and what renewal windows and DNS challenge providers are used. A misconfigured Certificate resource can cause certificate expiry across an entire cluster without any runtime error until the cert expires.',
    recommendation:
      'Review modified cert-manager Certificate and Issuer/ClusterIssuer resources. Verify that dnsNames, secretName, renewBefore, and issuerRef remain correct. Confirm ACME DNS-01 or HTTP-01 challenge solvers are still properly configured. Validate that the secret referenced by secretName exists and that any ClusterIssuer credentials are still valid.',
    matches: isCertManagerConfig,
  },
  {
    id: 'PKI_CA_CONFIG_DRIFT',
    severity: 'high',
    description:
      'PKI/CA certificate file or configuration modified — CA certificate changes affect the entire trust chain for all services and clients that rely on this CA. Replacing or modifying a CA certificate can invalidate all leaf certificates it signed, break mutual TLS, and remove the ability to verify prior signatures. Private-key changes are especially sensitive as they represent the signing authority itself.',
    recommendation:
      'Verify that CA certificate changes are authorised and that the new CA is correctly cross-signed or trusted by all relying parties. Review the certificate chain for correctness (root → intermediate → leaf). Confirm that any private key rotation was accompanied by re-issuance of all leaf certificates. Check that CRL or OCSP endpoints remain reachable.',
    matches: isPkiCaConfig,
  },
  {
    id: 'LETS_ENCRYPT_CONFIG_DRIFT',
    severity: 'high',
    description:
      "ACME / Let's Encrypt / certbot / lego renewal configuration modified — changes to ACME configs affect automatic certificate issuance and renewal for all configured domains. Misconfigured renewal hooks, incorrect challenge solvers, or changed email addresses for expiry notifications can cause unnoticed certificate expiry in production, resulting in a hard service outage.",
    recommendation:
      "Validate that domain names in the renewal config match the actual service hostnames. Confirm that the ACME challenge solver (HTTP-01, DNS-01, or TLS-ALPN-01) is still correctly configured. Ensure the registered account email is monitored for expiry notifications. Run a dry-run renewal (`certbot renew --dry-run`) to verify the configuration before deploying.",
    matches: isAcmeLetsEncryptConfig,
  },
  {
    id: 'CERTIFICATE_PINNING_CONFIG_DRIFT',
    severity: 'medium',
    description:
      'Certificate pinning configuration modified — pinning configs hard-code expected certificate or public-key hashes in mobile and desktop clients. A change that removes a pin disables MITM protection; a change that adds a wrong pin breaks all TLS connections until a new client release. Pinning changes require coordinated rollout across the client fleet and server certificate lifecycle.',
    recommendation:
      'Confirm that any removed pin hashes correspond to certificates that have already been retired from all servers. Verify that new hashes match the expected server leaf certificate or CA public key. Ensure that backup pins are retained to support zero-downtime certificate rotation. Test against both production and staging certificate chains before releasing the updated client.',
    matches: isCertificatePinningConfig,
  },
  {
    id: 'SSH_AUTH_KEY_DRIFT',
    severity: 'medium',
    description:
      'SSH authorized_keys or sshd_config modified — changes to SSH authorised keys grant or revoke interactive and programmatic access to production hosts. Adding an unauthorised key provides persistent access that survives password rotation. Weakening sshd_config (e.g. re-enabling PasswordAuthentication or root login) opens the host to credential-stuffing attacks.',
    recommendation:
      'Audit every added or removed key against your authorised key registry. Verify that removed keys are genuinely decommissioned (no active CI runners or operator workstations rely on them). Confirm that sshd_config changes do not re-enable PasswordAuthentication, PermitRootLogin, or reduce the AllowedAuthentications list. Rotate host keys if they were modified.',
    matches: isSshAuthKeyConfig,
  },
  {
    id: 'GPG_KEYRING_CONFIG_DRIFT',
    severity: 'medium',
    description:
      'GPG keyring or PGP configuration modified — GPG key changes affect code-signing verification, encrypted artefact integrity, and package-repository trust. Removing a trusted key stops verification of artefacts signed with it; adding an untrusted key can allow acceptance of maliciously signed content. Changes to gpg.conf (e.g. disabling signature verification) silently weaken trust.',
    recommendation:
      'Verify that added keys are from authorised signers and that their fingerprints match the expected values from a trusted source. Confirm that removed keys are genuinely revoked and that no unsigned artefacts will pass verification as a result. Check gpg.conf for any weakened verification settings. Ensure the GPG trust-database reflects the intended trust model.',
    matches: isGpgKeyringConfig,
  },
  {
    id: 'SIGSTORE_COSIGN_CONFIG_DRIFT',
    severity: 'medium',
    description:
      'Sigstore/cosign signing key, policy, or SLSA provenance configuration modified — cosign and Sigstore configs control which keys and identities are trusted to sign container images, binaries, and other artefacts. Policy relaxations (e.g. removing required OIDC identity constraints) can allow untrusted parties to sign artefacts that pass verification. SLSA provenance config changes affect supply-chain integrity attestation.',
    recommendation:
      'Review changes to cosign policy for any removal of identity or key constraints. Confirm that signing key rotation was accompanied by re-signing of all current artefacts. Validate that Rekor transparency log inclusion requirements were not weakened. Ensure SLSA provenance predicate requirements remain consistent with your supply-chain security posture.',
    matches: isSigstoreCosignConfig,
  },
  {
    id: 'TLS_CERTIFICATE_BUNDLE_DRIFT',
    severity: 'low',
    description:
      'TLS CA bundle or system trust-store modified — CA bundle changes alter which certificate authorities are trusted by services that consume the bundle. Adding an untrusted CA allows accepting certificates signed by that CA (potential MITM vector). Removing a CA breaks TLS to services using certificates from that authority.',
    recommendation:
      'Verify that any added CA is from a recognised and authorised certificate authority. Confirm that no private or self-signed CAs were inadvertently included in a bundle intended for production. Check that removed CAs are no longer in use by any service in the environment. Review the bundle source and update provenance.',
    matches: isTlsCertificateBundle,
  },
]

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

const PENALTY_PER: Record<CertPkiSeverity, number> = { high: 15, medium: 8, low: 4 }
const PENALTY_CAP: Record<CertPkiSeverity, number> = { high: 45, medium: 25, low: 15 }

function toRiskLevel(score: number): CertPkiRiskLevel {
  if (score === 0) return 'none'
  if (score < 20)  return 'low'
  if (score < 45)  return 'medium'
  if (score < 70)  return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Summary builder
// ---------------------------------------------------------------------------

const RULE_SHORT_LABEL: Record<CertPkiRuleId, string> = {
  CERT_MANAGER_CONFIG_DRIFT:        'cert-manager CRD',
  PKI_CA_CONFIG_DRIFT:              'PKI/CA certificate',
  LETS_ENCRYPT_CONFIG_DRIFT:        "Let's Encrypt / ACME",
  CERTIFICATE_PINNING_CONFIG_DRIFT: 'certificate pinning',
  SSH_AUTH_KEY_DRIFT:               'SSH authorized keys',
  GPG_KEYRING_CONFIG_DRIFT:         'GPG keyring',
  SIGSTORE_COSIGN_CONFIG_DRIFT:     'cosign / Sigstore',
  TLS_CERTIFICATE_BUNDLE_DRIFT:     'TLS CA bundle',
}

function buildSummary(
  findings: CertPkiDriftFinding[],
  riskLevel: CertPkiRiskLevel,
  fileCount: number,
): string {
  if (findings.length === 0) {
    return `Scanned ${fileCount} changed file${fileCount === 1 ? '' : 's'} — no cryptographic certificate or PKI configuration file changes detected.`
  }
  const highFindings = findings.filter((f) => f.severity === 'high')
  if (highFindings.length > 0) {
    const labels  = highFindings.map((f) => RULE_SHORT_LABEL[f.ruleId])
    const unique  = [...new Set(labels)]
    const joined  =
      unique.length <= 2
        ? unique.join(' and ')
        : `${unique.slice(0, -1).join(', ')}, and ${unique[unique.length - 1]}`
    return (
      `${findings.length} cryptographic PKI configuration file${findings.length === 1 ? '' : 's'} modified ` +
      `including ${joined} — mandatory security review required before merge.`
    )
  }
  const total = findings.reduce((a, f) => a + f.matchCount, 0)
  return (
    `${findings.length} cert/PKI configuration change${findings.length === 1 ? '' : 's'} across ` +
    `${total} file${total === 1 ? '' : 's'} (risk level: ${riskLevel}).`
  )
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

/**
 * Analyse a list of changed file paths from a push event and return a
 * risk-scored result indicating which cryptographic certificate and PKI
 * configuration files were modified.
 *
 * - Empty and whitespace-only paths are skipped.
 * - Paths inside vendor/build directories are excluded.
 * - Each rule fires at most once per scan (deduplicated per rule ID).
 * - The finding records the first matched path and total count of matched paths.
 */
export function scanCertPkiDrift(filePaths: string[]): CertPkiDriftResult {
  const ruleAccumulator = new Map<CertPkiRuleId, { firstPath: string; count: number }>()

  for (const rawPath of filePaths) {
    const trimmed = rawPath.trim()
    if (!trimmed) continue

    const normalised = normalizePath(trimmed)
    if (isVendoredPath(normalised)) continue

    for (const rule of CERT_PKI_RULES) {
      if (!rule.matches(normalised)) continue
      const acc = ruleAccumulator.get(rule.id)
      if (acc) {
        acc.count++
      } else {
        ruleAccumulator.set(rule.id, { firstPath: rawPath, count: 1 })
      }
    }
  }

  // Build findings in rule-definition order for consistent output
  const findings: CertPkiDriftFinding[] = []
  for (const rule of CERT_PKI_RULES) {
    const acc = ruleAccumulator.get(rule.id)
    if (!acc) continue
    findings.push({
      ruleId:         rule.id,
      severity:       rule.severity,
      matchedPath:    acc.firstPath,
      matchCount:     acc.count,
      description:    rule.description,
      recommendation: rule.recommendation,
    })
  }

  // Compute score with per-tier caps
  const penaltyByTier: Partial<Record<CertPkiSeverity, number>> = {}
  for (const f of findings) {
    penaltyByTier[f.severity] = (penaltyByTier[f.severity] ?? 0) + PENALTY_PER[f.severity]
  }

  let riskScore = 0
  for (const [sev, total] of Object.entries(penaltyByTier) as [CertPkiSeverity, number][]) {
    riskScore += Math.min(total, PENALTY_CAP[sev])
  }
  riskScore = Math.min(riskScore, 100)

  const riskLevel   = toRiskLevel(riskScore)
  const highCount   = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount    = findings.filter((f) => f.severity === 'low').length

  return {
    riskScore,
    riskLevel,
    totalFindings: findings.length,
    highCount,
    mediumCount,
    lowCount,
    findings,
    summary: buildSummary(findings, riskLevel, filePaths.filter((p) => p.trim()).length),
  }
}
