// WS-36 — Cryptography Weakness Detector: pure computation library.
//
// Detects use of deprecated or insecure cryptographic algorithms, modes,
// and practices in application source code via static regex-rule analysis.
// No network calls are made.
//
// Exports:
//   detectSourceFileType   — infers language from filename
//   scanFileForCryptoWeakness — runs all applicable rules against content
//   combineCryptoResults   — aggregates per-file results into a summary

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SourceFileType =
  | 'python'
  | 'javascript'
  | 'java'
  | 'golang'
  | 'ruby'
  | 'csharp'
  | 'php'
  | 'rust'
  | 'unknown'

export type CryptoSeverity = 'critical' | 'high' | 'medium' | 'low'

export type CryptoRuleId =
  // ── Weak hash algorithms ──────────────────────────────────────────────────
  /** MD5 used for any purpose — broken collision resistance. */
  | 'CRYPTO_MD5_USAGE'
  /** SHA-1 used for any purpose — broken collision resistance. */
  | 'CRYPTO_SHA1_USAGE'
  // ── Broken ciphers ────────────────────────────────────────────────────────
  /** DES or 3DES (Triple DES) cipher usage — NIST deprecated since 2015. */
  | 'CRYPTO_DES_USAGE'
  /** RC4 stream cipher — broken, prohibited by RFC 7465. */
  | 'CRYPTO_RC4_USAGE'
  /** Blowfish with short key — deprecated, vulnerable to SWEET32. */
  | 'CRYPTO_BLOWFISH_USAGE'
  // ── Insecure cipher modes ─────────────────────────────────────────────────
  /** ECB (Electronic Codebook) mode — deterministic, reveals plaintext patterns. */
  | 'CRYPTO_ECB_MODE'
  /** CBC mode without explicit MAC — susceptible to padding-oracle attacks. */
  | 'CRYPTO_CBC_NO_MAC'
  // ── Weak randomness ───────────────────────────────────────────────────────
  /** Math.random() / random.random() / rand() used for security-sensitive value. */
  | 'CRYPTO_WEAK_RANDOM'
  /** Predictable seed passed to PRNG (0, 1, timestamp with second precision). */
  | 'CRYPTO_SEEDED_PRNG'
  // ── Password hashing ──────────────────────────────────────────────────────
  /** MD5 or SHA-1 used directly for password hashing (no bcrypt/argon2/scrypt). */
  | 'CRYPTO_WEAK_PASSWORD_HASH'
  // ── RSA / asymmetric ─────────────────────────────────────────────────────
  /** RSA key size below 2048 bits — breakable with modern computing. */
  | 'CRYPTO_RSA_WEAK_KEY'
  // ── TLS / certificate verification ───────────────────────────────────────
  /** SSL/TLS certificate verification explicitly disabled. */
  | 'CRYPTO_NO_CERT_VERIFY'
  /** SSLv2, SSLv3, TLSv1.0, or TLSv1.1 explicitly selected — deprecated protocols. */
  | 'CRYPTO_INSECURE_TLS_VERSION'
  // ── Null / no-op cryptography ─────────────────────────────────────────────
  /** NullCipher or equivalent "no encryption" used in production paths. */
  | 'CRYPTO_NULL_CIPHER'
  // ── Miscellaneous ─────────────────────────────────────────────────────────
  /** Base64 encoding presented as or used in place of encryption. */
  | 'CRYPTO_BASE64_AS_ENCRYPTION'
  /** Hardcoded IV of all-zero bytes (IV reuse — destroys confidentiality). */
  | 'CRYPTO_HARDCODED_ZERO_IV'

export type CryptoFinding = {
  ruleId: CryptoRuleId
  severity: CryptoSeverity
  title: string
  description: string
  remediation: string
}

export type CryptoScanResult = {
  filename: string
  fileType: SourceFileType
  findings: CryptoFinding[]
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
}

export type CryptoScanSummary = {
  totalFiles: number
  totalFindings: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  overallRisk: 'critical' | 'high' | 'medium' | 'low' | 'none'
  fileResults: CryptoScanResult[]
  summary: string
}

// ---------------------------------------------------------------------------
// Rule definitions
// ---------------------------------------------------------------------------

type CryptoRule = {
  id: CryptoRuleId
  severity: CryptoSeverity
  title: string
  description: string
  remediation: string
  /** File types this rule applies to; empty means all known types. */
  fileTypes: SourceFileType[]
  pattern: RegExp
}

const ALL_TYPES: SourceFileType[] = [
  'python',
  'javascript',
  'java',
  'golang',
  'ruby',
  'csharp',
  'php',
  'rust',
]

const RULES: CryptoRule[] = [
  // ── Weak hash algorithms ───────────────────────────────────────────────────

  {
    id: 'CRYPTO_MD5_USAGE',
    severity: 'high',
    title: 'MD5 hash algorithm in use',
    description:
      'MD5 is cryptographically broken: collision attacks have been demonstrated since 2004. ' +
      'It must not be used for security-sensitive purposes such as signatures, integrity checks, ' +
      'or certificates.',
    remediation:
      'Replace MD5 with SHA-256 or SHA-3 for general hashing. ' +
      'For password hashing use bcrypt, Argon2id, or scrypt exclusively.',
    fileTypes: ALL_TYPES,
    pattern:
      /(?:hashlib\.md5|createHash\(\s*['"]md5['"]|MessageDigest\.getInstance\(\s*['"]MD5['"]|Digest::MD5|MD5\.digest|MD5\.hexdigest|md5\(\s*\$|openssl_digest\([^,]+,\s*['"]md5['"]|crypto\.Md5|md5\.New\(\)|MD5CryptoServiceProvider)/i,
  },

  {
    id: 'CRYPTO_SHA1_USAGE',
    severity: 'medium',
    title: 'SHA-1 hash algorithm in use',
    description:
      'SHA-1 is considered cryptographically weak: practical collision attacks exist (SHAttered, 2017). ' +
      'While not as immediately dangerous as MD5, it must not be used for digital signatures, ' +
      'certificate fingerprinting, or integrity verification.',
    remediation:
      'Replace SHA-1 with SHA-256 or SHA-3. SHA-1 remains acceptable for non-security use cases ' +
      'such as Git object IDs, but avoid it for authentication or signing.',
    fileTypes: ALL_TYPES,
    pattern:
      /(?:hashlib\.sha1|createHash\(\s*['"]sha1['"]|MessageDigest\.getInstance\(\s*['"]SHA-?1['"]|Digest::SHA1|sha1\(\s*\$|openssl_digest\([^,]+,\s*['"]sha1['"]|crypto\.Sha1|sha1\.New\(\)|SHA1CryptoServiceProvider)/i,
  },

  // ── Broken ciphers ─────────────────────────────────────────────────────────

  {
    id: 'CRYPTO_DES_USAGE',
    severity: 'critical',
    title: 'DES or Triple DES cipher in use',
    description:
      'DES has a 56-bit key space and is trivially brute-forced with modern hardware. ' +
      'Triple DES (3DES) is deprecated by NIST since 2015 and prohibited after 2023. ' +
      'Both ciphers are vulnerable to the SWEET32 birthday attack at scale.',
    remediation:
      'Replace DES/3DES with AES-128 or AES-256 in GCM mode.',
    fileTypes: ALL_TYPES,
    pattern:
      /(?:DES\.new|DES3\.new|Cipher\.getInstance\(\s*['"](?:DES|DESede|3DES|TripleDES)[/'"\s]|createCipheriv\(\s*['"](?:des|des3|des-ede)[^'"]*['"]|cipher\.NewDESEncrypter|DESCryptoServiceProvider|TripleDESCryptoServiceProvider|OpenSSL::Cipher::DES|Cipher\.new\(['"]DES)/i,
  },

  {
    id: 'CRYPTO_RC4_USAGE',
    severity: 'critical',
    title: 'RC4 stream cipher in use',
    description:
      'RC4 is prohibited by RFC 7465 for TLS and is considered broken. It has severe bias in its ' +
      'keystream and is vulnerable to several practical plaintext-recovery attacks.',
    remediation:
      'Replace RC4 with AES-GCM or ChaCha20-Poly1305.',
    fileTypes: ALL_TYPES,
    pattern:
      /(?:ARC4\.new|RC4\.new|Cipher\.getInstance\(\s*['"]RC4['"]|createCipheriv\(\s*['"]rc4['"]|rc4\.NewCipher|RC4CryptoServiceProvider|openssl_encrypt\([^,]+,\s*['"]RC4|Cipher\.new\(['"]RC4)/i,
  },

  {
    id: 'CRYPTO_BLOWFISH_USAGE',
    severity: 'high',
    title: 'Blowfish cipher in use',
    description:
      'Blowfish has a 64-bit block size, making it vulnerable to SWEET32 birthday attacks ' +
      'when encrypting more than approximately 4 GB of data under the same key. ' +
      'It is deprecated in favor of modern 128-bit block ciphers.',
    remediation:
      'Replace Blowfish with AES-128 or AES-256 in GCM mode.',
    fileTypes: ALL_TYPES,
    pattern:
      /(?:Blowfish\.new|Cipher\.getInstance\(\s*['"]Blowfish['"]|createCipheriv\(\s*['"]bf[^'"]*['"]|cipher\.NewBlowfishEncrypter|Cipher\.new\(['"]BF)/i,
  },

  // ── Insecure cipher modes ──────────────────────────────────────────────────

  {
    id: 'CRYPTO_ECB_MODE',
    severity: 'high',
    title: 'AES-ECB (Electronic Codebook) mode in use',
    description:
      'ECB mode encrypts each block independently, producing identical ciphertext blocks for ' +
      'identical plaintext blocks. This reveals data patterns and allows block substitution attacks. ' +
      'The "ECB penguin" is the canonical demonstration of this weakness.',
    remediation:
      'Use AES-GCM (authenticated encryption) or AES-CBC with a random IV and a separate MAC. ' +
      'Prefer AES-GCM as it provides both confidentiality and integrity.',
    fileTypes: ALL_TYPES,
    pattern:
      /(?:AES\.new\([^,]+,\s*AES\.MODE_ECB|Cipher\.getInstance\(\s*['"]AES\/ECB|createCipheriv\(\s*['"]aes-\d+-ecb['"]|NewECBEncrypter|ECBMode|RijndaelManaged[^}]*Mode\s*=\s*CipherMode\.ECB|openssl_encrypt\([^,]+,\s*['"]AES-\d+-ECB)/i,
  },

  {
    id: 'CRYPTO_CBC_NO_MAC',
    severity: 'medium',
    title: 'CBC mode without authenticated encryption',
    description:
      'AES-CBC without a Message Authentication Code (MAC) is susceptible to padding oracle attacks ' +
      '(e.g. POODLE, BEAST). Ciphertext can be tampered without detection.',
    remediation:
      'Prefer AES-GCM which provides built-in authentication. ' +
      'If CBC is required, apply HMAC-SHA256 over the ciphertext (Encrypt-then-MAC pattern).',
    fileTypes: ALL_TYPES,
    pattern:
      /(?:AES\.new\([^,]+,\s*AES\.MODE_CBC|Cipher\.getInstance\(\s*['"]AES\/CBC\/PKCS[^'"]*['"]|createCipheriv\(\s*['"]aes-\d+-cbc['"]|NewCBCEncrypter|CbcEncryptionAlgorithm|openssl_encrypt\([^,]+,\s*['"]AES-\d+-CBC)/i,
  },

  // ── Weak randomness ────────────────────────────────────────────────────────

  {
    id: 'CRYPTO_WEAK_RANDOM',
    severity: 'high',
    title: 'Non-cryptographic PRNG used for security-sensitive value',
    description:
      'Math.random(), Python\'s random.random(), or C\'s rand() are not cryptographically secure ' +
      'PRNGs. Their output is predictable given a small number of observations, making any ' +
      'token, nonce, or key derived from them guessable.',
    remediation:
      'Use a CSPRNG: crypto.randomBytes() in Node.js, secrets.token_bytes() in Python, ' +
      'crypto/rand in Go, or SecureRandom in Java.',
    fileTypes: ALL_TYPES,
    // Matches a security-sensitive context word either before OR after the PRNG call
    // on the same line (within ~60 chars), so both `secret = random.random()` and
    // `const token = Math.random()...` are caught regardless of word order.
    pattern:
      /(?:(?:token|secret|key|nonce|salt|password|csrf|session|auth)[^;\n]{0,60}(?:Math\.random\(\)|random\.random\(\)|random\.randint\(|random\.choice\(|rand\(\))|(?:Math\.random\(\)|random\.random\(\)|random\.randint\(|random\.choice\(|rand\(\))[^;\n]{0,60}(?:token|secret|key|nonce|salt|password|csrf|session|auth))/i,
  },

  {
    id: 'CRYPTO_SEEDED_PRNG',
    severity: 'high',
    title: 'PRNG seeded with predictable value',
    description:
      'Seeding a PRNG with a constant, timestamp, or PID produces a predictable sequence. ' +
      'An attacker who knows or can guess the seed can reproduce all generated values.',
    remediation:
      'Do not seed CSPRNGs — they seed themselves from OS entropy. ' +
      'If a seeded PRNG is needed for reproducibility, keep it strictly separate from any ' +
      'security-sensitive path.',
    fileTypes: ALL_TYPES,
    pattern:
      /(?:random\.seed\(\s*(?:0|1|42|\d{1,4}|time\.|datetime\.|os\.getpid)|srand\(\s*(?:0|1|time\(NULL\)|getpid\(\))|new\s+Random\(\s*(?:0|1|\d{1,6})\s*\)|Math\.seedrandom\(\s*(?:0|1|\d{1,6})\s*\))/i,
  },

  // ── Password hashing ───────────────────────────────────────────────────────

  {
    id: 'CRYPTO_WEAK_PASSWORD_HASH',
    severity: 'critical',
    title: 'MD5 or SHA-1 used for password hashing',
    description:
      'Applying MD5 or SHA-1 directly to a password (even with a salt) is inadequate: ' +
      'these algorithms are designed to be fast, enabling billions of guesses per second ' +
      'on commodity GPU hardware.',
    remediation:
      'Use a purpose-built password hashing function: Argon2id (recommended), bcrypt, or scrypt. ' +
      'Never use a general-purpose hash for passwords.',
    fileTypes: ALL_TYPES,
    pattern:
      /(?:hashlib\.(?:md5|sha1)\([^)]*password|md5\([^)]*password|sha1\([^)]*password|createHash\(\s*['"](?:md5|sha1)['"]\)[^;]{0,60}password|MessageDigest\.getInstance\(\s*['"](?:MD5|SHA-?1)['"]\)[^;]{0,80}password)/i,
  },

  // ── RSA / asymmetric ───────────────────────────────────────────────────────

  {
    id: 'CRYPTO_RSA_WEAK_KEY',
    severity: 'high',
    title: 'RSA key size below 2048 bits',
    description:
      'RSA keys shorter than 2048 bits are considered insecure. NIST recommends 2048 bits as a ' +
      'minimum through 2030, and 3072+ bits for keys that must remain secure beyond that.',
    remediation:
      'Generate RSA keys with a minimum size of 2048 bits. Prefer 4096 bits for long-lived keys ' +
      'or migrate to ECDSA/Ed25519 for equivalent security with smaller key sizes.',
    fileTypes: ALL_TYPES,
    // KeyPairGenerator and .initialize() may appear on separate lines in Java;
    // match .initialize(<weak-size>) independently since it uniquely identifies the weakness.
    pattern:
      /(?:RSA\.generate\(\s*(?:512|768|1024|1280|1536)\b|\.initialize\(\s*(?:512|768|1024|1280|1536)\b|rsa\.GenerateKey\([^,]+,\s*(?:512|768|1024|1280|1536)\b|generateRSAKey(?:Pair)?\([^)]*(?:512|768|1024|1280|1536)\b|new\s+RSAKeyPair\([^)]*(?:512|768|1024|1280|1536)\b)/i,
  },

  // ── TLS / certificate verification ────────────────────────────────────────

  {
    id: 'CRYPTO_NO_CERT_VERIFY',
    severity: 'critical',
    title: 'TLS certificate verification disabled',
    description:
      'Disabling certificate verification makes the connection vulnerable to man-in-the-middle attacks. ' +
      'An attacker positioned on the network can intercept and modify all traffic silently.',
    remediation:
      'Never disable certificate verification in production code. ' +
      'For development environments, use a local CA (e.g. mkcert) rather than disabling verification.',
    fileTypes: ALL_TYPES,
    pattern:
      /(?:verify\s*=\s*False|ssl\._create_unverified_context|InsecureRequestWarning|checkValidity\s*=\s*false|TrustAllCerts|InsecureSkipVerify\s*:\s*true|setHostnameVerifier\(\s*SSLSocketFactory\.ALLOW_ALL_HOSTNAME_VERIFIER\)|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0['"]|rejectUnauthorized\s*:\s*false|ssl_verify\s*=\s*false|SSL_VERIFYPEER\s*=>\s*false)/i,
  },

  {
    id: 'CRYPTO_INSECURE_TLS_VERSION',
    severity: 'critical',
    title: 'Deprecated TLS/SSL protocol version explicitly selected',
    description:
      'SSLv2, SSLv3, TLSv1.0, and TLSv1.1 have known vulnerabilities (POODLE, BEAST, DROWN) ' +
      'and are prohibited by PCI-DSS 3.2+ and RFC 8996. Explicitly selecting these versions ' +
      'overrides the safe platform defaults.',
    remediation:
      'Require TLSv1.2 as a minimum and prefer TLSv1.3. ' +
      'Remove any explicit version overrides and rely on the platform default negotiation.',
    fileTypes: ALL_TYPES,
    pattern:
      /(?:ssl\.PROTOCOL_SSLv2|ssl\.PROTOCOL_SSLv3|ssl\.PROTOCOL_TLSv1\b|ssl\.PROTOCOL_TLSv1_1|SSLv2|SSLv3|TLSv1\.0\b|tls\.VersionTLS10\b|tls\.VersionTLS11\b|MINIMUM_TLS_VERSION\s*=\s*['"](?:TLSv1|TLSv1\.0|TLSv1\.1)['"]|SslProtocols\.Ssl2|SslProtocols\.Ssl3|SslProtocols\.Tls\b(?!\d))/i,
  },

  // ── Null / no-op cryptography ──────────────────────────────────────────────

  {
    id: 'CRYPTO_NULL_CIPHER',
    severity: 'critical',
    title: 'Null cipher or no-encryption scheme in use',
    description:
      'NullCipher and equivalent constructs perform no actual encryption, transmitting data in ' +
      'plaintext while appearing to use a cipher. This is a common mistake when testing that ' +
      'is accidentally left in production code.',
    remediation:
      'Replace NullCipher with a real cipher. Use AES-GCM for symmetric encryption.',
    fileTypes: ALL_TYPES,
    pattern:
      /(?:NullCipher|Cipher\.getInstance\(\s*['"]NONE['"]|createCipheriv\(\s*['"]none['"]|NullEncryptionAlgorithm|EncryptionType\.None\b)/i,
  },

  // ── Miscellaneous ──────────────────────────────────────────────────────────

  {
    id: 'CRYPTO_BASE64_AS_ENCRYPTION',
    severity: 'medium',
    title: 'Base64 encoding used as encryption substitute',
    description:
      'Base64 is an encoding scheme, not encryption. Encoded data is trivially reversible by ' +
      'anyone who sees it. Treating base64 as a security measure provides no confidentiality protection.',
    remediation:
      'Use proper authenticated encryption (AES-GCM) if confidentiality is required. ' +
      'Base64 is appropriate for encoding binary data for transport, never for protecting secrets.',
    fileTypes: ALL_TYPES,
    pattern:
      /(?:base64(?:\.b64encode|\.encode|\.encodestring)?[^;]{0,40}encrypt|encrypt[^;]{0,40}base64|"encrypted"[^;]{0,30}base64|base64[^;]{0,40}"secure"|btoa\([^)]+\)[^;]{0,40}(?:token|secret|encrypt))/i,
  },

  {
    id: 'CRYPTO_HARDCODED_ZERO_IV',
    severity: 'high',
    title: 'All-zero IV hardcoded for symmetric cipher',
    description:
      'An initialization vector (IV) of all-zero bytes is equivalent to no IV. ' +
      'Reusing the same IV with the same key allows attackers to recover plaintext by XOR-ing ' +
      'two ciphertexts encrypted with the same key+IV pair.',
    remediation:
      'Generate a random IV using a CSPRNG for every encryption operation and transmit it ' +
      'alongside the ciphertext. With AES-GCM, the 12-byte nonce must be unique per encryption.',
    fileTypes: ALL_TYPES,
    pattern:
      /(?:iv\s*=\s*(?:b['"]\\x00{8,}['"]|\[0\]\s*\*\s*\d+|bytes\(\d+\)|b['"][\\x00 ]+['"]|\x27\\0{8,}\x27|"\x00{8,}"|Array\.fill\(0\))|IV\s*=\s*new\s+byte\[\d+\](?!\s*{[^}]*[^0])|initialization_vector\s*=\s*(?:b'\\x00+'))/i,
  },
]

// ---------------------------------------------------------------------------
// detectSourceFileType
// ---------------------------------------------------------------------------

/**
 * Infers the source language from the filename.
 *
 * Rules (first match wins):
 *   *.py                    → python
 *   *.js / *.ts / *.jsx / *.tsx / *.mjs / *.cjs → javascript
 *   *.java                  → java
 *   *.go                    → golang
 *   *.rb                    → ruby
 *   *.cs                    → csharp
 *   *.php                   → php
 *   *.rs                    → rust
 *   everything else         → unknown
 */
export function detectSourceFileType(filename: string): SourceFileType {
  const lower = filename.toLowerCase()
  const base = lower.split(/[/\\]/).pop() ?? lower

  if (base.endsWith('.py')) return 'python'
  if (/\.(js|ts|jsx|tsx|mjs|cjs)$/.test(base)) return 'javascript'
  if (base.endsWith('.java')) return 'java'
  if (base.endsWith('.go')) return 'golang'
  if (base.endsWith('.rb')) return 'ruby'
  if (base.endsWith('.cs')) return 'csharp'
  if (base.endsWith('.php')) return 'php'
  if (base.endsWith('.rs')) return 'rust'
  return 'unknown'
}

// ---------------------------------------------------------------------------
// scanFileForCryptoWeakness
// ---------------------------------------------------------------------------

/**
 * Runs all cryptography-weakness rules applicable to the detected file type
 * against the provided content string.
 *
 * @param filename  Used to infer the source language
 * @param content   Full text of the source file
 */
export function scanFileForCryptoWeakness(filename: string, content: string): CryptoScanResult {
  const fileType = detectSourceFileType(filename)

  // Skip files we don't understand
  const applicableRules =
    fileType === 'unknown'
      ? []
      : RULES.filter((r) => r.fileTypes.length === 0 || r.fileTypes.includes(fileType))

  const findings: CryptoFinding[] = []

  for (const rule of applicableRules) {
    if (rule.pattern.test(content)) {
      findings.push({
        ruleId: rule.id,
        severity: rule.severity,
        title: rule.title,
        description: rule.description,
        remediation: rule.remediation,
      })
    }
  }

  const criticalCount = findings.filter((f) => f.severity === 'critical').length
  const highCount = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount = findings.filter((f) => f.severity === 'low').length

  return { filename, fileType, findings, criticalCount, highCount, mediumCount, lowCount }
}

// ---------------------------------------------------------------------------
// combineCryptoResults
// ---------------------------------------------------------------------------

/**
 * Aggregates per-file scan results into a single summary.
 */
export function combineCryptoResults(results: CryptoScanResult[]): CryptoScanSummary {
  const totalFindings = results.reduce((s, r) => s + r.findings.length, 0)
  const criticalCount = results.reduce((s, r) => s + r.criticalCount, 0)
  const highCount = results.reduce((s, r) => s + r.highCount, 0)
  const mediumCount = results.reduce((s, r) => s + r.mediumCount, 0)
  const lowCount = results.reduce((s, r) => s + r.lowCount, 0)

  const overallRisk: CryptoScanSummary['overallRisk'] =
    criticalCount > 0
      ? 'critical'
      : highCount > 0
        ? 'high'
        : mediumCount > 0
          ? 'medium'
          : lowCount > 0
            ? 'low'
            : 'none'

  const summary =
    results.length === 0
      ? 'No source files scanned for cryptographic weaknesses.'
      : totalFindings === 0
        ? `Scanned ${results.length} source file${results.length === 1 ? '' : 's'}. No cryptographic weaknesses found.`
        : `Scanned ${results.length} source file${results.length === 1 ? '' : 's'}. Found ${totalFindings} cryptographic weakness${totalFindings === 1 ? '' : 'es'}` +
          (criticalCount > 0 ? ` (${criticalCount} critical)` : '') +
          '.'

  return {
    totalFiles: results.length,
    totalFindings,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    overallRisk,
    fileResults: results,
    summary,
  }
}
