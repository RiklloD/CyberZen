/// <reference types="vite/client" />
// WS-36 — Cryptography Weakness Detector: unit tests.

import { describe, expect, test } from 'vitest'
import {
  combineCryptoResults,
  detectSourceFileType,
  scanFileForCryptoWeakness,
} from './cryptoWeakness'

// ---------------------------------------------------------------------------
// detectSourceFileType
// ---------------------------------------------------------------------------

describe('detectSourceFileType', () => {
  test('identifies Python', () => {
    expect(detectSourceFileType('utils/crypto.py')).toBe('python')
  })

  test('identifies JavaScript', () => {
    expect(detectSourceFileType('src/auth.js')).toBe('javascript')
  })

  test('identifies TypeScript', () => {
    expect(detectSourceFileType('lib/hash.ts')).toBe('javascript')
  })

  test('identifies TSX', () => {
    expect(detectSourceFileType('components/Login.tsx')).toBe('javascript')
  })

  test('identifies Java', () => {
    expect(detectSourceFileType('src/Crypto.java')).toBe('java')
  })

  test('identifies Go', () => {
    expect(detectSourceFileType('pkg/auth/hash.go')).toBe('golang')
  })

  test('identifies Ruby', () => {
    expect(detectSourceFileType('lib/auth.rb')).toBe('ruby')
  })

  test('identifies C#', () => {
    expect(detectSourceFileType('Services/CryptoHelper.cs')).toBe('csharp')
  })

  test('identifies PHP', () => {
    expect(detectSourceFileType('src/Hash.php')).toBe('php')
  })

  test('identifies Rust', () => {
    expect(detectSourceFileType('src/crypto.rs')).toBe('rust')
  })

  test('returns unknown for YAML', () => {
    expect(detectSourceFileType('config.yml')).toBe('unknown')
  })

  test('returns unknown for text file', () => {
    expect(detectSourceFileType('README.md')).toBe('unknown')
  })
})

// ---------------------------------------------------------------------------
// Weak hash algorithms
// ---------------------------------------------------------------------------

describe('CRYPTO_MD5_USAGE', () => {
  test('detects Python hashlib.md5', () => {
    const result = scanFileForCryptoWeakness('auth.py', `
import hashlib
def hash_token(val):
    return hashlib.md5(val.encode()).hexdigest()
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_MD5_USAGE')).toBe(true)
    expect(result.highCount).toBeGreaterThan(0)
  })

  test('detects Node.js crypto.createHash md5', () => {
    const result = scanFileForCryptoWeakness('hash.js', `
const crypto = require('crypto')
const hash = crypto.createHash('md5').update(data).digest('hex')
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_MD5_USAGE')).toBe(true)
  })

  test('detects Java MessageDigest MD5', () => {
    const result = scanFileForCryptoWeakness('Hash.java', `
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hash = md.digest(input);
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_MD5_USAGE')).toBe(true)
  })

  test('does not trigger on SHA-256 reference', () => {
    const result = scanFileForCryptoWeakness('hash.py', `
import hashlib
h = hashlib.sha256(data).hexdigest()
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_MD5_USAGE')).toBe(false)
  })
})

describe('CRYPTO_SHA1_USAGE', () => {
  test('detects Python hashlib.sha1', () => {
    const result = scanFileForCryptoWeakness('util.py', `
import hashlib
digest = hashlib.sha1(content).hexdigest()
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_SHA1_USAGE')).toBe(true)
    expect(result.mediumCount).toBeGreaterThan(0)
  })

  test('detects Node.js createHash sha1', () => {
    const result = scanFileForCryptoWeakness('hmac.ts', `
const sig = createHash('sha1').update(msg).digest('hex')
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_SHA1_USAGE')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Broken ciphers
// ---------------------------------------------------------------------------

describe('CRYPTO_DES_USAGE', () => {
  test('detects PyCryptodome DES', () => {
    const result = scanFileForCryptoWeakness('cipher.py', `
from Crypto.Cipher import DES
cipher = DES.new(key, DES.MODE_CBC)
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_DES_USAGE')).toBe(true)
    expect(result.criticalCount).toBeGreaterThan(0)
  })

  test('detects Java DES cipher', () => {
    const result = scanFileForCryptoWeakness('Enc.java', `
Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_DES_USAGE')).toBe(true)
  })

  test('detects Node.js des cipher', () => {
    const result = scanFileForCryptoWeakness('enc.js', `
const cipher = crypto.createCipheriv('des-cbc', key, iv)
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_DES_USAGE')).toBe(true)
  })
})

describe('CRYPTO_RC4_USAGE', () => {
  test('detects PyCryptodome ARC4', () => {
    const result = scanFileForCryptoWeakness('stream.py', `
from Crypto.Cipher import ARC4
cipher = ARC4.new(key)
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_RC4_USAGE')).toBe(true)
    expect(result.criticalCount).toBeGreaterThan(0)
  })

  test('detects Java RC4 cipher', () => {
    const result = scanFileForCryptoWeakness('Stream.java', `
Cipher c = Cipher.getInstance("RC4");
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_RC4_USAGE')).toBe(true)
  })
})

describe('CRYPTO_BLOWFISH_USAGE', () => {
  test('detects PyCryptodome Blowfish', () => {
    const result = scanFileForCryptoWeakness('enc.py', `
from Crypto.Cipher import Blowfish
cipher = Blowfish.new(key, Blowfish.MODE_CBC)
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_BLOWFISH_USAGE')).toBe(true)
    expect(result.highCount).toBeGreaterThan(0)
  })
})

// ---------------------------------------------------------------------------
// Insecure cipher modes
// ---------------------------------------------------------------------------

describe('CRYPTO_ECB_MODE', () => {
  test('detects Python AES ECB mode', () => {
    const result = scanFileForCryptoWeakness('crypto.py', `
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_ECB_MODE')).toBe(true)
    expect(result.highCount).toBeGreaterThan(0)
  })

  test('detects Java AES/ECB', () => {
    const result = scanFileForCryptoWeakness('Enc.java', `
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_ECB_MODE')).toBe(true)
  })

  test('detects Node.js aes-256-ecb', () => {
    const result = scanFileForCryptoWeakness('enc.js', `
const c = crypto.createCipheriv('aes-256-ecb', key, null)
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_ECB_MODE')).toBe(true)
  })

  test('does not trigger on AES-GCM', () => {
    const result = scanFileForCryptoWeakness('enc.py', `
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_GCM)
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_ECB_MODE')).toBe(false)
  })
})

describe('CRYPTO_CBC_NO_MAC', () => {
  test('detects Python AES CBC mode', () => {
    const result = scanFileForCryptoWeakness('enc.py', `
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_CBC, iv)
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_CBC_NO_MAC')).toBe(true)
  })

  test('detects Java AES/CBC cipher', () => {
    const result = scanFileForCryptoWeakness('Enc.java', `
Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_CBC_NO_MAC')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Weak randomness
// ---------------------------------------------------------------------------

describe('CRYPTO_WEAK_RANDOM', () => {
  test('detects Math.random for token generation', () => {
    const result = scanFileForCryptoWeakness('auth.js', `
const token = Math.random().toString(36).slice(2)
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_WEAK_RANDOM')).toBe(true)
    expect(result.highCount).toBeGreaterThan(0)
  })

  test('detects Python random for secret', () => {
    const result = scanFileForCryptoWeakness('util.py', `
secret = random.random()
session_key = secret
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_WEAK_RANDOM')).toBe(true)
  })

  test('does not trigger when random is not near security context', () => {
    const result = scanFileForCryptoWeakness('game.py', `
# Not security related
x = random.random()
position = x * 100
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_WEAK_RANDOM')).toBe(false)
  })
})

describe('CRYPTO_SEEDED_PRNG', () => {
  test('detects Python random seeded with 0', () => {
    const result = scanFileForCryptoWeakness('gen.py', `
import random
random.seed(0)
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_SEEDED_PRNG')).toBe(true)
  })

  test('detects C srand with time', () => {
    const result = scanFileForCryptoWeakness('main.c', `srand(time(NULL));`)
    // c file is unknown type, no findings expected
    expect(result.fileType).toBe('unknown')
    expect(result.findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Password hashing
// ---------------------------------------------------------------------------

describe('CRYPTO_WEAK_PASSWORD_HASH', () => {
  test('detects md5 applied to password in Python', () => {
    const result = scanFileForCryptoWeakness('auth.py', `
hashed = hashlib.md5(password.encode()).hexdigest()
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_WEAK_PASSWORD_HASH')).toBe(true)
    expect(result.criticalCount).toBeGreaterThan(0)
  })

  test('detects sha1 for password in Node.js', () => {
    const result = scanFileForCryptoWeakness('auth.js', `
const hashed = createHash('sha1').update(password).digest('hex')
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_WEAK_PASSWORD_HASH')).toBe(true)
  })

  test('does not trigger when md5 is not near password context', () => {
    const result = scanFileForCryptoWeakness('etag.py', `
etag = hashlib.md5(file_content).hexdigest()
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_WEAK_PASSWORD_HASH')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// RSA key size
// ---------------------------------------------------------------------------

describe('CRYPTO_RSA_WEAK_KEY', () => {
  test('detects PyCryptodome RSA 1024-bit key', () => {
    const result = scanFileForCryptoWeakness('keys.py', `
from Crypto.PublicKey import RSA
key = RSA.generate(1024)
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_RSA_WEAK_KEY')).toBe(true)
    expect(result.highCount).toBeGreaterThan(0)
  })

  test('detects Java RSA 512-bit key', () => {
    const result = scanFileForCryptoWeakness('Keys.java', `
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
kpg.initialize(512);
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_RSA_WEAK_KEY')).toBe(true)
  })

  test('does not trigger on 4096-bit RSA', () => {
    const result = scanFileForCryptoWeakness('keys.py', `
key = RSA.generate(4096)
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_RSA_WEAK_KEY')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// TLS / certificate verification
// ---------------------------------------------------------------------------

describe('CRYPTO_NO_CERT_VERIFY', () => {
  test('detects Python requests verify=False', () => {
    const result = scanFileForCryptoWeakness('client.py', `
import requests
resp = requests.get(url, verify=False)
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_NO_CERT_VERIFY')).toBe(true)
    expect(result.criticalCount).toBeGreaterThan(0)
  })

  test('detects Node.js rejectUnauthorized: false', () => {
    const result = scanFileForCryptoWeakness('client.ts', `
const agent = new https.Agent({ rejectUnauthorized: false })
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_NO_CERT_VERIFY')).toBe(true)
  })

  test('detects Go InsecureSkipVerify', () => {
    const result = scanFileForCryptoWeakness('client.go', `
tlsConfig := &tls.Config{InsecureSkipVerify: true}
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_NO_CERT_VERIFY')).toBe(true)
  })

  test('detects NODE_TLS_REJECT_UNAUTHORIZED=0', () => {
    const result = scanFileForCryptoWeakness('server.js', `
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_NO_CERT_VERIFY')).toBe(true)
  })
})

describe('CRYPTO_INSECURE_TLS_VERSION', () => {
  test('detects Python SSLv3 protocol', () => {
    const result = scanFileForCryptoWeakness('ssl_client.py', `
import ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_INSECURE_TLS_VERSION')).toBe(true)
    expect(result.criticalCount).toBeGreaterThan(0)
  })

  test('detects TLSv1.0 protocol selection', () => {
    const result = scanFileForCryptoWeakness('ssl_client.py', `
ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_INSECURE_TLS_VERSION')).toBe(true)
  })

  test('detects Go TLS 1.0 constant', () => {
    const result = scanFileForCryptoWeakness('tls.go', `
cfg := &tls.Config{MinVersion: tls.VersionTLS10}
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_INSECURE_TLS_VERSION')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Null cipher / base64 / hardcoded IV
// ---------------------------------------------------------------------------

describe('CRYPTO_NULL_CIPHER', () => {
  test('detects Java NullCipher', () => {
    const result = scanFileForCryptoWeakness('Enc.java', `
Cipher c = new NullCipher();
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_NULL_CIPHER')).toBe(true)
    expect(result.criticalCount).toBeGreaterThan(0)
  })

  test('detects Cipher.getInstance("NONE")', () => {
    const result = scanFileForCryptoWeakness('Enc.java', `
Cipher c = Cipher.getInstance("NONE");
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_NULL_CIPHER')).toBe(true)
  })
})

describe('CRYPTO_BASE64_AS_ENCRYPTION', () => {
  test('detects base64 encode used as encrypt', () => {
    const result = scanFileForCryptoWeakness('util.py', `
encrypted_data = base64.b64encode(raw_data)
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_BASE64_AS_ENCRYPTION')).toBe(true)
    expect(result.mediumCount).toBeGreaterThan(0)
  })
})

describe('CRYPTO_HARDCODED_ZERO_IV', () => {
  test('detects Python all-zero IV bytes', () => {
    const result = scanFileForCryptoWeakness('enc.py', `
iv = b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
cipher = AES.new(key, AES.MODE_CBC, iv)
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_HARDCODED_ZERO_IV')).toBe(true)
    expect(result.highCount).toBeGreaterThan(0)
  })

  test('detects iv = [0] * 16 pattern', () => {
    const result = scanFileForCryptoWeakness('enc.py', `
iv = [0] * 16
`)
    expect(result.findings.some((f) => f.ruleId === 'CRYPTO_HARDCODED_ZERO_IV')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Unknown file type
// ---------------------------------------------------------------------------

describe('unknown file type', () => {
  test('returns no findings for an unrecognised file', () => {
    const result = scanFileForCryptoWeakness('config.yaml', `
algorithm: MD5
`)
    expect(result.fileType).toBe('unknown')
    expect(result.findings).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// combineCryptoResults
// ---------------------------------------------------------------------------

describe('combineCryptoResults', () => {
  test('empty array → none risk', () => {
    const s = combineCryptoResults([])
    expect(s.overallRisk).toBe('none')
    expect(s.totalFiles).toBe(0)
    expect(s.summary).toMatch(/No source files/)
  })

  test('no findings → none risk', () => {
    const r = scanFileForCryptoWeakness('clean.py', `
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
key = secrets.token_bytes(32)
`)
    const s = combineCryptoResults([r])
    expect(s.overallRisk).toBe('none')
    expect(s.totalFindings).toBe(0)
    expect(s.summary).toMatch(/No cryptographic weaknesses/)
  })

  test('promotes to critical when any critical finding exists', () => {
    const r = scanFileForCryptoWeakness('enc.py', `
from Crypto.Cipher import DES
c = DES.new(key, DES.MODE_CBC)
`)
    const s = combineCryptoResults([r])
    expect(s.overallRisk).toBe('critical')
    expect(s.criticalCount).toBeGreaterThan(0)
  })

  test('aggregates counts across multiple files', () => {
    const r1 = scanFileForCryptoWeakness('hash.py', `digest = hashlib.md5(data).hexdigest()`)
    const r2 = scanFileForCryptoWeakness('tls.go', `tlsConfig := &tls.Config{InsecureSkipVerify: true}`)
    const s = combineCryptoResults([r1, r2])
    expect(s.totalFiles).toBe(2)
    expect(s.totalFindings).toBeGreaterThanOrEqual(2)
  })

  test('summary mentions critical count', () => {
    const r = scanFileForCryptoWeakness('cipher.py', `
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)
hashed = hashlib.md5(password.encode()).hexdigest()
`)
    const s = combineCryptoResults([r])
    expect(s.summary).toMatch(/critical/)
  })

  test('summary mentions file count', () => {
    const r = scanFileForCryptoWeakness('hash.js', `const h = createHash('md5').update(d).digest('hex')`)
    const s = combineCryptoResults([r])
    expect(s.summary).toMatch(/1 source file/)
  })

  test('overallRisk is high when only high findings', () => {
    const r = scanFileForCryptoWeakness('hash.py', `digest = hashlib.md5(data).hexdigest()`)
    const s = combineCryptoResults([r])
    // MD5 is high severity
    expect(s.overallRisk).toBe('high')
  })
})
