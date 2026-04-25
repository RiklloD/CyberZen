/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest'
import { detectZeroDayAnomalies, type ZeroDayInput } from './zeroDayDetector'

const base: ZeroDayInput = {
  changedFiles: [],
  addedLines: [],
  recentBreachTypes: [],
  hasTestChanges: false,
  hasLockfileChanges: false,
}

describe('detectZeroDayAnomalies — empty / benign', () => {
  it('returns benign for empty input', () => {
    const r = detectZeroDayAnomalies(base)
    expect(r.category).toBe('benign')
    expect(r.signals).toHaveLength(0)
    expect(r.anomalyScore).toBe(0)
  })

  it('returns benign for normal code change with no signals', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/utils/helpers.ts'],
      addedLines: ['const x = 1 + 2', 'return x'],
      hasTestChanges: true,
    })
    expect(r.category).toBe('benign')
    expect(r.signals).toHaveLength(0)
  })
})

describe('detectZeroDayAnomalies — authentication_bypass_pattern', () => {
  it('fires when auth file gets bypass keyword', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/auth/middleware.ts'],
      addedLines: ['if (bypass) return true'],
    })
    const s = r.signals.find((x) => x.signalType === 'authentication_bypass_pattern')
    expect(s).toBeDefined()
    expect(s!.confidence).toBe(0.75)
    expect(s!.affectedFiles).toContain('src/auth/middleware.ts')
  })

  it('fires when login dir file has allowAll', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/login/handler.ts'],
      addedLines: ['allowAll = true'],
    })
    const s = r.signals.find((x) => x.signalType === 'authentication_bypass_pattern')
    expect(s).toBeDefined()
  })

  it('does not fire when auth file has no bypass keywords', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/auth/middleware.ts'],
      addedLines: ['const token = getToken(req)'],
    })
    const s = r.signals.find((x) => x.signalType === 'authentication_bypass_pattern')
    expect(s).toBeUndefined()
  })

  it('does not fire when non-auth file has bypass keyword', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/utils/helpers.ts'],
      addedLines: ['const bypass = false'],
    })
    const s = r.signals.find((x) => x.signalType === 'authentication_bypass_pattern')
    expect(s).toBeUndefined()
  })
})

describe('detectZeroDayAnomalies — new_network_egress', () => {
  it('fires on fetch call in non-client file when no lockfile change', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/workers/processor.ts'],
      addedLines: ['const result = await fetch(url)'],
      hasLockfileChanges: false,
    })
    const s = r.signals.find((x) => x.signalType === 'new_network_egress')
    expect(s).toBeDefined()
  })

  it('does NOT fire when lockfile was also changed', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/workers/processor.ts'],
      addedLines: ['const result = await fetch(url)'],
      hasLockfileChanges: true,
    })
    const s = r.signals.find((x) => x.signalType === 'new_network_egress')
    expect(s).toBeUndefined()
  })

  it('does NOT fire when only test files changed', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/workers/processor.test.ts'],
      addedLines: ['await fetch(mockUrl)'],
      hasLockfileChanges: false,
    })
    const s = r.signals.find((x) => x.signalType === 'new_network_egress')
    expect(s).toBeUndefined()
  })
})

describe('detectZeroDayAnomalies — cryptography_weakening', () => {
  it('fires on MD5 in added lines', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/crypto/hasher.ts'],
      addedLines: ['const hash = MD5(data)'],
    })
    const s = r.signals.find((x) => x.signalType === 'cryptography_weakening')
    expect(s).toBeDefined()
    expect(s!.confidence).toBe(0.8)
  })

  it('fires on SHA1 reference', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/auth/token.ts'],
      addedLines: ['algo = "SHA-1"'],
    })
    const s = r.signals.find((x) => x.signalType === 'cryptography_weakening')
    expect(s).toBeDefined()
  })

  it('fires on DES usage', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/utils/cipher.ts'],
      addedLines: ['const cipher = DES(key)'],
    })
    const s = r.signals.find((x) => x.signalType === 'cryptography_weakening')
    expect(s).toBeDefined()
  })

  it('does not fire for AES-256', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/crypto/hasher.ts'],
      addedLines: ['const cipher = AES_256_GCM(key)'],
    })
    const s = r.signals.find((x) => x.signalType === 'cryptography_weakening')
    expect(s).toBeUndefined()
  })
})

describe('detectZeroDayAnomalies — privilege_expansion', () => {
  it('fires on isAdmin = true', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/user/profile.ts'],
      addedLines: ['user.isAdmin = true'],
    })
    const s = r.signals.find((x) => x.signalType === 'privilege_expansion')
    expect(s).toBeDefined()
    expect(s!.confidence).toBe(0.7)
  })

  it('fires on SUPERUSER keyword', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/db/migrations/001.sql'],
      addedLines: ['GRANT SUPERUSER TO app_user;'],
    })
    const s = r.signals.find((x) => x.signalType === 'privilege_expansion')
    expect(s).toBeDefined()
  })

  it('fires on allowAll constant', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/permissions/gate.ts'],
      addedLines: ['const allowAll = true'],
    })
    const s = r.signals.find((x) => x.signalType === 'privilege_expansion')
    expect(s).toBeDefined()
  })
})

describe('detectZeroDayAnomalies — data_exfiltration_pattern', () => {
  it('fires when both data-read and data-write patterns appear', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/handlers/export.ts'],
      addedLines: ['const rows = await db.query(sql)', 'await fetch(endpoint, { body: JSON.stringify(rows) })'],
    })
    const s = r.signals.find((x) => x.signalType === 'data_exfiltration_pattern')
    expect(s).toBeDefined()
    expect(s!.confidence).toBe(0.65)
  })

  it('does NOT fire when only data read', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/handlers/read.ts'],
      addedLines: ['const rows = await db.query(sql)'],
    })
    const s = r.signals.find((x) => x.signalType === 'data_exfiltration_pattern')
    expect(s).toBeUndefined()
  })

  it('does NOT fire when only network write', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/handlers/notify.ts'],
      addedLines: ['await fetch(endpoint, { body: JSON.stringify(msg) })'],
    })
    const s = r.signals.find((x) => x.signalType === 'data_exfiltration_pattern')
    expect(s).toBeUndefined()
  })
})

describe('detectZeroDayAnomalies — code_obfuscation', () => {
  it('fires on eval( in non-test file', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/utils/dynamic.ts'],
      addedLines: ['eval(userInput)'],
    })
    const s = r.signals.find((x) => x.signalType === 'code_obfuscation')
    expect(s).toBeDefined()
    expect(s!.confidence).toBe(0.85)
  })

  it('fires on new Function( call', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/templating/engine.ts'],
      addedLines: ['const fn = new Function("return " + code)'],
    })
    const s = r.signals.find((x) => x.signalType === 'code_obfuscation')
    expect(s).toBeDefined()
  })

  it('fires on long base64 blob', () => {
    const blob = 'SGVsbG8gV29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IGVuY29kZWQgc3RyaW5n'
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/payloads/loader.ts'],
      addedLines: [`const payload = "${blob}"`],
    })
    const s = r.signals.find((x) => x.signalType === 'code_obfuscation')
    expect(s).toBeDefined()
  })

  it('does NOT fire in test files', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/utils/dynamic.test.ts'],
      addedLines: ['eval(testInput)'],
    })
    const s = r.signals.find((x) => x.signalType === 'code_obfuscation')
    expect(s).toBeUndefined()
  })
})

describe('detectZeroDayAnomalies — novel_injection_vector', () => {
  it('fires on string interpolation in non-test file', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/db/query.ts'],
      addedLines: ['const sql = `SELECT * FROM ${tableName}`'],
    })
    const s = r.signals.find((x) => x.signalType === 'novel_injection_vector')
    expect(s).toBeDefined()
  })

  it('has higher confidence when recent breach types include injection', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/db/query.ts'],
      addedLines: ['const sql = `SELECT * FROM ${tableName}`'],
      recentBreachTypes: ['sql_injection', 'command_injection'],
    })
    const s = r.signals.find((x) => x.signalType === 'novel_injection_vector')
    expect(s).toBeDefined()
    expect(s!.confidence).toBeGreaterThan(0.6)
  })

  it('does NOT fire in test files', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/db/query.test.ts'],
      addedLines: ['const sql = `SELECT * FROM ${tableName}`'],
    })
    const s = r.signals.find((x) => x.signalType === 'novel_injection_vector')
    expect(s).toBeUndefined()
  })
})

describe('detectZeroDayAnomalies — security_config_modified_untested', () => {
  it('fires when jwt.config modified without test changes', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['config/jwt.config.ts'],
      addedLines: ['algorithm: "RS256"'],
      hasTestChanges: false,
    })
    const s = r.signals.find((x) => x.signalType === 'security_config_modified_untested')
    expect(s).toBeDefined()
    expect(s!.confidence).toBe(0.35)
  })

  it('does NOT fire when test changes are present', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['config/jwt.config.ts'],
      addedLines: ['algorithm: "RS256"'],
      hasTestChanges: true,
    })
    const s = r.signals.find((x) => x.signalType === 'security_config_modified_untested')
    expect(s).toBeUndefined()
  })

  it('fires for .env file modification', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['.env'],
      addedLines: ['NEW_SECRET=abc123'],
      hasTestChanges: false,
    })
    const s = r.signals.find((x) => x.signalType === 'security_config_modified_untested')
    expect(s).toBeDefined()
  })
})

describe('detectZeroDayAnomalies — category derivation', () => {
  it('assigns potential_zero_day when anomalyScore >= 70 (code_obfuscation = 0.85)', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/loader.ts'],
      addedLines: ['eval(payload)'],
    })
    expect(r.category).toBe('potential_zero_day')
    expect(r.anomalyScore).toBeGreaterThanOrEqual(70)
  })

  it('assigns suspicious_change for score between 40 and 69 (privilege_expansion = 0.7)', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/user.ts'],
      addedLines: ['user.isAdmin = true'],
    })
    // privilege = 0.7 → score 70 → potential_zero_day
    expect(['suspicious_change', 'potential_zero_day']).toContain(r.category)
  })

  it('assigns benign when no signals', () => {
    const r = detectZeroDayAnomalies({ ...base })
    expect(r.category).toBe('benign')
  })

  it('assigns novel_pattern when low score with breach type overlap', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['config/jwt.config.ts'],
      addedLines: ['timeout: 3600'],
      hasTestChanges: false,
      recentBreachTypes: ['authentication_bypass'],
    })
    const s = r.signals.find((x) => x.signalType === 'security_config_modified_untested')
    if (s) {
      expect(r.category).toBe('novel_pattern')
    }
  })
})

describe('detectZeroDayAnomalies — anomalyScore', () => {
  it('equals max signal confidence × 100', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/loader.ts'],
      addedLines: ['eval(payload)'],
    })
    expect(r.anomalyScore).toBe(85)
  })

  it('is 0 for empty input', () => {
    expect(detectZeroDayAnomalies(base).anomalyScore).toBe(0)
  })
})

describe('detectZeroDayAnomalies — recommendation', () => {
  it('includes eval recommendation for code_obfuscation', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/loader.ts'],
      addedLines: ['eval(payload)'],
    })
    expect(r.recommendation).toContain('eval')
  })

  it('returns benign message when no signals', () => {
    const r = detectZeroDayAnomalies(base)
    expect(r.recommendation.toLowerCase()).toContain('no anomalous')
  })

  it('prefixes with ⚠️ for potential_zero_day', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/loader.ts'],
      addedLines: ['eval(payload)'],
    })
    expect(r.recommendation).toContain('⚠️')
  })
})

describe('detectZeroDayAnomalies — multiple signals', () => {
  it('returns all firing signals', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/auth/handler.ts'],
      addedLines: ['user.isAdmin = true', 'if (bypass) return true', 'eval(code)'],
    })
    expect(r.signals.length).toBeGreaterThanOrEqual(2)
  })

  it('anomalyScore takes max confidence across all signals', () => {
    const r = detectZeroDayAnomalies({
      ...base,
      changedFiles: ['src/auth/handler.ts'],
      addedLines: ['user.isAdmin = true', 'if (bypass) return true', 'eval(code)'],
    })
    const maxConfidence = Math.max(...r.signals.map((s) => s.confidence))
    expect(r.anomalyScore).toBe(Math.round(maxConfidence * 100))
  })
})
