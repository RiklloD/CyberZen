/// <reference types="vite/client" />
import { describe, expect, test } from 'vitest'
import {
  cosineSimilarity,
  normalize,
  searchPatterns,
  buildCodeContext,
  type StoredPattern,
} from './codeEmbedding'

// ── Vector math ───────────────────────────────────────────────────────────────

describe('cosineSimilarity', () => {
  test('identical vectors have similarity 1.0', () => {
    const v = [0.5, 0.5, 0.5, 0.5]
    expect(cosineSimilarity(v, v)).toBeCloseTo(1.0, 5)
  })

  test('orthogonal vectors have similarity 0', () => {
    expect(cosineSimilarity([1, 0], [0, 1])).toBeCloseTo(0, 5)
  })

  test('opposite vectors have similarity -1.0', () => {
    expect(cosineSimilarity([1, 0], [-1, 0])).toBeCloseTo(-1.0, 5)
  })

  test('returns 0 for empty vectors', () => {
    expect(cosineSimilarity([], [])).toBe(0)
  })

  test('returns 0 for mismatched lengths', () => {
    expect(cosineSimilarity([1, 2], [1])).toBe(0)
  })

  test('returns 0 for zero vectors', () => {
    expect(cosineSimilarity([0, 0], [0, 0])).toBe(0)
  })

  test('partial similarity between related vectors', () => {
    const sim = cosineSimilarity([1, 1, 0], [1, 0, 0])
    expect(sim).toBeGreaterThan(0.5)
    expect(sim).toBeLessThan(1.0)
  })
})

describe('normalize', () => {
  test('unit vector unchanged', () => {
    const v = [1, 0, 0]
    const result = normalize(v)
    expect(result[0]).toBeCloseTo(1, 5)
    expect(result[1]).toBeCloseTo(0, 5)
  })

  test('normalized vector has magnitude 1.0', () => {
    const v = [3, 4, 0]  // magnitude = 5
    const result = normalize(v)
    const mag = Math.sqrt(result.reduce((s, x) => s + x * x, 0))
    expect(mag).toBeCloseTo(1.0, 5)
  })

  test('zero vector unchanged', () => {
    expect(normalize([0, 0, 0])).toEqual([0, 0, 0])
  })
})

// ── Pattern search ────────────────────────────────────────────────────────────

function makePattern(id: string, vulnClass: string, vector: number[]): StoredPattern {
  return {
    patternId: id,
    vulnClass,
    severity: 'high',
    description: `${vulnClass} description`,
    vector: normalize(vector),
  }
}

describe('searchPatterns', () => {
  const patterns: StoredPattern[] = [
    makePattern('P1', 'sql_injection', [1, 0, 0, 0]),
    makePattern('P2', 'xss', [0, 1, 0, 0]),
    makePattern('P3', 'ssrf', [0, 0, 1, 0]),
    makePattern('P4', 'path_traversal', [0.9, 0.1, 0, 0]),
  ]

  test('returns top matching pattern', () => {
    const query = normalize([1, 0, 0, 0])  // closest to P1
    const results = searchPatterns(query, patterns, { topK: 1, minSimilarity: 0.5 })
    expect(results[0].patternId).toBe('P1')
    expect(results[0].vulnClass).toBe('sql_injection')
    expect(results[0].similarity).toBeGreaterThan(0.99)
  })

  test('filters by minSimilarity', () => {
    const query = normalize([1, 0, 0, 0])
    const results = searchPatterns(query, patterns, { minSimilarity: 0.98 })
    // Only P1 and P4 are close enough
    expect(results.length).toBeLessThanOrEqual(2)
    expect(results.every((r) => r.similarity >= 0.98)).toBe(true)
  })

  test('returns topK results', () => {
    const query = normalize([1, 0.5, 0, 0])
    const results = searchPatterns(query, patterns, { topK: 2, minSimilarity: 0.5 })
    expect(results.length).toBeLessThanOrEqual(2)
  })

  test('returns empty array when no patterns match', () => {
    const query = normalize([0, 0, 0, 1])
    const results = searchPatterns(query, patterns, { minSimilarity: 0.99 })
    expect(results).toHaveLength(0)
  })

  test('results are sorted by similarity descending', () => {
    const query = normalize([1, 0.5, 0, 0])
    const results = searchPatterns(query, patterns, { topK: 3, minSimilarity: 0.1 })
    for (let i = 1; i < results.length; i++) {
      expect(results[i - 1].similarity).toBeGreaterThanOrEqual(results[i].similarity)
    }
  })

  test('confidence is between 0 and 1', () => {
    const query = normalize([1, 0, 0, 0])
    const results = searchPatterns(query, patterns, { minSimilarity: 0.5 })
    for (const r of results) {
      expect(r.confidence).toBeGreaterThanOrEqual(0)
      expect(r.confidence).toBeLessThanOrEqual(1)
    }
  })

  test('empty patterns returns empty results', () => {
    const query = normalize([1, 0, 0, 0])
    expect(searchPatterns(query, [], {})).toHaveLength(0)
  })
})

// ── Code context extraction ───────────────────────────────────────────────────

describe('buildCodeContext', () => {
  test('includes repository name', () => {
    const ctx = buildCodeContext({
      repositoryName: 'acme/payments',
      changedFiles: [],
      packageDependencies: [],
    })
    expect(ctx).toContain('acme/payments')
  })

  test('includes changed files', () => {
    const ctx = buildCodeContext({
      repositoryName: 'repo',
      changedFiles: ['src/auth/login.ts', 'src/api/users.ts'],
      packageDependencies: [],
    })
    expect(ctx).toContain('src/auth/login.ts')
    expect(ctx).toContain('src/api/users.ts')
  })

  test('includes commit message when provided', () => {
    const ctx = buildCodeContext({
      repositoryName: 'repo',
      changedFiles: [],
      packageDependencies: [],
      commitMessage: 'fix: security patch for auth bypass',
    })
    expect(ctx).toContain('security patch for auth bypass')
  })

  test('includes package dependencies', () => {
    const ctx = buildCodeContext({
      repositoryName: 'repo',
      changedFiles: [],
      packageDependencies: ['express', 'lodash', 'jsonwebtoken'],
    })
    expect(ctx).toContain('jsonwebtoken')
  })

  test('truncates long file lists to 50 entries', () => {
    const files = Array.from({ length: 100 }, (_, i) => `file${i}.ts`)
    const ctx = buildCodeContext({
      repositoryName: 'repo',
      changedFiles: files,
      packageDependencies: [],
    })
    const fileLines = ctx.split('\n').filter((l) => l.startsWith('  file'))
    expect(fileLines.length).toBeLessThanOrEqual(50)
  })
})
