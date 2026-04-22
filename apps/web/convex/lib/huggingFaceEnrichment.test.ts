/// <reference types="vite/client" />
/**
 * Tests for the HuggingFace enrichment pure library.
 *
 * Covers: component identification, model ID extraction, API response parsing
 * (happy path, partial responses, edge-case tag formats, gating variants).
 */

import { describe, expect, test } from 'vitest'
import {
  extractHFModelId,
  isHuggingFaceComponent,
  parseHFApiResponse,
} from './huggingFaceEnrichment'

// ── isHuggingFaceComponent ────────────────────────────────────────────────────

describe('isHuggingFaceComponent', () => {
  test('matches explicit huggingface ecosystem', () => {
    expect(
      isHuggingFaceComponent('meta-llama/Llama-2-7b', 'huggingface', 'ai_model'),
    ).toBe(true)
  })

  test('matches hugging_face ecosystem variant', () => {
    expect(
      isHuggingFaceComponent('mistralai/Mistral-7B', 'hugging_face', 'ai_model'),
    ).toBe(true)
  })

  test('matches ai_model layer with org/model pattern', () => {
    expect(
      isHuggingFaceComponent('sentence-transformers/all-MiniLM-L6-v2', 'pypi', 'ai_model'),
    ).toBe(true)
  })

  test('matches ai-model (hyphenated) layer with org/model pattern', () => {
    expect(
      isHuggingFaceComponent('BAAI/bge-small-en-v1.5', 'unknown', 'ai-model'),
    ).toBe(true)
  })

  test('rejects npm scoped packages (@ prefix)', () => {
    expect(
      isHuggingFaceComponent('@openai/api', 'npm', 'direct'),
    ).toBe(false)
  })

  test('rejects Go module paths (hostname in org segment)', () => {
    expect(
      isHuggingFaceComponent('github.com/owner/repo', 'go', 'direct'),
    ).toBe(false)
  })

  test('rejects pypi packages with no slash', () => {
    expect(
      isHuggingFaceComponent('transformers', 'pypi', 'direct'),
    ).toBe(false)
  })

  test('rejects path with three segments', () => {
    expect(
      isHuggingFaceComponent('org/model/variant', 'huggingface', 'ai_model'),
    ).toBe(false)
  })

  test('rejects empty name', () => {
    expect(isHuggingFaceComponent('', 'huggingface', 'ai_model')).toBe(false)
  })

  test('non-ai-model layer without explicit HF ecosystem is not matched', () => {
    // A pypi package on the "direct" layer with a slash-name is NOT HF
    expect(
      isHuggingFaceComponent('some-org/some-package', 'pypi', 'direct'),
    ).toBe(false)
  })
})

// ── extractHFModelId ──────────────────────────────────────────────────────────

describe('extractHFModelId', () => {
  test('returns the name for a standard org/model pattern', () => {
    expect(extractHFModelId('meta-llama/Llama-2-7b')).toBe('meta-llama/Llama-2-7b')
  })

  test('returns null for empty string', () => {
    expect(extractHFModelId('')).toBeNull()
  })

  test('returns null for names with no slash', () => {
    expect(extractHFModelId('transformers')).toBeNull()
  })

  test('returns null for npm scoped package', () => {
    expect(extractHFModelId('@huggingface/inference')).toBeNull()
  })

  test('returns null for three-segment path', () => {
    expect(extractHFModelId('a/b/c')).toBeNull()
  })

  test('returns null for hostname-style org', () => {
    expect(extractHFModelId('github.com/org/model')).toBeNull()
  })

  test('preserves original casing', () => {
    expect(extractHFModelId('BAAI/bge-small-en-v1.5')).toBe('BAAI/bge-small-en-v1.5')
  })
})

// ── parseHFApiResponse — happy path ──────────────────────────────────────────

describe('parseHFApiResponse — full response', () => {
  const fullResponse = {
    id: 'meta-llama/Llama-2-7b',
    sha: 'abc123def456',
    private: false,
    gated: 'auto',
    disabled: false,
    pipeline_tag: 'text-generation',
    lastModified: '2023-07-18T09:35:00.000Z',
    cardData: {
      license: 'llama2',
      datasets: ['bookcorpus', 'wikipedia'],
    },
    siblings: [
      { rfilename: 'README.md' },
      { rfilename: 'config.json' },
      { rfilename: 'pytorch_model.bin' },
    ],
    tags: ['transformers', 'dataset:c4', 'license:llama2'],
  }

  test('parses ok: true', () => {
    const r = parseHFApiResponse('meta-llama/Llama-2-7b', fullResponse)
    expect(r.ok).toBe(true)
  })

  test('extracts commit SHA', () => {
    const r = parseHFApiResponse('meta-llama/Llama-2-7b', fullResponse)
    expect(r.ok && r.commitSha).toBe('abc123def456')
  })

  test('prefers cardData.license over tag license', () => {
    const r = parseHFApiResponse('meta-llama/Llama-2-7b', fullResponse)
    expect(r.ok && r.license).toBe('llama2')
  })

  test('detects README.md → modelCardPresent', () => {
    const r = parseHFApiResponse('meta-llama/Llama-2-7b', fullResponse)
    expect(r.ok && r.modelCardPresent).toBe(true)
  })

  test('merges cardData datasets with dataset: tags, deduplicated', () => {
    const r = parseHFApiResponse('meta-llama/Llama-2-7b', fullResponse)
    if (!r.ok) throw new Error('expected ok')
    // bookcorpus + wikipedia from cardData, c4 from tag, llama2 tag is NOT a dataset
    expect(r.trainingDatasets).toContain('bookcorpus')
    expect(r.trainingDatasets).toContain('wikipedia')
    expect(r.trainingDatasets).toContain('c4')
    expect(r.trainingDatasets).not.toContain('llama2')
  })

  test('marks model as gated when gated: "auto"', () => {
    const r = parseHFApiResponse('meta-llama/Llama-2-7b', fullResponse)
    expect(r.ok && r.isGated).toBe(true)
  })

  test('extracts pipeline_tag', () => {
    const r = parseHFApiResponse('meta-llama/Llama-2-7b', fullResponse)
    expect(r.ok && r.pipelineTag).toBe('text-generation')
  })

  test('extracts lastModified', () => {
    const r = parseHFApiResponse('meta-llama/Llama-2-7b', fullResponse)
    expect(r.ok && r.lastModified).toBe('2023-07-18T09:35:00.000Z')
  })
})

// ── parseHFApiResponse — partial / edge cases ─────────────────────────────────

describe('parseHFApiResponse — partial responses', () => {
  test('gated: true (boolean) → isGated true', () => {
    const r = parseHFApiResponse('org/model', { sha: 'x', gated: true })
    expect(r.ok && r.isGated).toBe(true)
  })

  test('gated: "manual" → isGated true', () => {
    const r = parseHFApiResponse('org/model', { gated: 'manual' })
    expect(r.ok && r.isGated).toBe(true)
  })

  test('gated: false → isGated false', () => {
    const r = parseHFApiResponse('org/model', { gated: false })
    expect(r.ok && r.isGated).toBe(false)
  })

  test('no siblings → modelCardPresent false', () => {
    const r = parseHFApiResponse('org/model', { sha: 'abc' })
    expect(r.ok && r.modelCardPresent).toBe(false)
  })

  test('README.md case-insensitive match', () => {
    const r = parseHFApiResponse('org/model', {
      siblings: [{ rfilename: 'readme.md' }],
    })
    expect(r.ok && r.modelCardPresent).toBe(true)
  })

  test('missing cardData → license falls back to tag', () => {
    const r = parseHFApiResponse('org/model', {
      tags: ['license:apache-2.0'],
    })
    expect(r.ok && r.license).toBe('apache-2.0')
  })

  test('no license anywhere → license null', () => {
    const r = parseHFApiResponse('org/model', { tags: ['transformers'] })
    expect(r.ok && r.license).toBeNull()
  })

  test('empty response → all fields null/false/empty', () => {
    const r = parseHFApiResponse('org/model', {})
    if (!r.ok) throw new Error('expected ok')
    expect(r.commitSha).toBeNull()
    expect(r.license).toBeNull()
    expect(r.modelCardPresent).toBe(false)
    expect(r.trainingDatasets).toEqual([])
    expect(r.isGated).toBe(false)
    expect(r.pipelineTag).toBeNull()
    expect(r.lastModified).toBeNull()
  })

  test('duplicate dataset across cardData and tags is deduplicated', () => {
    const r = parseHFApiResponse('org/model', {
      cardData: { datasets: ['bookcorpus'] },
      tags: ['dataset:bookcorpus', 'dataset:wikipedia'],
    })
    if (!r.ok) throw new Error('expected ok')
    const ds = r.trainingDatasets
    expect(ds.filter((d) => d.toLowerCase() === 'bookcorpus')).toHaveLength(1)
    expect(ds).toContain('wikipedia')
  })

  test('preserves modelId in result', () => {
    const r = parseHFApiResponse('BAAI/bge-small-en', {})
    expect(r.modelId).toBe('BAAI/bge-small-en')
  })
})
