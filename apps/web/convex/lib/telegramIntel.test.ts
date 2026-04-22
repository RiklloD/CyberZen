import { describe, expect, it } from 'vitest'
import { parseTelegramPost, scoreMessageThreatLevel, type TelegramChannelPost } from './telegramIntel'

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

function makePost(overrides: Partial<TelegramChannelPost> = {}): TelegramChannelPost {
  return {
    message_id: 12345,
    chat: { id: -1001234567890, type: 'channel', title: 'Security Channel', username: 'sec_chan' },
    text: '',
    date: 1700000000,  // Unix timestamp
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// parseTelegramPost — CVE extraction
// ---------------------------------------------------------------------------

describe('parseTelegramPost — CVE extraction', () => {
  it('extracts a single CVE ID from message text', () => {
    const signal = parseTelegramPost(makePost({ text: 'Critical: CVE-2021-44228 is being exploited' }))
    expect(signal.cveIds).toContain('CVE-2021-44228')
  })

  it('extracts multiple CVE IDs', () => {
    const signal = parseTelegramPost(makePost({ text: 'CVE-2021-44228 and CVE-2023-46805 both unpatched' }))
    expect(signal.cveIds).toHaveLength(2)
    expect(signal.cveIds).toContain('CVE-2021-44228')
    expect(signal.cveIds).toContain('CVE-2023-46805')
  })

  it('deduplicates repeated CVE IDs', () => {
    const signal = parseTelegramPost(makePost({ text: 'CVE-2021-44228 CVE-2021-44228 CVE-2021-44228' }))
    expect(signal.cveIds).toHaveLength(1)
  })

  it('normalises CVE IDs to uppercase', () => {
    const signal = parseTelegramPost(makePost({ text: 'cve-2021-44228 is critical' }))
    expect(signal.cveIds).toContain('CVE-2021-44228')
  })

  it('returns empty cveIds when no CVE found', () => {
    const signal = parseTelegramPost(makePost({ text: 'no vulnerability here' }))
    expect(signal.cveIds).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// parseTelegramPost — text/caption handling
// ---------------------------------------------------------------------------

describe('parseTelegramPost — text/caption', () => {
  it('uses caption when text is absent', () => {
    const signal = parseTelegramPost(makePost({ text: undefined, caption: 'CVE-2023-46805 exploit released' }))
    expect(signal.cveIds).toContain('CVE-2023-46805')
  })

  it('truncates text to 2000 chars', () => {
    const longText = 'a'.repeat(3000)
    const signal = parseTelegramPost(makePost({ text: longText }))
    expect(signal.text).toHaveLength(2000)
  })

  it('sets channelId from chat.id', () => {
    const signal = parseTelegramPost(makePost({ chat: { id: -999, type: 'channel' } }))
    expect(signal.channelId).toBe('-999')
  })

  it('sets messageId from message_id', () => {
    const signal = parseTelegramPost(makePost({ message_id: 42 }))
    expect(signal.messageId).toBe('42')
  })

  it('converts date seconds to milliseconds', () => {
    const signal = parseTelegramPost(makePost({ date: 1700000000 }))
    expect(signal.capturedAt).toBe(1700000000 * 1000)
  })

  it('returns none threat level for empty text', () => {
    const signal = parseTelegramPost(makePost({ text: '' }))
    expect(signal.threatLevel).toBe('none')
  })
})

// ---------------------------------------------------------------------------
// parseTelegramPost — credential patterns
// ---------------------------------------------------------------------------

describe('parseTelegramPost — credential detection', () => {
  it('detects GitHub personal access token', () => {
    const signal = parseTelegramPost(makePost({ text: 'Token leaked: ghp_abcdefghijklmnopqrstuvwxyz0123456789' }))
    expect(signal.hasCredentialPattern).toBe(true)
  })

  it('detects AWS access key', () => {
    const signal = parseTelegramPost(makePost({ text: 'AWS key: AKIAIOSFODNN7EXAMPLE found in repo' }))
    expect(signal.hasCredentialPattern).toBe(true)
  })

  it('no credential pattern for benign text', () => {
    const signal = parseTelegramPost(makePost({ text: 'New update released for log4j' }))
    expect(signal.hasCredentialPattern).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// parseTelegramPost — package mentions
// ---------------------------------------------------------------------------

describe('parseTelegramPost — package mentions', () => {
  it('detects package@version pattern', () => {
    const signal = parseTelegramPost(makePost({ text: 'Vuln in log4j@2.14.1 and log4j@2.15.0' }))
    expect(signal.packageMentions.length).toBeGreaterThan(0)
  })
})

// ---------------------------------------------------------------------------
// scoreMessageThreatLevel
// ---------------------------------------------------------------------------

describe('scoreMessageThreatLevel', () => {
  it('returns none for benign signal', () => {
    expect(
      scoreMessageThreatLevel({
        cveIds: [],
        hasCredentialPattern: false,
        hasExploitKeywords: false,
        hasRansomwareKeywords: false,
      }),
    ).toBe('none')
  })

  it('returns medium for CVE reference alone', () => {
    expect(
      scoreMessageThreatLevel({
        cveIds: ['CVE-2021-44228'],
        hasCredentialPattern: false,
        hasExploitKeywords: false,
        hasRansomwareKeywords: false,
      }),
    ).toBe('medium')
  })

  it('returns high for CVE + exploit keywords', () => {
    expect(
      scoreMessageThreatLevel({
        cveIds: ['CVE-2021-44228'],
        hasCredentialPattern: false,
        hasExploitKeywords: true,
        hasRansomwareKeywords: false,
      }),
    ).toBe('high')
  })

  it('returns high for credential pattern alone', () => {
    expect(
      scoreMessageThreatLevel({
        cveIds: [],
        hasCredentialPattern: true,
        hasExploitKeywords: false,
        hasRansomwareKeywords: false,
      }),
    ).toBe('high')
  })

  it('returns critical for credential + CVE co-occurrence', () => {
    expect(
      scoreMessageThreatLevel({
        cveIds: ['CVE-2021-44228'],
        hasCredentialPattern: true,
        hasExploitKeywords: false,
        hasRansomwareKeywords: false,
      }),
    ).toBe('critical')
  })

  it('returns critical for ransomware mention', () => {
    expect(
      scoreMessageThreatLevel({
        cveIds: [],
        hasCredentialPattern: false,
        hasExploitKeywords: false,
        hasRansomwareKeywords: true,
      }),
    ).toBe('critical')
  })

  it('returns low for exploit keywords alone', () => {
    expect(
      scoreMessageThreatLevel({
        cveIds: [],
        hasCredentialPattern: false,
        hasExploitKeywords: true,
        hasRansomwareKeywords: false,
      }),
    ).toBe('low')
  })
})

// ---------------------------------------------------------------------------
// parseTelegramPost — end-to-end threat level
// ---------------------------------------------------------------------------

describe('parseTelegramPost — threat level end-to-end', () => {
  it('lockbit mention → critical threat level', () => {
    const signal = parseTelegramPost(makePost({ text: 'LockBit ransomware group adds new victims' }))
    expect(signal.hasRansomwareKeywords).toBe(true)
    expect(signal.threatLevel).toBe('critical')
  })

  it('exploit keyword → at least low threat level', () => {
    const signal = parseTelegramPost(makePost({ text: 'New POC released for recent vulnerability' }))
    expect(signal.hasExploitKeywords).toBe(true)
    expect(['low', 'medium', 'high', 'critical']).toContain(signal.threatLevel)
  })
})
