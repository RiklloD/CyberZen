// Telegram threat intelligence parser — pure library.
//
// Parses Telegram channel posts and direct messages for security threat signals:
//   CVE identifiers, package version mentions, credential leak patterns,
//   exploit keywords, and ransomware campaign keywords.
//
// Used by:
//   • POST /webhooks/telegram  — Telegram Bot API webhook delivery
//   • syncTelegramChannel action — Bot API polling (getUpdates)
//
// No network calls here — just pattern matching and scoring.

// ---------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------

const CVE_PATTERN = /CVE-\d{4}-\d{4,7}/gi

const CREDENTIAL_PATTERNS: RegExp[] = [
  /(?:password|passwd|pwd)\s*[:=]\s*\S+/gi,
  /(?:api[_-]?key|api_token|access_token|secret[_-]?key)\s*[:=]\s*[A-Za-z0-9+/]{20,}/gi,
  /gh[pousr]_[A-Za-z0-9]{36,}/g,   // GitHub personal access tokens
  /AKIA[0-9A-Z]{16}/g,              // AWS access key IDs
  /sk-[A-Za-z0-9]{32,}/g,          // OpenAI / Anthropic-style keys
]

const EXPLOIT_KEYWORDS = [
  'exploit', 'poc', 'proof of concept', '0day', 'zero-day', 'rce',
  'remote code execution', 'privilege escalation', 'privesc', 'lpe',
  'code execution', 'buffer overflow', 'use after free', 'uaf',
  'heap spray', 'shellcode', 'payload', 'reverse shell',
]

const RANSOMWARE_KEYWORDS = [
  'ransomware', 'lockbit', 'blackcat', 'alphv', 'clop', 'akira',
  'conti', 'ryuk', 'blackmatter', 'darkside', 'hive',
  'scattered spider', 'scattered spider',
]

// Simple package@version or package==version patterns.
// Matches things like "log4j@2.14.1", "requests==2.28.0".
const PACKAGE_PATTERN = /[a-z][a-z0-9_-]+[@=:]\d+\.\d+[\d.]*/gi

// ---------------------------------------------------------------------------
// Input / output types
// ---------------------------------------------------------------------------

/** Minimal Telegram update shape we need — covers both channel_post and message. */
export type TelegramChannelPost = {
  message_id: number
  chat: { id: number; type: string; title?: string; username?: string }
  text?: string
  caption?: string
  date: number  // Unix timestamp seconds
  from?: { id: number; username?: string; is_bot?: boolean }
}

export type TelegramThreatSignal = {
  channelId: string
  messageId: string
  text: string                // truncated to 2 000 chars
  cveIds: string[]
  packageMentions: string[]
  hasCredentialPattern: boolean
  hasExploitKeywords: boolean
  hasRansomwareKeywords: boolean
  threatLevel: 'critical' | 'high' | 'medium' | 'low' | 'none'
  capturedAt: number          // Unix milliseconds
}

// ---------------------------------------------------------------------------
// Extraction helpers
// ---------------------------------------------------------------------------

function extractCveIds(text: string): string[] {
  const raw = text.match(CVE_PATTERN) ?? []
  return [...new Set(raw.map((id) => id.toUpperCase()))]
}

function detectCredentialPatterns(text: string): boolean {
  return CREDENTIAL_PATTERNS.some((pattern) => {
    pattern.lastIndex = 0
    return pattern.test(text)
  })
}

function detectExploitKeywords(text: string): boolean {
  const lower = text.toLowerCase()
  return EXPLOIT_KEYWORDS.some((kw) => lower.includes(kw))
}

function detectRansomwareKeywords(text: string): boolean {
  const lower = text.toLowerCase()
  return RANSOMWARE_KEYWORDS.some((kw) => lower.includes(kw))
}

function extractPackageMentions(text: string): string[] {
  const raw = text.match(PACKAGE_PATTERN) ?? []
  return [...new Set(raw)]
}

// ---------------------------------------------------------------------------
// Threat scoring
// ---------------------------------------------------------------------------

/**
 * Score a threat level from extracted signal components.
 * Exported for independent unit testing of the scoring logic.
 */
export function scoreMessageThreatLevel(
  signal: Pick<
    TelegramThreatSignal,
    'cveIds' | 'hasCredentialPattern' | 'hasExploitKeywords' | 'hasRansomwareKeywords'
  >,
): TelegramThreatSignal['threatLevel'] {
  const { cveIds, hasCredentialPattern, hasExploitKeywords, hasRansomwareKeywords } = signal

  // Critical: ransomware campaign confirmed
  if (hasRansomwareKeywords) return 'critical'

  // Critical: credential leak co-located with exploit content
  if (hasCredentialPattern && (cveIds.length > 0 || hasExploitKeywords)) return 'critical'

  // High: known CVE discussed alongside exploit technique
  if (cveIds.length > 0 && hasExploitKeywords) return 'high'

  // High: credential pattern without other context (potential data breach)
  if (hasCredentialPattern) return 'high'

  // Medium: CVE referenced (may be patch announcement or researcher post)
  if (cveIds.length > 0) return 'medium'

  // Low: exploit technique keywords without specific CVE
  if (hasExploitKeywords) return 'low'

  return 'none'
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/**
 * Parse a Telegram channel post or message into a structured threat signal.
 * Pure function — no async, no DB calls.
 */
export function parseTelegramPost(post: TelegramChannelPost): TelegramThreatSignal {
  const rawText = (post.text ?? post.caption ?? '').trim()
  const text = rawText.slice(0, 2000)

  const cveIds = extractCveIds(text)
  const packageMentions = extractPackageMentions(text)
  const hasCredentialPattern = detectCredentialPatterns(text)
  const hasExploitKeywords = detectExploitKeywords(text)
  const hasRansomwareKeywords = detectRansomwareKeywords(text)

  const threatLevel = scoreMessageThreatLevel({
    cveIds,
    hasCredentialPattern,
    hasExploitKeywords,
    hasRansomwareKeywords,
  })

  return {
    channelId: post.chat.id.toString(),
    messageId: post.message_id.toString(),
    text,
    cveIds,
    packageMentions,
    hasCredentialPattern,
    hasExploitKeywords,
    hasRansomwareKeywords,
    threatLevel,
    capturedAt: post.date * 1000,
  }
}
