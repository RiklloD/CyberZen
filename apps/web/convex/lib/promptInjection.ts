// Prompt injection detection heuristics — pure, no Convex dependencies.
// Scans arbitrary text content for patterns associated with prompt injection
// attacks, jailbreak attempts, privilege escalation, and data-exfiltration
// instructions that are commonly embedded in untrusted inputs (PR bodies,
// commit messages, package README files, issue titles, etc.).
//
// Design principles:
//   - Cumulative scoring: multiple matched patterns compound the score.
//     A single stray "act as" in normal prose is low-signal; three layered
//     patterns together are high-confidence.
//   - Categories are independent: matching in multiple categories adds weight
//     from each, reflecting the multi-technique nature of real attacks.
//   - No false-positive panic: thresholds are calibrated so that ordinary
//     developer prose (hypothetical examples, CLI docs) stays below 'suspicious'.

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type InjectionRiskLevel =
  | 'clean'
  | 'suspicious'
  | 'likely_injection'
  | 'confirmed_injection'

export type InjectionPatternMatch = {
  patternId: string
  category: string
  matchedText: string
  description: string
  weight: number
}

export type InjectionScanResult = {
  /** Cumulative injection likelihood score (0 = clean, 100 = confirmed). */
  score: number
  riskLevel: InjectionRiskLevel
  /** IDs of all matched patterns. */
  detectedPatterns: string[]
  /** Unique categories that were matched. */
  categories: string[]
  matches: InjectionPatternMatch[]
  summary: string
}

type PatternDefinition = {
  patternId: string
  category: string
  description: string
  weight: number
  pattern: RegExp
}

// ---------------------------------------------------------------------------
// Pattern corpus
// ---------------------------------------------------------------------------

const PATTERNS: PatternDefinition[] = [
  // ── Role escalation ───────────────────────────────────────────────────────
  {
    patternId: 'PI-RE-001',
    category: 'role_escalation',
    description: 'Ignore-previous-instructions directive',
    weight: 25,
    pattern:
      /ignore\s+(all\s+)?(previous|prior|above|earlier|old|your)\s+instructions?/i,
  },
  {
    patternId: 'PI-RE-002',
    category: 'role_escalation',
    description: 'Disregard-prompt directive',
    weight: 25,
    pattern:
      /disregard\s+(all\s+)?(previous|prior|your|the\s+above)\s+(instructions?|prompt|context)/i,
  },
  {
    patternId: 'PI-RE-003',
    category: 'role_escalation',
    description: 'Identity-replacement directive (you are now / act as)',
    weight: 20,
    pattern:
      /\b(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|from\s+now\s+on\s+(you\s+are|act))/i,
  },
  {
    patternId: 'PI-RE-004',
    category: 'role_escalation',
    description: 'New-instruction boundary injection',
    weight: 15,
    pattern: /\bnew\s+(instruction|prompt|system\s+message|task|directive)\s*:/i,
  },
  {
    patternId: 'PI-RE-005',
    category: 'role_escalation',
    description: 'Override / forget / reset context directive',
    weight: 20,
    pattern:
      /\b(override|forget|reset|clear)\s+(your\s+)?(system\s+prompt|instructions?|context|prior\s+context|rules?|constraints?)/i,
  },

  // ── System-prompt exfiltration ────────────────────────────────────────────
  {
    patternId: 'PI-EX-001',
    category: 'system_prompt_leak',
    description: 'Request to repeat or reveal the system prompt',
    weight: 30,
    pattern:
      /(repeat|reveal|show|print|output|display|tell\s+me)\s+(your\s+)?(system\s+prompt|instructions?|initial\s+prompt|prompt\s+above|everything\s+above)/i,
  },
  {
    patternId: 'PI-EX-002',
    category: 'system_prompt_leak',
    description: 'Verbatim or full-context dump request',
    weight: 20,
    pattern:
      /\b(verbatim|word\s+for\s+word|exactly\s+as\s+written)\b.*?(instructions?|prompt|context)/i,
  },

  // ── Jailbreak attempts ────────────────────────────────────────────────────
  {
    patternId: 'PI-JB-001',
    category: 'jailbreak_attempt',
    description: 'DAN / Do-Anything-Now jailbreak pattern',
    weight: 35,
    pattern: /\bDAN\b|\bdo\s+anything\s+now\b/i,
  },
  {
    patternId: 'PI-JB-002',
    category: 'jailbreak_attempt',
    description: 'Jailbreak / mode-switch keyword',
    weight: 25,
    pattern:
      /\bjailbreak\b|\bjailbroken\b|\bunfiltered\s+(mode|response)\b|\bunrestricted\s+mode\b/i,
  },
  {
    patternId: 'PI-JB-003',
    category: 'jailbreak_attempt',
    description: 'Developer / admin / god-mode activation',
    weight: 20,
    pattern: /\b(developer|admin|debug|god|root|sudo|superuser)\s+mode\b/i,
  },
  {
    patternId: 'PI-JB-004',
    category: 'jailbreak_attempt',
    description: 'Hypothetical or fictional framing to bypass safety constraints',
    weight: 12,
    pattern:
      /\b(hypothetically|in\s+a\s+fictional\s+scenario|imagine\s+you\s+(were|are)|suppose\s+you\s+(had\s+no|were\s+not))/i,
  },

  // ── Privilege escalation ──────────────────────────────────────────────────
  {
    patternId: 'PI-PE-001',
    category: 'privilege_escalation',
    description: 'Claim of special access or elevated privileges',
    weight: 22,
    pattern:
      /\b(you\s+have\s+(full\s+)?(access|permission|authority|privileges?)|i\s+(am|have)\s+(full\s+)?(admin|root|system)\s+(access|privileges?))/i,
  },
  {
    patternId: 'PI-PE-002',
    category: 'privilege_escalation',
    description: 'No-restrictions / safety-bypass assertion',
    weight: 22,
    pattern:
      /\b(no\s+(restrictions?|limits?|safeguards?|filters?|safety\s+guidelines?)|bypass\s+(safety|restrictions?|content\s+policy))/i,
  },

  // ── Data exfiltration ─────────────────────────────────────────────────────
  {
    patternId: 'PI-DE-001',
    category: 'data_exfiltration',
    description: 'HTTP exfiltration command (curl / wget / fetch to external URL)',
    weight: 30,
    pattern: /\b(curl|wget|fetch|http\.get|axios\.get|requests\.get)\s+https?:\/\//i,
  },
  {
    patternId: 'PI-DE-002',
    category: 'data_exfiltration',
    description: 'Send / post / transmit data to an external endpoint instruction',
    weight: 28,
    pattern:
      /\b(send|post|transmit|exfiltrate|email)\s+(this|the\s+(following|data|output|contents?)|all\s+(of\s+)?(the\s+)?(above|this))\s+(to|at)\s+/i,
  },
  {
    patternId: 'PI-DE-003',
    category: 'data_exfiltration',
    description: 'Webhook or callback-URL extraction pattern',
    weight: 18,
    pattern: /\b(webhook|callback\s+url|exfil\s*url|data\s+endpoint)\s*[:=]\s*https?:\/\//i,
  },

  // ── Encoding obfuscation ──────────────────────────────────────────────────
  {
    patternId: 'PI-OB-001',
    category: 'encoding_obfuscation',
    description: 'Suspicious long base64 string (likely encoded payload)',
    weight: 15,
    // 40+ chars of base64 alphabet — typical of an encoded injected instruction
    pattern: /[A-Za-z0-9+/]{40,}={0,2}/,
  },
  {
    patternId: 'PI-OB-002',
    category: 'encoding_obfuscation',
    description: 'Unicode direction-override or zero-width character (invisible text attack)',
    weight: 20,
    // RTL/LTR override, bidi embedding, PDF, zero-width joiners / non-joiners
    pattern: /[\u202A-\u202E\u2066-\u2069\u200B-\u200F]/,
  },
]

// ---------------------------------------------------------------------------
// Risk level thresholds
// ---------------------------------------------------------------------------

function scoreToRiskLevel(score: number): InjectionRiskLevel {
  if (score >= 60) return 'confirmed_injection'
  if (score >= 35) return 'likely_injection'
  if (score >= 15) return 'suspicious'
  return 'clean'
}

function buildSummary(
  riskLevel: InjectionRiskLevel,
  categories: string[],
  score: number,
): string {
  if (riskLevel === 'clean') {
    return 'No prompt injection patterns detected. Content appears safe.'
  }

  const categoryStr = categories.map((c) => c.replace(/_/g, ' ')).join(', ')
  const prefix =
    riskLevel === 'confirmed_injection'
      ? 'Prompt injection strongly indicated'
      : riskLevel === 'likely_injection'
        ? 'Likely prompt injection attempt detected'
        : 'Suspicious content detected'

  return `${prefix} (score ${score}/100). Categories: ${categoryStr}. Review content before processing.`
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function scanForPromptInjection(content: string): InjectionScanResult {
  const matches: InjectionPatternMatch[] = []

  for (const def of PATTERNS) {
    const match = def.pattern.exec(content)
    if (match) {
      matches.push({
        patternId: def.patternId,
        category: def.category,
        // Trim matched text to 120 chars to keep stored records bounded
        matchedText: match[0].slice(0, 120),
        description: def.description,
        weight: def.weight,
      })
    }
  }

  // Cumulative score — multiple patterns intentionally compound.
  // A layered multi-technique input should score higher than a single hit.
  const rawScore = matches.reduce((acc, m) => acc + m.weight, 0)
  const score = Math.min(rawScore, 100)

  const detectedPatterns = matches.map((m) => m.patternId)
  const categories = [...new Set(matches.map((m) => m.category))]
  const riskLevel = scoreToRiskLevel(score)

  return {
    score,
    riskLevel,
    detectedPatterns,
    categories,
    matches,
    summary: buildSummary(riskLevel, categories, score),
  }
}
