// §B10 — PII masking utilities for Convex backend (exports, audit log responses).
// Admin callers skip masking by checking role before calling these functions.

export function maskEmail(email: string): string {
  const at = email.indexOf('@')
  if (at <= 0) return '***'
  const local = email.slice(0, at)
  const domain = email.slice(at)
  if (local.length <= 1) return `*${domain}`
  return `${local[0]}***${domain}`
}

export function maskName(name: string): string {
  // A23 — guard empty / whitespace-only input
  if (!name || !name.trim()) return '***'
  const parts = name.trim().split(/\s+/)
  const first = parts[0]
  const last = parts.length > 1 ? parts[parts.length - 1] : ''
  // A11 — GDPR data minimization: first initial only, never the full first name
  if (last) {
    return `${first[0]}***${last[0]}.`
  }
  return `${first[0]}***`
}

export function maskIp(ip: string): string {
  // IPv4 — mask last octet
  const v4Parts = ip.split('.')
  if (v4Parts.length === 4) {
    return `${v4Parts[0]}.${v4Parts[1]}.${v4Parts[2]}.*`
  }
  // A4 — IPv6: mask last 4 groups (interface identifier), not just the segment
  // after the last colon
  if (ip.includes(':')) {
    const groups = ip.split(':')
    if (groups.length > 4) {
      const masked = groups.slice(0, groups.length - 4)
      masked.push('****')
      return masked.join(':')
    }
    return '****'
  }
  return '***'
}

export function maskString(value: string, visibleChars = 3): string {
  if (value.length <= visibleChars) return '***'
  return `${value.slice(0, visibleChars)}***`
}

// A12 — Token / API-key masking

/** Mask a token or API key, exposing only the last 4 characters. */
export function maskToken(token: string): string {
  if (!token || token.length <= 4) return '****'
  return `****${token.slice(-4)}`
}

/** Scan free-form text and mask known secret patterns (sk-, ghp_, czk_, xox*, Bearer). */
export function maskAll(text: string): string {
  if (!text) return text
  return text
    .replace(/(sk-[a-zA-Z0-9]{4})[a-zA-Z0-9-]+/g, '$1****')
    .replace(/(ghp_[a-zA-Z0-9]{4})[a-zA-Z0-9]+/g, '$1****')
    .replace(/(czk_[a-zA-Z0-9]{4})[a-zA-Z0-9-]+/g, '$1****')
    .replace(/(xox[baprs]-[a-zA-Z0-9]{4})-[a-zA-Z0-9-]+/g, '$1-****')
    .replace(/(Bearer\s)[a-zA-Z0-9._-]+/gi, '$1****')
}
