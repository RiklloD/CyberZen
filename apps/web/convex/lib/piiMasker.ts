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
  const parts = name.trim().split(/\s+/)
  if (parts.length === 0) return '***'
  const first = parts[0]
  const last = parts.length > 1 ? ` ${parts[parts.length - 1][0]}.` : ''
  return `${first}${last}`
}

export function maskIp(ip: string): string {
  const parts = ip.split('.')
  if (parts.length === 4) {
    return `${parts[0]}.${parts[1]}.${parts[2]}.*`
  }
  const colonIdx = ip.lastIndexOf(':')
  if (colonIdx !== -1) return `${ip.slice(0, colonIdx)}:***`
  return '***'
}

export function maskString(value: string, visibleChars = 3): string {
  if (value.length <= visibleChars) return '***'
  return `${value.slice(0, visibleChars)}***`
}
