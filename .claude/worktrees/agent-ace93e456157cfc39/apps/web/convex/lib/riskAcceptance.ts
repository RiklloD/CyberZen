// Risk Acceptance Lifecycle — pure library with no Convex imports.
//
// Models the governed risk-acceptance workflow for findings:
//   - Temporary acceptances have a bounded window (durationDays) and
//     auto-expire back to open when the deadline passes.
//   - Permanent acceptances require an explicit revocation.
//   - The expiry check runs hourly via cron; only acceptances with status
//     'active' and a past expiresAt are processed.
//
// Status transitions:
//   (created)  → active
//   active     → expired   (automatic, hourly cron)
//   active     → revoked   (explicit operator action)

export type AcceptanceLevel = 'temporary' | 'permanent'
export type AcceptanceStatus = 'active' | 'expired' | 'revoked'

export type AcceptanceSummary = {
  /** Total currently-active acceptances (not yet expired or revoked). */
  totalActive: number
  /** Active temporary acceptances expiring within 7 days. */
  expiringSoon: number
  /** Active acceptances whose expiresAt has already passed (awaiting cron). */
  alreadyExpired: number
  /** Active acceptances with no expiry date. */
  permanent: number
  /** Active acceptances with a bounded window. */
  temporary: number
}

const EXPIRING_SOON_WINDOW_MS = 7 * 24 * 3_600_000 // 7 days

// Returns true when a temporary acceptance has passed its deadline.
export function isExpired(
  record: { expiresAt?: number | null },
  nowMs: number,
): boolean {
  if (record.expiresAt == null) return false
  return nowMs >= record.expiresAt
}

// Returns true when a temporary acceptance expires within the given window
// (default 7 days) but has not yet expired.
export function isExpiringSoon(
  record: { expiresAt?: number | null },
  nowMs: number,
  windowMs = EXPIRING_SOON_WINDOW_MS,
): boolean {
  if (record.expiresAt == null) return false
  const remaining = record.expiresAt - nowMs
  return remaining > 0 && remaining <= windowMs
}

// Returns a human-readable expiry description.
export function formatExpiryText(
  expiresAt: number | null | undefined,
  nowMs: number,
): string {
  if (expiresAt == null) return 'permanent'
  if (nowMs >= expiresAt) return 'expired'
  const remaining = expiresAt - nowMs
  const days = Math.floor(remaining / (24 * 3_600_000))
  if (days === 0) return 'expires today'
  if (days === 1) return 'expires tomorrow'
  return `expires in ${days}d`
}

// Compute expiry timestamp for a temporary acceptance.
export function computeExpiresAt(
  createdAt: number,
  durationDays: number,
): number {
  return createdAt + durationDays * 24 * 3_600_000
}

// Aggregate a list of acceptance records into a summary.
export function computeAcceptanceSummary(
  records: ReadonlyArray<{
    level: AcceptanceLevel
    expiresAt?: number | null
    status: AcceptanceStatus
  }>,
  nowMs: number,
): AcceptanceSummary {
  let totalActive = 0
  let expiringSoon = 0
  let alreadyExpired = 0
  let permanent = 0
  let temporary = 0

  for (const r of records) {
    if (r.status !== 'active') continue
    totalActive++

    if (r.level === 'permanent') {
      permanent++
    } else {
      temporary++
      if (isExpired(r, nowMs)) alreadyExpired++
      else if (isExpiringSoon(r, nowMs)) expiringSoon++
    }
  }

  return { totalActive, expiringSoon, alreadyExpired, permanent, temporary }
}
