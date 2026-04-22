import { cronJobs } from 'convex/server'
import { internal } from './_generated/api'

const crons = cronJobs()

// GitHub Advisory + OSV sync — every 6 hours
crons.interval(
  'sync recent advisories',
  { hours: 6 },
  internal.breachIngest.syncRecentAdvisoriesOnSchedule,
  {
    maxRepositories: 20,
    lookbackHours: 72,
    githubLimit: 100,
    osvLimit: 100,
  },
)

// Weekly Slack security posture digest — every Monday at 09:00 UTC
crons.cron(
  'weekly slack posture digest',
  '0 9 * * 1',
  internal.slack.sendWeeklyPostureDigest,
  { tenantSlug: 'atlas-fintech' },
)

// Weekly Microsoft Teams security posture digest — every Monday at 09:15 UTC
// Staggered 15 minutes after Slack to avoid simultaneous external calls.
crons.cron(
  'weekly teams posture digest',
  '15 9 * * 1',
  internal.teams.sendWeeklyTeamsDigest,
  { tenantSlug: 'atlas-fintech' },
)

// Datadog custom metrics push — every 15 minutes.
// Silently skips when DD_API_KEY is not configured.
crons.interval(
  'push datadog metrics',
  { minutes: 15 },
  internal.datadog.pushAllTenantMetrics,
  {},
)

// CISA Known Exploited Vulnerabilities sync — daily at 03:00 UTC.
// Fetches the public CISA KEV catalog, cross-references open breach
// disclosures, and patches exploitAvailable=true on matched entries.
crons.cron(
  'sync cisa kev catalog',
  '0 3 * * *',
  internal.tier3Intel.syncCisaKevCatalog,
  {},
)

// EPSS score sync — daily at 04:00 UTC (after CISA KEV at 03:00).
// Queries FIRST.org for EPSS exploitation-probability scores for every CVE
// ID present in the last 500 breach disclosures.  Patches epssScore and
// epssPercentile directly on matched disclosure rows so downstream queries
// (remediation queue, escalation engine) can incorporate probability data.
crons.cron(
  'sync epss scores',
  '0 4 * * *',
  internal.epssIntel.syncEpssScores,
  {},
)

// SLA enforcement — every hour.
// Scans all active findings across all repositories, inserts breach events for
// findings that have exceeded their per-severity SLA window, and schedules
// Slack notifications for first-time breaches.
crons.interval(
  'sla breach check',
  { hours: 1 },
  internal.slaIntel.checkAllSlaBreaches,
  {},
)

// Risk acceptance expiry — every hour.
// Scans all active risk acceptances, transitions expired ones to 'expired',
// re-opens the associated findings, and schedules Slack notifications.
crons.interval(
  'risk acceptance expiry check',
  { hours: 1 },
  internal.riskAcceptanceIntel.checkExpiredAcceptances,
  {},
)

// Severity escalation sweep — every 4 hours.
// Re-evaluates all active open/pr_opened findings across every repository.
// Findings whose context has improved (new exploit available, blast radius
// grown, cross-repo spread confirmed, SLA breached) are automatically
// upgraded one severity level per run.
crons.interval(
  'severity escalation sweep',
  { hours: 4 },
  internal.escalationIntel.runAllEscalationSweeps,
  {},
)

// Autonomous Remediation Dispatch — daily at 02:00 UTC.
// Selects eligible P0 findings from the priority queue and schedules
// `proposeFix` for each one.  The dispatch is opt-in (enabled=false by
// default) and capped by maxConcurrentPrs to prevent CI flooding.
crons.cron(
  'auto remediation dispatch',
  '0 2 * * *',
  internal.autoRemediationIntel.runAllAutoRemediationDispatches,
  {},
)

// Vendor risk sweep — daily at 01:00 UTC.
// Fans out sweepVendorRisk across every active tenant.  Each per-tenant
// sweep runs as an independent scheduled action — isolated failures and
// retries don't block other tenants.
crons.cron(
  'vendor risk sweep',
  '0 1 * * *',
  internal.vendorTrust.sweepAllTenantsVendorRisk,
  {},
)

// Gamification sprint leaderboard refresh — every Monday at 08:00 UTC.
// Runs before the Slack and Teams posture digests so the leaderboard is
// fresh when digests fire at 09:00 / 09:15.
crons.cron(
  'gamification sprint refresh',
  '0 8 * * 1',
  internal.gamificationIntel.refreshAllTenantsGamification,
  {},
)

export default crons
