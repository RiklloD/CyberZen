import { cronJobs } from 'convex/server'
import { internalAction } from './_generated/server'
import { internal } from './_generated/api'

// ─── Monitored wrappers ───────────────────────────────────────────────────────
// These wrap key cron jobs to record start/end in cronJobRuns for the admin
// job monitoring dashboard without modifying downstream functions.

export const monitoredSlaBreachCheck = internalAction({
  args: {},
  handler: async (ctx) => {
    const runId = await ctx.runMutation(internal.jobMonitoring.recordJobStart, {
      jobName: 'sla breach check',
    })
    try {
      await ctx.runAction(internal.slaIntel.checkAllSlaBreaches, {})
      await ctx.runMutation(internal.jobMonitoring.recordJobEnd, {
        runId,
        status: 'success',
      })
    } catch (err) {
      await ctx.runMutation(internal.jobMonitoring.recordJobEnd, {
        runId,
        status: 'failed',
        error: err instanceof Error ? err.message : String(err),
      })
    }
  },
})

export const monitoredSeverityEscalation = internalAction({
  args: {},
  handler: async (ctx) => {
    const runId = await ctx.runMutation(internal.jobMonitoring.recordJobStart, {
      jobName: 'severity escalation sweep',
    })
    try {
      await ctx.runAction(internal.escalationIntel.runAllEscalationSweeps, {})
      await ctx.runMutation(internal.jobMonitoring.recordJobEnd, {
        runId,
        status: 'success',
      })
    } catch (err) {
      await ctx.runMutation(internal.jobMonitoring.recordJobEnd, {
        runId,
        status: 'failed',
        error: err instanceof Error ? err.message : String(err),
      })
    }
  },
})

export const monitoredWebhookRetries = internalAction({
  args: {},
  handler: async (ctx) => {
    const runId = await ctx.runMutation(internal.jobMonitoring.recordJobStart, {
      jobName: 'process webhook retries',
    })
    try {
      await ctx.runAction(internal.webhooks.processWebhookRetries, {})
      await ctx.runMutation(internal.jobMonitoring.recordJobEnd, {
        runId,
        status: 'success',
      })
    } catch (err) {
      await ctx.runMutation(internal.jobMonitoring.recordJobEnd, {
        runId,
        status: 'failed',
        error: err instanceof Error ? err.message : String(err),
      })
    }
  },
})

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

// SLA enforcement — every hour (monitored for job health dashboard).
crons.interval(
  'sla breach check',
  { hours: 1 },
  internal.crons.monitoredSlaBreachCheck,
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

// Severity escalation sweep — every 4 hours (monitored for job health dashboard).
crons.interval(
  'severity escalation sweep',
  { hours: 4 },
  internal.crons.monitoredSeverityEscalation,
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

// Integration status recomputation — every 5 minutes (spec §5.5).
// Walks every tenant × catalog entry, checks env vars + last-success
// timestamps, and upserts integrationStatus rows with derived health.
crons.interval(
  'recompute integration status',
  { minutes: 5 },
  internal.integrations.recomputeIntegrationStatus,
  {},
)

// Data retention archive — daily at 05:00 UTC (after EPSS at 04:00).
// Applies enabled retention policies: archives or deletes expired data rows
// per data type and retention period.
crons.cron(
  'data retention archive',
  '0 5 * * *',
  internal.retention.runDailyArchive,
  {},
)

// Data retention enforcement — daily at 05:30 UTC (after archive at 05:00).
// Enforces per-tenant retention periods: deletes closed findings, audit logs,
// API usage records, and webhook deliveries older than configured thresholds.
crons.cron(
  'data retention enforcement',
  '30 5 * * *',
  internal.dataRetention.runDailyEnforcement,
  {},
)

// Usage metering daily aggregate — every day at 00:00 UTC (§8.3).
// Rolls up raw usage records into per-tenant per-metric daily totals.
crons.cron(
  'usage daily aggregate',
  '0 0 * * *',
  internal.usage.dailyAggregate,
  {},
)

// Neural Memory learning cycle — every 6 hours.
// Processes unprocessed episodes across all repositories, extracts patterns
// from similar episode groups, and generates predictions from active patterns.
crons.interval(
  'neural memory learning',
  { hours: 6 },
  internal.neuralMemoryScheduler.runAllLearningCycles,
  {},
)

// Neural Memory feedback evaluation — daily at 06:00 UTC.
// Evaluates prediction accuracy by checking expired predictions against
// actual events and auto-resolving confirmed/disproved predictions.
crons.cron(
  'neural memory feedback',
  '0 6 * * *',
  internal.neuralMemory.runFeedbackCycle,
  {},
)

// Neural Memory cross-project learning — weekly on Sunday at 07:00 UTC.
// Analyzes patterns across all tenant repositories to identify shared
// vulnerabilities and create tenant-level insights and predictions.
crons.cron(
  'neural memory cross-project',
  '0 7 * * 0',
  internal.neuralMemoryScheduler.runAllCrossProjectLearning,
  {},
)

// Right-to-Deletion processing — daily at 07:30 UTC (§B3).
// Processes all scheduled deletions whose grace period has elapsed.
// Anonymizes user PII, transfers finding ownership, and cascades tenant deletes.
crons.cron(
  'process deletion queue',
  '30 7 * * *',
  internal.deletionPipeline.processDeletionQueue,
  {},
)

// GDPR data request processing — daily at 02:30 UTC.
// Processes pending data access, export, and deletion requests.
// Deletion requests are only processed after the 30-day grace period.
crons.cron(
  'process gdpr data requests',
  '30 2 * * *',
  internal.dataPrivacy.processPendingRequests,
  {},
)

// Webhook retry processor — every 1 minute (monitored for job health dashboard).
crons.interval(
  'process webhook retries',
  { minutes: 1 },
  internal.crons.monitoredWebhookRetries,
  {},
)

// AlienVault OTX threat intel sync — daily at 08:00 UTC.
// Pulls recent subscribed pulses (requires OTX_API_KEY env var; skips if absent).
// Fans out across all tenants and correlates with open findings.
crons.cron(
  'sync alienvault otx',
  '0 8 * * *',
  internal.threatIntelligence.syncAlienVaultOTXScheduled,
  {},
)

// CISA KEV threat intel import — daily at 08:30 UTC.
// Imports the full KEV catalog as threat intel records and correlates
// with open findings, tagging them as actively exploited.
crons.cron(
  'sync cisa kev threat intel',
  '30 8 * * *',
  internal.threatIntelligence.syncCisaKevThreatIntel,
  {},
)

// Quarterly access review reminder — first day of each quarter at 09:00 UTC.
crons.cron(
  'quarterly access review reminder',
  '0 9 1 1,4,7,10 *',
  internal.accessReview.sendQuarterlyReminder,
  {},
)

// Integration health checks — every 15 minutes.
crons.interval(
  'integration health checks',
  { minutes: 15 },
  internal.integrationHealth.runHealthChecks,
  {},
)

export default crons
