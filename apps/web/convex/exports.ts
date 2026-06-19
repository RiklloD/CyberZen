import { action, internalQuery } from './_generated/server'
import { ConvexError, v } from 'convex/values'
import { api, internal } from './_generated/api'
import { requireSessionAuth } from './lib/sessionAuth' // FIX: C3 — needed for export auth
import { maskName, maskString } from './lib/piiMasker'

// ─── §6.22 — Export / Report Generation (CSV + PDF) ─────────────────────────

/**
 * Internal helper: resolve tenant by slug.
 */
export const getTenantBySlug = internalQuery({
  args: { tenantSlug: v.string() },
  returns: v.union(
    v.null(),
    v.object({ _id: v.id('tenants'), slug: v.string(), name: v.string() }),
  ),
  handler: async (ctx, { tenantSlug }) => {
    return await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()
  },
})

// FIX: C3 — internal query that verifies the caller is a member of the given tenant
export const verifyExportAccess = internalQuery({
  args: { authToken: v.string(), tenantSlug: v.string() },
  returns: v.boolean(),
  handler: async (ctx, { authToken, tenantSlug }) => {
    const { userId } = await requireSessionAuth(ctx as any, authToken)
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()
    if (!tenant) return false
    const membership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q: any) =>
        q.eq('tenantId', tenant._id).eq('userId', userId),
      )
      .unique()
    return membership !== null
  },
})

// Internal query: returns whether the caller is an owner/admin of the tenant
export const isAdminCaller = internalQuery({
  args: { authToken: v.string(), tenantSlug: v.string() },
  returns: v.boolean(),
  handler: async (ctx, { authToken, tenantSlug }) => {
    const { userId } = await requireSessionAuth(ctx as any, authToken)
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()
    if (!tenant) return false
    const membership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q: any) =>
        q.eq('tenantId', tenant._id).eq('userId', userId),
      )
      .unique()
    return membership?.role === 'owner' || membership?.role === 'admin'
  },
})

/**
 * Export findings as CSV.
 * Returns the CSV content as a string that the frontend can trigger as a download.
 */
export const exportFindingsCsv = action({
  args: {
    tenantSlug: v.string(),
    authToken: v.string(), // FIX: C3 — required for authorization
    severity: v.optional(
      v.union(
        v.literal('critical'),
        v.literal('high'),
        v.literal('medium'),
        v.literal('low'),
        v.literal('informational'),
      ),
    ),
    status: v.optional(v.string()),
  },
  returns: v.object({
    csv: v.string(),
    filename: v.string(),
    rowCount: v.number(),
  }),
  handler: async (ctx, { tenantSlug, authToken, severity, status }) => {
    // FIX: C3 — verify the caller is a member of the requested tenant
    const isMember = await ctx.runQuery(internal.exports.verifyExportAccess, { authToken, tenantSlug })
    if (!isMember) throw new ConvexError('Forbidden')

    const isAdmin = await ctx.runQuery(internal.exports.isAdminCaller, { authToken, tenantSlug })

    const tenant = await ctx.runQuery(internal.exports.getTenantBySlug, { tenantSlug })
    if (!tenant) throw new Error(`Tenant not found: ${tenantSlug}`)

    const overview = await ctx.runQuery(api.dashboard.overview, { tenantSlug })

    if (!overview) {
      return { csv: '', filename: 'findings-empty.csv', rowCount: 0 }
    }

    let findings: any[] = overview.findings ?? []
    if (severity) findings = findings.filter((f: any) => f.severity === severity)
    if (status) findings = findings.filter((f: any) => f.status === status)

    const headers = [
      'ID',
      'Title',
      'Severity',
      'Status',
      'Repository',
      'Source',
      'Confidence',
      'Business Impact',
      'Affected Files',
      'Affected Packages',
      'Created At',
      'Resolved At',
    ]

    const rows = findings.map((f: any) => {
      const repoName = f.repositoryFullName ?? f.repositoryId ?? ''
      const maskedRepo = isAdmin ? repoName : maskName(repoName)
      return [
        f._id ?? '',
        // A10 — mask title and source for non-admin members
        csvEscape(isAdmin ? (f.title ?? '') : maskString(f.title ?? '')),
        f.severity ?? '',
        f.status ?? '',
        csvEscape(maskedRepo),
        csvEscape(isAdmin ? (f.source ?? '') : maskString(f.source ?? '')),
        f.confidence ?? '',
        f.businessImpactScore ?? '',
        csvEscape(isAdmin ? (f.affectedFiles ?? []).join('; ') : maskString((f.affectedFiles ?? []).join('; '))),
        // A10 — redact affected packages entirely for non-admin members
        isAdmin ? csvEscape((f.affectedPackages ?? []).join('; ')) : '[REDACTED]',
        f.createdAt ? new Date(f.createdAt).toISOString() : '',
        f.resolvedAt ? new Date(f.resolvedAt).toISOString() : '',
      ].join(',')
    })

    const csv = [headers.join(','), ...rows].join('\n')
    const ts = new Date().toISOString().slice(0, 10)

    return {
      csv,
      filename: `cyberzen-findings-${ts}.csv`,
      rowCount: rows.length,
    }
  },
})

/**
 * Export executive report as a structured HTML report for PDF rendering.
 */
export const exportExecReportPdf = action({
  args: {
    tenantSlug: v.string(),
    authToken: v.string(), // A1 — required for authorization
  },
  returns: v.object({
    html: v.string(),
    filename: v.string(),
  }),
  handler: async (ctx, { tenantSlug, authToken }) => {
    // A1 — verify the caller is a member of the requested tenant
    const isMember = await ctx.runQuery(internal.exports.verifyExportAccess, { authToken, tenantSlug })
    if (!isMember) throw new ConvexError('Forbidden')

    const report = await ctx.runQuery(api.executiveReportIntel.getExecutiveReport, { tenantSlug })

    if (!report) {
      throw new Error('No executive report available for this tenant')
    }

    const ts = new Date().toISOString().slice(0, 10)

    const worstRows = (report.worstRepos ?? [])
      .map(
        (r: any) =>
          `<tr><td>${escapeHtml(r.fullName ?? r.repositoryId ?? '—')}</td><td>${escapeHtml(r.score ?? '—')}</td></tr>`,
      )
      .join('\n')

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CyberZen Executive Report — ${escapeHtml(tenantSlug)}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 800px; margin: 0 auto; padding: 2rem; color: #1a1a2e; }
  h1 { font-size: 1.5rem; border-bottom: 2px solid #0077b6; padding-bottom: 0.5rem; }
  h2 { font-size: 1.1rem; margin-top: 1.5rem; color: #0077b6; }
  table { width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.85rem; }
  th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #e0e0e0; }
  th { font-weight: 600; background: #f5f5f5; }
  .kpi { display: inline-block; background: #f0f7ff; border-radius: 8px; padding: 1rem; margin: 0.5rem; text-align: center; }
  .kpi .value { font-size: 1.5rem; font-weight: 700; color: #0077b6; }
  .kpi .label { font-size: 0.75rem; color: #666; }
  .footer { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #e0e0e0; font-size: 0.75rem; color: #999; }
</style>
</head>
<body>
<h1>CyberZen Executive Security Report</h1>
<p><strong>Tenant:</strong> ${escapeHtml(tenantSlug)} &nbsp;|&nbsp; <strong>Generated:</strong> ${escapeHtml(new Date(report.generatedAt).toLocaleDateString())}</p>

<h2>Key Performance Indicators</h2>
<div>
  <div class="kpi"><div class="value">${escapeHtml(report.openCritical ?? '—')}</div><div class="label">Open Critical</div></div>
  <div class="kpi"><div class="value">${escapeHtml(report.mttr ?? '—')}</div><div class="label">MTTR</div></div>
  <div class="kpi"><div class="value">${escapeHtml(((report.gateBlockRate ?? 0) * 100).toFixed(1))}%</div><div class="label">Gate Block Rate</div></div>
</div>

<h2>Domain Averages</h2>
<table>
  <tr><th>Domain</th><th>Score (0–100)</th></tr>
  <tr><td>Health</td><td>${escapeHtml(report.domainAverages?.healthAvg ?? '—')}</td></tr>
  <tr><td>Drift Posture</td><td>${escapeHtml(report.domainAverages?.driftPostureAvg ?? '—')}</td></tr>
  <tr><td>Supply Chain</td><td>${escapeHtml(report.domainAverages?.supplyChainAvg ?? '—')}</td></tr>
  <tr><td>Compliance</td><td>${escapeHtml(report.domainAverages?.complianceAvg ?? '—')}</td></tr>
</table>

${worstRows ? `<h2>Top At-Risk Repositories</h2><table><tr><th>Repository</th><th>Score</th></tr>${worstRows}</table>` : ''}

<div class="footer"><p>Generated by CyberZen Sentinel · ${escapeHtml(ts)}</p></div>
</body>
</html>`

    return { html, filename: `cyberzen-exec-report-${tenantSlug}-${ts}.html` }
  },
})

/**
 * Export compliance evidence as a structured HTML report.
 */
export const exportComplianceEvidencePdf = action({
  args: {
    tenantSlug: v.string(),
    authToken: v.string(), // A2 — required for authorization
    framework: v.optional(v.string()),
  },
  returns: v.object({
    html: v.string(),
    filename: v.string(),
  }),
  handler: async (ctx, { tenantSlug, authToken, framework }) => {
    // A2 — verify the caller is a member of the requested tenant
    const isMember = await ctx.runQuery(internal.exports.verifyExportAccess, { authToken, tenantSlug })
    if (!isMember) throw new ConvexError('Forbidden')

    const evidence: any[] = await ctx.runQuery(
      api.complianceEvidenceIntel.getAllFrameworkEvidence,
      { tenantSlug },
    )

    if (!evidence || evidence.length === 0) {
      throw new Error('No compliance evidence available for this tenant')
    }

    const ts = new Date().toISOString().slice(0, 10)
    const items = framework ? evidence.filter((e: any) => e.framework === framework) : evidence

    const rows = items
      .map(
        (e: any) =>
          `<tr><td>${escapeHtml(e.framework ?? '—')}</td><td>${escapeHtml(e.controlId ?? '—')}</td><td>${escapeHtml(e.status ?? '—')}</td><td>${escapeHtml(e.collectedAt ? new Date(e.collectedAt).toLocaleDateString() : '—')}</td></tr>`,
      )
      .join('\n')

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CyberZen Compliance Evidence — ${escapeHtml(tenantSlug)}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 800px; margin: 0 auto; padding: 2rem; color: #1a1a2e; }
  h1 { font-size: 1.5rem; border-bottom: 2px solid #0077b6; padding-bottom: 0.5rem; }
  table { width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.85rem; }
  th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #e0e0e0; }
  th { font-weight: 600; background: #f5f5f5; }
  .footer { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #e0e0e0; font-size: 0.75rem; color: #999; }
</style>
</head>
<body>
<h1>CyberZen Compliance Evidence Report</h1>
<p><strong>Tenant:</strong> ${escapeHtml(tenantSlug)} &nbsp;|&nbsp; <strong>Generated:</strong> ${escapeHtml(ts)}${framework ? ` &nbsp;|&nbsp; <strong>Framework:</strong> ${escapeHtml(framework)}` : ''}</p>
<table><tr><th>Framework</th><th>Control ID</th><th>Status</th><th>Collected</th></tr>${rows}</table>
<div class="footer"><p>Generated by CyberZen Sentinel · ${escapeHtml(ts)}</p></div>
</body>
</html>`

    return { html, filename: `cyberzen-compliance-evidence-${tenantSlug}-${ts}.html` }
  },
})

// ─── Helpers ─────────────────────────────────────────────────────────────────

// A3 — HTML-escape untrusted values before interpolating into report templates
function escapeHtml(text: unknown): string {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
}

function csvEscape(val: string): string {
  // A9 — CSV formula injection: prepend single-quote to fields that could be
  // interpreted as formulas by spreadsheet apps (=, +, -, @, tab, CR)
  let safe = val
  const first = safe[0]
  if (first === '=' || first === '+' || first === '-' || first === '@' || first === '\t' || safe.charCodeAt(0) === 13) {
    safe = `'${safe}`
  }
  if (safe.includes(',') || safe.includes('"') || safe.includes('\n')) {
    return `"${safe.replace(/"/g, '""')}"`
  }
  return safe
}
