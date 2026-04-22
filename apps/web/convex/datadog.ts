"use node";
/**
 * Datadog Custom Metrics Integration — spec §4.6.5
 *
 * Pushes Sentinel platform metrics to Datadog as custom gauges.
 * Called on a 15-minute cron from crons.ts.
 *
 * Metrics pushed:
 *   sentinel.attack_surface.score           gauge, tagged tenant + repository
 *   sentinel.findings.open                  gauge, tagged tenant + repository + severity
 *   sentinel.gate.blocked_total             gauge, tagged tenant + repository
 *   sentinel.trust_score.average            gauge, tagged tenant + repository
 *   sentinel.red_agent.win_rate             gauge, tagged tenant + repository
 *   sentinel.provenance.score               gauge, tagged tenant + repository
 *   sentinel.compliance.evidence_score      gauge, tagged tenant + repository + framework
 *
 * Configuration:
 *   npx convex env set DD_API_KEY <your-api-key>
 *   npx convex env set DD_SITE datadoghq.com          (default; use datadoghq.eu for EU)
 *   npx convex env set DD_ENV production               (optional environment tag)
 *
 * Get your API key: Datadog → Organization Settings → API Keys → New Key
 */

import { v } from "convex/values";
import { internalAction } from "./_generated/server";
import { internal, api } from "./_generated/api";
import { buildDatadogPayload } from "./lib/datadogPayload";

// ── Datadog API helper ────────────────────────────────────────────────────────

const DD_METRICS_PATH = "/api/v2/series";

async function postDatadogMetrics(
  apiKey: string,
  site: string,
  payload: object,
): Promise<{ ok: boolean; status: number; message?: string }> {
  const url = `https://api.${site}${DD_METRICS_PATH}`;

  const resp = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "DD-API-KEY": apiKey,
    },
    body: JSON.stringify(payload),
  });

  const text = await resp.text().catch(() => "");
  if (!resp.ok) {
    console.error(`[datadog] push failed: ${resp.status} — ${text.slice(0, 200)}`);
    return { ok: false, status: resp.status, message: text.slice(0, 200) };
  }

  return { ok: true, status: resp.status };
}

// ── pushMetricsToDatadog — single tenant (or specific repository) ─────────────

/**
 * Push Sentinel metrics for a specific tenant (and optionally one repository)
 * to Datadog. Called from the cron or manually via the CLI.
 */
export const pushMetricsToDatadog = internalAction({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.optional(v.string()),
  },
  handler: async (ctx, args): Promise<{ pushed: boolean; reason?: string; seriesCount?: number }> => {
    const apiKey = process.env.DD_API_KEY;
    if (!apiKey) {
      console.log("[datadog] DD_API_KEY not set — skipping metrics push");
      return { pushed: false, reason: "no_api_key" };
    }

    const site = process.env.DD_SITE ?? "datadoghq.com";
    const env = process.env.DD_ENV ?? "production";

    const metricsArray = await ctx.runQuery(api.observabilityIntel.getMetricsSnapshot, {
      tenantSlug: args.tenantSlug,
      repositoryFullName: args.repositoryFullName,
    });

    if (metricsArray.length === 0) {
      return { pushed: false, reason: "no_repositories_found" };
    }

    // Build a single batched payload for all repositories
    const allSeries = metricsArray.flatMap((m) => {
      const payload = buildDatadogPayload(m);
      // Inject the environment tag into every series
      return payload.series.map((s) => ({
        ...s,
        tags: [...s.tags, `env:${env}`],
      }));
    });

    if (allSeries.length === 0) {
      return { pushed: false, reason: "no_series_to_push" };
    }

    const result = await postDatadogMetrics(apiKey, site, { series: allSeries });
    console.log(`[datadog] pushed ${allSeries.length} series for tenant ${args.tenantSlug}: ${result.status}`);

    return {
      pushed: result.ok,
      seriesCount: allSeries.length,
      reason: result.ok ? undefined : result.message,
    };
  },
});

// ── pushAllTenantMetrics — iterates every active tenant ───────────────────────

/**
 * Push metrics for ALL active tenants. Intended for use by the 15-minute cron.
 * Skips gracefully when DD_API_KEY is not configured.
 */
export const pushAllTenantMetrics = internalAction({
  args: {},
  handler: async (ctx): Promise<{ pushed: boolean; reason?: string; tenantCount?: number }> => {
    const apiKey = process.env.DD_API_KEY;
    if (!apiKey) {
      // Silently skip — no API key means Datadog is not configured
      return { pushed: false, reason: "no_api_key" };
    }

    const tenantSlugs = await ctx.runQuery(
      internal.observabilityIntel.getActiveTenantSlugs,
      {},
    );

    if (tenantSlugs.length === 0) {
      return { pushed: false, reason: "no_active_tenants" };
    }

    // Push metrics for each tenant sequentially (avoids API rate-limit issues)
    let pushCount = 0
    for (const slug of tenantSlugs) {
      const result = await ctx.runAction(internal.datadog.pushMetricsToDatadog, {
        tenantSlug: slug,
      });
      if (result.pushed) pushCount++
    }

    return { pushed: pushCount > 0, tenantCount: pushCount };
  },
});
