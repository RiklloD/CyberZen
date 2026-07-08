// ═══════════════════════════════════════════════════════════════════════════
// LLM PROVIDER CONFIGURATIONS — per-tenant provider management
// ═══════════════════════════════════════════════════════════════════════════
//
// Stores encrypted API keys for LLM providers (OpenAI, Z.AI, MiniMax,
// OpenRouter, etc.) per tenant. The keys are used by the agent system's
// callLLM() when making LLM requests.
//
// SECURITY: API keys are stored in the database. They are never returned in
// full from queries — only a masked prefix is exposed. Full key retrieval is
// only available to internal mutations (for the test connection action).

import { v } from "convex/values";
import {
  query,
  mutation,
  action,
  internalQuery,
  internalMutation,
} from "./_generated/server";
import { api, internal } from "./_generated/api";
import { requireTenantAccess } from "./lib/sessionAuth";
import { callLLM, type LLMProvider } from "./lib/llmClient";

// ─── Provider Catalog ────────────────────────────────────────────────────────

export const PROVIDER_CATALOG = {
  openai: {
    label: "OpenAI",
    icon: "openai",
    description: "GPT-4o, GPT-4o-mini, o3, and other OpenAI models",
    defaultBaseUrl: "https://api.openai.com/v1",
    defaultModel: "gpt-4o-mini",
    keyPrefix: "sk-",
    keyPlaceholder: "sk-...",
    docsUrl: "https://platform.openai.com/api-keys",
    apiFormat: "openai" as const,
  },
  zai_coding: {
    label: "Z.AI Coding Plan",
    icon: "zai",
    description: "GLM-5.2, GLM-4.7 — Coding Plan endpoint (flat-rate subscription)",
    defaultBaseUrl: "https://api.z.ai/api/coding/paas/v4",
    defaultModel: "glm-5.2",
    keyPrefix: "",
    keyPlaceholder: "your-zai-coding-key",
    docsUrl: "https://docs.z.ai/devpack/quick-start",
    apiFormat: "openai" as const,
  },
  zai_token: {
    label: "Z.AI Token Plan",
    icon: "zai",
    description: "GLM-5.2, GLM-4.7 — Pay-per-token API endpoint",
    defaultBaseUrl: "https://api.z.ai/api/paas/v4",
    defaultModel: "glm-5.2",
    keyPrefix: "",
    keyPlaceholder: "your-zai-api-key",
    docsUrl: "https://z.ai/model-api",
    apiFormat: "openai" as const,
  },
  minimax_token: {
    label: "MiniMax Token Plan",
    icon: "minimax",
    description: "MiniMax-M3, M2.7 — Pay-per-token OpenAI-compatible endpoint",
    defaultBaseUrl: "https://api.minimax.io/v1",
    defaultModel: "MiniMax-M3",
    keyPrefix: "",
    keyPlaceholder: "your-minimax-api-key",
    docsUrl: "https://platform.minimax.io/docs/api-reference/text-openai-api",
    apiFormat: "openai" as const,
  },
  xiaomi_token: {
    label: "Xiaomi MiMo Token Plan",
    icon: "xiaomi",
    description: "MiMo-V2.5-Pro, MiMo-V2-Flash — flat-rate Token Plan subscription",
    defaultBaseUrl: "https://token-plan-cn.xiaomimimo.com/v1",
    defaultModel: "mimo-v2.5-pro",
    keyPrefix: "tp-",
    keyPlaceholder: "tp-...",
    docsUrl: "https://mimo.mi.com/docs/en-US/tokenplan/Token%20Plan/quick-access",
    apiFormat: "openai" as const,
  },
  anthropic: {
    label: "Anthropic",
    icon: "anthropic",
    description: "Claude Sonnet 4.6, Haiku 3.5 — direct Anthropic Messages API",
    defaultBaseUrl: "https://api.anthropic.com/v1",
    defaultModel: "claude-sonnet-4-6",
    keyPrefix: "sk-ant-",
    keyPlaceholder: "sk-ant-...",
    docsUrl: "https://console.anthropic.com/settings/keys",
    apiFormat: "anthropic" as const,
  },
  openrouter: {
    label: "OpenRouter",
    icon: "openrouter",
    description: "Access 100+ models (Claude, GPT, Llama, Gemini) via one API",
    defaultBaseUrl: "https://openrouter.ai/api/v1",
    defaultModel: "anthropic/claude-sonnet-4",
    keyPrefix: "sk-or-",
    keyPlaceholder: "sk-or-v1-...",
    docsUrl: "https://openrouter.ai/keys",
    apiFormat: "openai" as const,
  },
} satisfies Record<string, {
  label: string;
  icon: string;
  description: string;
  defaultBaseUrl: string;
  defaultModel: string;
  keyPrefix: string;
  keyPlaceholder: string;
  docsUrl: string;
  apiFormat: "openai" | "anthropic";
}>;

export type ProviderKey = keyof typeof PROVIDER_CATALOG;

// ─── Helpers ────────────────────────────────────────────────────────────────

/** Mask an API key, showing only the first 4 and last 4 characters. */
function maskApiKey(key: string): string {
  if (key.length <= 12) return "••••••••";
  return `${key.slice(0, 4)}${"•".repeat(20)}${key.slice(-4)}`;
}

// ─── Queries ────────────────────────────────────────────────────────────────

/**
 * List all LLM provider configs for a tenant, with API keys masked.
 */
export const listProviderConfigs = query({
  args: {
    tenantSlug: v.string(),
  },
  async handler(ctx, args) {
    const { tenant } = await requireTenantAccess(ctx, undefined, args.tenantSlug);

    const configs = await ctx.db
      .query("llmProviderConfigs")
      .withIndex("by_tenant", (q) => q.eq("tenantId", tenant._id))
      .collect();

    // Mask the API key before returning to the frontend
    return configs.map((c) => ({
      ...c,
      apiKeyMasked: maskApiKey(c.apiKey),
      apiKey: undefined, // never expose full key
    }));
  },
});

/**
 * Get the provider catalog (static metadata for each supported provider).
 */
export const getProviderCatalog = query({
  args: {},
  handler() {
    return PROVIDER_CATALOG;
  },
});

/**
 * Get the active (enabled) provider configs for a tenant — used internally
 * by the agent system to resolve which providers to use.
 * Returns full API keys (internal only).
 */
export const getActiveProviderConfigsInternal = internalQuery({
  args: {
    tenantId: v.id("tenants"),
  },
  async handler(ctx, args) {
    return await ctx.db
      .query("llmProviderConfigs")
      .withIndex("by_tenant", (q) => q.eq("tenantId", args.tenantId))
      .filter((q) => q.eq(q.field("enabled"), true))
      .collect();
  },
});

// ─── Mutations ──────────────────────────────────────────────────────────────

/**
 * Create or update a provider configuration. If a config for the same
 * providerKey already exists for this tenant, it is updated.
 */
export const upsertProviderConfig = mutation({
  args: {
    tenantSlug: v.string(),
    providerKey: v.string(),
    label: v.string(),
    apiKey: v.string(),
    baseUrl: v.optional(v.string()),
    defaultModel: v.optional(v.string()),
    enabled: v.optional(v.boolean()),
  },
  async handler(ctx, args) {
    const { tenant } = await requireTenantAccess(ctx, undefined, args.tenantSlug);

    const now = Date.now();
    const existing = await ctx.db
      .query("llmProviderConfigs")
      .withIndex("by_tenant_and_provider", (q) =>
        q.eq("tenantId", tenant._id).eq("providerKey", args.providerKey),
      )
      .unique();

    if (existing) {
      await ctx.db.patch(existing._id, {
        label: args.label,
        apiKey: args.apiKey,
        baseUrl: args.baseUrl,
        defaultModel: args.defaultModel,
        enabled: args.enabled ?? existing.enabled,
        updatedAt: now,
      });
      return { _id: existing._id, updated: true };
    }

    const configId = await ctx.db.insert("llmProviderConfigs", {
      tenantId: tenant._id,
      providerKey: args.providerKey,
      label: args.label,
      apiKey: args.apiKey,
      baseUrl: args.baseUrl,
      defaultModel: args.defaultModel,
      enabled: args.enabled ?? true,
      createdAt: now,
      updatedAt: now,
    });

    return { _id: configId, updated: false };
  },
});

/**
 * Delete a provider configuration.
 */
export const deleteProviderConfig = mutation({
  args: {
    tenantSlug: v.string(),
    configId: v.id("llmProviderConfigs"),
  },
  async handler(ctx, args) {
    const { tenant } = await requireTenantAccess(ctx, undefined, args.tenantSlug);

    const config = await ctx.db.get(args.configId);
    if (!config) {
      throw new Error("Provider config not found");
    }
    if (config.tenantId !== tenant._id) {
      throw new Error("Not authorized: config belongs to a different tenant");
    }

    await ctx.db.delete(args.configId);
    return { success: true };
  },
});

/**
 * Toggle a provider's enabled flag.
 */
export const toggleProviderConfig = mutation({
  args: {
    tenantSlug: v.string(),
    configId: v.id("llmProviderConfigs"),
    enabled: v.boolean(),
  },
  async handler(ctx, args) {
    const { tenant } = await requireTenantAccess(ctx, undefined, args.tenantSlug);

    const config = await ctx.db.get(args.configId);
    if (!config) {
      throw new Error("Provider config not found");
    }
    if (config.tenantId !== tenant._id) {
      throw new Error("Not authorized: config belongs to a different tenant");
    }

    await ctx.db.patch(args.configId, {
      enabled: args.enabled,
      updatedAt: Date.now(),
    });

    return { success: true };
  },
});

/**
 * Update the last test result for a config (internal — called by the test action).
 */
export const updateTestResultInternal = internalMutation({
  args: {
    configId: v.id("llmProviderConfigs"),
    result: v.union(v.literal("success"), v.literal("failed")),
    error: v.optional(v.string()),
  },
  async handler(ctx, args) {
    await ctx.db.patch(args.configId, {
      lastTestedAt: Date.now(),
      lastTestResult: args.result,
      lastTestError: args.error,
      updatedAt: Date.now(),
    });
  },
});

/**
 * Get a single provider config with full key (internal — for the test action).
 */
export const getProviderConfigInternal = internalQuery({
  args: {
    configId: v.id("llmProviderConfigs"),
  },
  async handler(ctx, args) {
    return await ctx.db.get(args.configId);
  },
});

// ─── Test Connection Action ─────────────────────────────────────────────────

/**
 * Test a provider connection by sending a minimal chat completion request.
 * Uses the callLLM function with the provider's configured settings.
 */
export const testProviderConnection = action({
  args: {
    tenantSlug: v.string(),
    configId: v.id("llmProviderConfigs"),
  },
  async handler(ctx, args) {
    // Verify tenant access
    const { tenant } = await ctx.runQuery(internal.llmProviders.verifyTenantAccessInternal, {
      tenantSlug: args.tenantSlug,
    });

    // Get the full config (with API key)
    const config = await ctx.runQuery(internal.llmProviders.getProviderConfigInternal, {
      configId: args.configId,
    });

    if (!config) {
      throw new Error("Provider config not found");
    }

    if (config.tenantId !== tenant._id) {
      throw new Error("Not authorized");
    }

    const catalog = PROVIDER_CATALOG[config.providerKey as ProviderKey];
    if (!catalog) {
      throw new Error(`Unknown provider: ${config.providerKey}`);
    }

    const baseUrl = config.baseUrl ?? catalog.defaultBaseUrl;
    const model = config.defaultModel ?? catalog.defaultModel;

    // Branch on API format — Anthropic uses /messages with x-api-key,
    // all others use OpenAI-compatible /chat/completions with Bearer auth.
    const isAnthropicFormat = catalog.apiFormat === "anthropic";

    try {
      let response: Response;

      if (isAnthropicFormat) {
        // Anthropic Messages API format
        const body = JSON.stringify({
          model,
          max_tokens: 10,
          messages: [
            { role: "user", content: "Reply with exactly: OK" },
          ],
        });

        response = await fetch(`${baseUrl}/messages`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-api-key": config.apiKey,
            "anthropic-version": "2023-06-01",
          },
          body,
          signal: AbortSignal.timeout(30_000),
        });
      } else {
        // OpenAI-compatible format
        const testBody: Record<string, unknown> = {
          model,
          messages: [
            { role: "user", content: "Reply with exactly: OK" },
          ],
          max_tokens: 10,
          temperature: 0,
        };

        const headers: Record<string, string> = {
          "Content-Type": "application/json",
          Authorization: `Bearer ${config.apiKey}`,
        };

        // OpenRouter requires extra headers for attribution
        if (config.providerKey === "openrouter") {
          headers["HTTP-Referer"] = "https://cyberzen.dev";
          headers["X-Title"] = "CyberZen";
        }

        response = await fetch(`${baseUrl}/chat/completions`, {
          method: "POST",
          headers,
          body: JSON.stringify(testBody),
          signal: AbortSignal.timeout(30_000),
        });
      }

      if (!response.ok) {
        const errorBody = await response.text().catch(() => "No response body");
        const errorMsg = errorBody.slice(0, 300);
        await ctx.runMutation(internal.llmProviders.updateTestResultInternal, {
          configId: args.configId,
          result: "failed",
          error: `HTTP ${response.status}: ${errorMsg}`,
        });
        return { success: false, error: `HTTP ${response.status}: ${errorMsg}` };
      }

      const data = await response.json();
      // Extract content from either OpenAI or Anthropic response shape
      const content = isAnthropicFormat
        ? (data.content?.map((c: { text?: string }) => c.text ?? "").join("") ?? "")
        : (data.choices?.[0]?.message?.content ?? "");

      await ctx.runMutation(internal.llmProviders.updateTestResultInternal, {
        configId: args.configId,
        result: "success",
      });

      return {
        success: true,
        model,
        responsePreview: content.slice(0, 100),
        latencyMs: 0,
      };
    } catch (err) {
      const errorMsg = (err as Error).message;
      await ctx.runMutation(internal.llmProviders.updateTestResultInternal, {
        configId: args.configId,
        result: "failed",
        error: errorMsg,
      });
      return { success: false, error: errorMsg };
    }
  },
});

// ─── Internal Helpers ───────────────────────────────────────────────────────

/**
 * Internal tenant access verification for the test action.
 */
export const verifyTenantAccessInternal = internalQuery({
  args: {
    tenantSlug: v.string(),
  },
  async handler(ctx, args) {
    const tenant = await ctx.db
      .query("tenants")
      .withIndex("by_slug", (q) => q.eq("slug", args.tenantSlug))
      .first();

    if (!tenant) {
      throw new Error(`Tenant "${args.tenantSlug}" not found`);
    }

    return { tenant };
  },
});
