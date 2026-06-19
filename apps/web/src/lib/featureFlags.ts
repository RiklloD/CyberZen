import { useQuery } from "convex/react";
import { api } from "./convex";
import { useTenantSlug } from "./workspace";

// ─── §8.2 — Feature Flags React hook ──────────────────────────────────────

/**
 * Returns true when the current tenant's plan includes the given feature flag.
 * Returns undefined while the query is loading.
 */
export function useFeatureFlag(slug: string): boolean | undefined {
	const tenantSlug = useTenantSlug();
	const enabled = useQuery(api.featureFlags.isEnabledForTenant, {
		tenantSlug,
		slug });
	return enabled;
}

/**
 * Returns the list of enabled feature flags for the current tenant.
 * Returns undefined while loading.
 */
export function useEnabledFeatureFlags(): string[] | undefined {
	const tenantSlug = useTenantSlug();
	return useQuery(api.featureFlags.listEnabledForTenant, { tenantSlug });
}
