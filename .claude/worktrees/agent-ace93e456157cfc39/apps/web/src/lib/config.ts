import { env } from "../env";

/**
 * Runtime tenant slug.
 *
 * In a multi-tenant deployment this is resolved from the authenticated
 * session (e.g. Clerk organisation slug, JWT claim, or URL subdomain).
 * For single-tenant deployments configure via VITE_TENANT_SLUG env var.
 */
export const TENANT_SLUG: string = env.VITE_TENANT_SLUG;
