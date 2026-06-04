/**
 * GitHub API client — supports both GitHub Cloud and GitHub Enterprise Server.
 *
 * GitHub Enterprise Server (GHES) uses the same REST API but with a custom
 * base URL: https://github.acme.com/api/v3 instead of https://api.github.com
 *
 * Configuration:
 *   Cloud (default):
 *     GITHUB_TOKEN  — personal access token or fine-grained token
 *
 *   Enterprise Server:
 *     GITHUB_TOKEN  — same, but scoped to the GHES instance
 *     GHES_BASE_URL — e.g. https://github.acme.com
 *     GHES_API_URL  — optional override for API URL (defaults to {GHES_BASE_URL}/api/v3)
 *
 * Usage:
 *   const client = githubApiClient()
 *   const resp = await client.get('/advisories?...')
 */

// ── URL resolution ────────────────────────────────────────────────────────────

export type GitHubClientConfig = {
  baseUrl: string       // e.g. https://api.github.com or https://github.acme.com/api/v3
  token: string | undefined
  isEnterprise: boolean
}

export function resolveGitHubConfig(): GitHubClientConfig {
  const token =
    process.env.GITHUB_TOKEN ??
    process.env.GITHUB_SECURITY_ADVISORY_TOKEN ??
    process.env.GH_TOKEN

  const ghesBase = process.env.GHES_BASE_URL?.replace(/\/$/, '')
  const ghesApi = process.env.GHES_API_URL?.replace(/\/$/, '')

  if (ghesBase) {
    const apiUrl = ghesApi ?? `${ghesBase}/api/v3`
    return { baseUrl: apiUrl, token, isEnterprise: true }
  }

  return {
    baseUrl: 'https://api.github.com',
    token,
    isEnterprise: false,
  }
}

// ── HTTP client ───────────────────────────────────────────────────────────────

export type GitHubRequestOptions = {
  method?: 'GET' | 'POST' | 'PATCH' | 'DELETE'
  body?: unknown
  accept?: string
}

export async function githubRequest<T>(
  path: string,
  opts: GitHubRequestOptions = {},
  config?: GitHubClientConfig,
): Promise<T> {
  const cfg = config ?? resolveGitHubConfig()
  const url = path.startsWith('http') ? path : `${cfg.baseUrl}${path}`

  const headers: Record<string, string> = {
    Accept: opts.accept ?? 'application/vnd.github+json',
    'User-Agent': 'Sentinel-Security-Agent/1.0',
    'X-GitHub-Api-Version': '2022-11-28',
  }

  if (cfg.token) {
    headers.Authorization = `Bearer ${cfg.token}`
  }

  const resp = await fetch(url, {
    method: opts.method ?? 'GET',
    headers,
    body: opts.body != null ? JSON.stringify(opts.body) : undefined,
  })

  if (!resp.ok) {
    const body = await resp.text().catch(() => '')
    throw new Error(
      `GitHub API error ${resp.status} at ${url}: ${body.slice(0, 300)}`,
    )
  }

  return resp.json() as Promise<T>
}

export function githubHeaders(config?: GitHubClientConfig): Record<string, string> {
  const cfg = config ?? resolveGitHubConfig()
  const h: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'Sentinel-Security-Agent/1.0',
    'X-GitHub-Api-Version': '2022-11-28',
  }
  if (cfg.token) h.Authorization = `Bearer ${cfg.token}`
  return h
}

// ── GHES-specific: upload advisory to private vulnerability DB ────────────────
//
// GitHub Enterprise Server 3.7+ supports private vulnerability reporting.
// This helper creates a security advisory on a GHES instance.

export async function createGhesAdvisory(
  repoFullName: string,
  opts: {
    summary: string
    description: string
    severity: 'critical' | 'high' | 'medium' | 'low'
    cveId?: string
  },
  config?: GitHubClientConfig,
): Promise<{ ghsaId: string; url: string } | null> {
  const cfg = config ?? resolveGitHubConfig()
  if (!cfg.isEnterprise) return null // Only applicable for GHES

  try {
    const result = await githubRequest<{ ghsa_id: string; html_url: string }>(
      `/repos/${repoFullName}/security-advisories`,
      {
        method: 'POST',
        body: {
          summary: opts.summary.slice(0, 256),
          description: opts.description.slice(0, 65536),
          severity: opts.severity,
          cve_id: opts.cveId,
        },
      },
      cfg,
    )
    return { ghsaId: result.ghsa_id, url: result.html_url }
  } catch {
    return null
  }
}
