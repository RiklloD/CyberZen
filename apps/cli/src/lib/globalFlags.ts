import type { Command } from "commander";

/**
 * Global flags available on every command. Resolved once at startup and
 * exposed to subcommands via `cmd.optsWithGlobals()`.
 *
 * Precedence (highest → lowest):
 *   CLI flag → CYBERZEN_* env → .cyberzen/project.json → global config → default
 */
export interface GlobalFlags {
	json: boolean;
	ndjson: boolean;
	tenant?: string;
	repo?: string;
	profile?: string;
	token?: string;
	apiUrl?: string;
	siteUrl?: string;
	verbose: boolean;
	color: boolean;
	timeout: number;
}

export function applyGlobalFlags(program: Command): void {
	program
		.option("--json", "Output machine-readable JSON", false)
		.option("--ndjson", "Stream array results as newline-delimited JSON", false)
		.option("--tenant <slug>", "Tenant slug (overrides env/link/config)")
		.option("--repo <owner/name>", "Repository full name (overrides env/link)")
		.option("--profile <name>", "Named credential profile")
		.option("--token <key>", "API key (czk_/msk_), overrides stored auth")
		.option("--api-url <url>", "Convex cloud URL (client)")
		.option("--site-url <url>", "Convex HTTP Actions URL (site)")
		.option("--verbose", "Verbose diagnostics to stderr", false)
		.option("--no-color", "Disable colored output")
		.option(
			"--timeout <ms>",
			"Request timeout in milliseconds",
			(v) => Number.parseInt(v, 10),
			30000,
		)
		.enablePositionalOptions();
}

/** Read the merged globals for a command action. */
export function globalsOf(cmd: Command): GlobalFlags {
	const o = cmd.optsWithGlobals();
	const resolved = {
		json: Boolean(o.json) || process.env.CYBERZEN_OUTPUT === "json",
		ndjson: Boolean(o.ndjson),
		tenant: o.tenant ?? process.env.CYBERZEN_TENANT,
		repo: o.repo ?? process.env.CYBERZEN_REPO,
		profile: o.profile ?? process.env.CYBERZEN_PROFILE,
		token: o.token ?? process.env.CYBERZEN_API_KEY,
		apiUrl: o.apiUrl ?? process.env.CYBERZEN_API_URL,
		siteUrl: o.siteUrl ?? process.env.CYBERZEN_SITE_URL,
		verbose: Boolean(o.verbose),
		color: o.color !== false && !process.env.NO_COLOR,
		timeout: typeof o.timeout === "number" ? o.timeout : 30000,
	};
	activeToken = resolved.token;
	return resolved;
}

/**
 * The token resolved from the active command's globals. Set by `globalsOf`
 * during action execution and used by the HTTP client so `--token` (and
 * `CYBERZEN_API_KEY`) reach every command without each call site forwarding
 * the flag explicitly.
 */
let activeToken: string | undefined;

export function activeTokenValue(): string | undefined {
	return activeToken;
}
