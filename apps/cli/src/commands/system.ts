import type { Command } from "commander";
import { api } from "../lib/api";
import { completionScript } from "../lib/completions";
import { globalsOf } from "../lib/globalFlags";
import { render } from "../lib/output";

export interface CommandManifestEntry {
	command: string;
	transport: "local" | "http" | "convex-bridge";
	endpoint?: string;
	machineOutput: boolean;
}

/** Machine-readable capability inventory. Keep this synchronized with command modules. */
export const COMMAND_MANIFEST: CommandManifestEntry[] = [
	{
		command: "agents tasks",
		transport: "http",
		endpoint: "GET /api/cli/agent-tasks",
		machineOutput: true,
	},
	{
		command: "agents usage",
		transport: "http",
		endpoint: "GET /api/cli/agent-usage",
		machineOutput: true,
	},
	{
		command: "dashboard",
		transport: "http",
		endpoint: "GET /api/cli/dashboard",
		machineOutput: true,
	},
	{
		command: "memory summary",
		transport: "http",
		endpoint: "GET /api/cli/memory/summary",
		machineOutput: true,
	},
	{
		command: "billing summary",
		transport: "http",
		endpoint: "GET /api/cli/billing/summary",
		machineOutput: true,
	},
	{
		command: "integrations catalog",
		transport: "http",
		endpoint: "GET /api/cli/integrations/catalog",
		machineOutput: true,
	},
	{
		command: "integrations health",
		transport: "http",
		endpoint: "GET /api/cli/integrations/health",
		machineOutput: true,
	},
	{
		command: "jobs summary",
		transport: "http",
		endpoint: "GET /api/cli/jobs/summary",
		machineOutput: true,
	},
	{
		command: "tenants members",
		transport: "http",
		endpoint: "GET /api/cli/tenants/members",
		machineOutput: true,
	},
	{
		command: "tenants invites",
		transport: "http",
		endpoint: "GET /api/cli/tenants/invites",
		machineOutput: true,
	},
	{ command: "auth login", transport: "local", machineOutput: true },
	{
		command: "auth keys",
		transport: "http",
		endpoint: "GET /api/cli/auth/keys",
		machineOutput: true,
	},
	{
		command: "repos list",
		transport: "http",
		endpoint: "GET /api/cli/repos",
		machineOutput: true,
	},
	{
		command: "repos get",
		transport: "http",
		endpoint: "GET /api/cli/repos/detail",
		machineOutput: true,
	},
	{
		command: "scans list",
		transport: "http",
		endpoint: "GET /api/cli/scans",
		machineOutput: true,
	},
	{
		command: "scans get",
		transport: "http",
		endpoint: "GET /api/cli/scans/detail",
		machineOutput: true,
	},
	{ command: "auth whoami", transport: "local", machineOutput: true },
	{ command: "auth logout", transport: "local", machineOutput: true },
	{
		command: "system completions <shell>",
		transport: "local",
		machineOutput: true,
	},
	{ command: "link", transport: "local", machineOutput: true },
	{
		command: "findings *",
		transport: "http",
		endpoint: "GET|POST /api/findings/* and /api/cli/findings/*",
		machineOutput: true,
	},
	{
		command: "repos *",
		transport: "http",
		endpoint: "GET|POST /api/repositories/*",
		machineOutput: true,
	},
	{
		command: "sbom *",
		transport: "http",
		endpoint: "GET /api/sbom/*",
		machineOutput: true,
	},
	{
		command: "drift *",
		transport: "http",
		endpoint: "GET /api/repository/*-drift",
		machineOutput: true,
	},
	{
		command: "gates *",
		transport: "http",
		endpoint: "GET /api/security/timeline",
		machineOutput: true,
	},
	{
		command: "attack *",
		transport: "http",
		endpoint: "GET /api/attack-surface/*|/api/attack-paths|/api/blast-radius/*",
		machineOutput: true,
	},
	{
		command: "trust *",
		transport: "http",
		endpoint: "GET /api/trust-scores/*",
		machineOutput: true,
	},
	{
		command: "threat *",
		transport: "http",
		endpoint: "GET|POST /api/threat-intel/*",
		machineOutput: true,
	},
	{
		command: "compliance *",
		transport: "http",
		endpoint: "GET /api/compliance/*",
		machineOutput: true,
	},
	{
		command: "reports *",
		transport: "http",
		endpoint: "GET|POST /api/reports/*",
		machineOutput: true,
	},
	{
		command: "sla *",
		transport: "http",
		endpoint: "GET /api/sla/status",
		machineOutput: true,
	},
	{
		command: "remediation *",
		transport: "http",
		endpoint: "GET /api/remediation/*",
		machineOutput: true,
	},
	{
		command: "security *",
		transport: "http",
		endpoint: "GET /api/security/*",
		machineOutput: true,
	},
	{
		command: "crypto *",
		transport: "http",
		endpoint: "GET /api/crypto/*",
		machineOutput: true,
	},
	{
		command: "repository *",
		transport: "http",
		endpoint: "GET /api/repository/*",
		machineOutput: true,
	},
	{
		command: "traffic *",
		transport: "http",
		endpoint: "GET /api/traffic/events",
		machineOutput: true,
	},
	{
		command: "webhooks *",
		transport: "http",
		endpoint: "GET|POST|DELETE /api/webhooks*",
		machineOutput: true,
	},
	{
		command: "siem push",
		transport: "http",
		endpoint: "POST /api/siem/push",
		machineOutput: true,
	},
	{
		command: "honeypot trigger",
		transport: "http",
		endpoint: "POST /api/honeypot/trigger",
		machineOutput: true,
	},
	{
		command: "sandbox *",
		transport: "http",
		endpoint: "GET /api/sandbox/*",
		machineOutput: true,
	},
	{
		command: "marketplace *",
		transport: "http",
		endpoint: "GET|POST /api/marketplace/*",
		machineOutput: true,
	},
	{
		command: "mssp *",
		transport: "http",
		endpoint: "GET|POST /api/mssp/*",
		machineOutput: true,
	},
];

export function registerSystem(program: Command): void {
	const system = program
		.command("system")
		.description("CLI and platform utilities");
	system
		.command("schema")
		.description("Print the machine-readable CLI capability manifest")
		.action((_options: unknown, command: Command) => {
			render(COMMAND_MANIFEST, { ...globalsOf(command), json: true });
		});
	system
		.command("completions <shell>")
		.description("Print shell completion script")
		.action((shell: string) => process.stdout.write(completionScript(shell)));
	system.command("version").action((_options: unknown, command: Command) => {
		render(
			{ cli: process.env.CYBERZEN_CLI_VERSION ?? "0.1.0" },
			globalsOf(command),
		);
	});
	system
		.command("status")
		.description("Check the CyberZen platform health endpoint")
		.action(async (_options: unknown, command: Command) => {
			const globals = globalsOf(command);
			render(
				await api({
					path: "/api/observability/metrics",
					timeout: globals.timeout,
				}),
				globals,
			);
		});
}

export function registerStatus(_program: Command): void {
	// Kept as a compatibility export for callers from older CLI builds.
}
