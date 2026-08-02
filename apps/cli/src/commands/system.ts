import type { Command } from "commander";
import { api } from "../lib/api";
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
	{ command: "auth login", transport: "local", machineOutput: true },
	{ command: "auth whoami", transport: "local", machineOutput: true },
	{ command: "auth logout", transport: "local", machineOutput: true },
	{ command: "link", transport: "local", machineOutput: true },
	{
		command: "findings *",
		transport: "http",
		endpoint: "GET|POST /api/findings/*",
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
