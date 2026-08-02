import type { Command } from "commander";
import { api } from "../lib/api";
import { globalsOf } from "../lib/globalFlags";
import { render } from "../lib/output";
import { repositoryName, requiredTenant } from "../lib/tenant";

interface ScopedOptions {
	tenant?: string;
	repo?: string;
}

function scoped(options: ScopedOptions, command: Command) {
	const globals = globalsOf(command);
	return {
		globals,
		query: {
			tenantSlug: requiredTenant(options.tenant ?? globals.tenant),
			repositoryFullName: repositoryName(options.repo),
		},
	};
}

function registerReadGroup(
	program: Command,
	name: string,
	description: string,
	routes: Record<string, string>,
): void {
	const group = program.command(name).description(description);
	for (const [subcommand, path] of Object.entries(routes)) {
		group
			.command(subcommand)
			.option("--tenant <slug>")
			.option("--repo <owner/name>")
			.action(async (options: ScopedOptions, command: Command) => {
				const { globals, query } = scoped(options, command);
				render(await api({ path, query, timeout: globals.timeout }), globals);
			});
	}
}

export function registerOperations(program: Command): void {
	registerReadGroup(program, "gates", "CI/CD gate enforcement and decisions", {
		list: "/api/security/timeline",
		status: "/api/sla/status",
	});

	registerReadGroup(
		program,
		"attack",
		"Attack surface, attack paths, and blast radius",
		{
			score: "/api/attack-surface/score",
			history: "/api/attack-surface/score/history",
			components: "/api/attack-surface/components",
			paths: "/api/attack-paths",
			"blast-radius": "/api/blast-radius",
			"blast-radius-graph": "/api/blast-radius/graph",
		},
	);

	registerReadGroup(
		program,
		"trust",
		"Repository and dependency trust scores",
		{
			list: "/api/trust-scores",
			detail: "/api/trust-scores/detail",
			history: "/api/trust-scores/history",
		},
	);

	const threat = program
		.command("threat")
		.description("Threat intelligence feeds");
	threat
		.command("kev")
		.description("List CISA Known Exploited Vulnerabilities")
		.option("--limit <n>")
		.action(async (options: { limit?: string }, command: Command) => {
			const globals = globalsOf(command);
			render(
				await api({
					path: "/api/threat-intel/cisa-kev",
					query: { limit: options.limit },
					timeout: globals.timeout,
				}),
				globals,
			);
		});
	threat
		.command("kev-sync")
		.description("Synchronize the CISA KEV feed")
		.action(async (_options: unknown, command: Command) => {
			const globals = globalsOf(command);
			render(
				await api({
					path: "/api/threat-intel/cisa-kev/sync",
					method: "POST",
					timeout: globals.timeout,
				}),
				globals,
			);
		});
	threat
		.command("epss")
		.description("List EPSS scores")
		.option("--cve <id>")
		.action(async (options: { cve?: string }, command: Command) => {
			const globals = globalsOf(command);
			render(
				await api({
					path: "/api/threat-intel/epss",
					query: { cve: options.cve },
					timeout: globals.timeout,
				}),
				globals,
			);
		});
	threat
		.command("epss-sync")
		.description("Synchronize EPSS scores")
		.action(async (_options: unknown, command: Command) => {
			const globals = globalsOf(command);
			render(
				await api({
					path: "/api/threat-intel/epss/sync",
					method: "POST",
					timeout: globals.timeout,
				}),
				globals,
			);
		});

	registerReadGroup(
		program,
		"compliance",
		"Compliance evidence and remediation",
		{
			evidence: "/api/compliance/evidence",
			attestation: "/api/compliance/attestation",
			"remediation-plan": "/api/compliance/remediation-plan",
		},
	);

	registerReadGroup(
		program,
		"reports",
		"Security, compliance, and adversarial reports",
		{
			"security-posture": "/api/reports/security-posture",
			compliance: "/api/reports/compliance",
			adversarial: "/api/reports/adversarial",
			executive: "/api/tenant/executive-report",
		},
	);

	const reports = program.commands.find(
		(command) => command.name() === "reports",
	);
	if (!reports) throw new Error("reports command was not registered");
	reports
		.command("generate")
		.requiredOption("--type <type>")
		.option("--tenant <slug>")
		.option("--repo <owner/name>")
		.action(
			async (options: { type: string } & ScopedOptions, command: Command) => {
				const { globals, query } = scoped(options, command);
				render(
					await api({
						path: "/api/reports/generate",
						method: "POST",
						body: { ...query, reportType: options.type },
						timeout: globals.timeout,
					}),
					globals,
				);
			},
		);
	reports
		.command("download")
		.requiredOption("--report-id <id>")
		.action(async (options: { reportId: string }, command: Command) => {
			const globals = globalsOf(command);
			render(
				await api({
					path: "/api/reports/download",
					query: { reportId: options.reportId },
					timeout: globals.timeout,
				}),
				globals,
			);
		});

	registerReadGroup(program, "sla", "Service-level agreement status", {
		status: "/api/sla/status",
	});
	registerReadGroup(
		program,
		"remediation",
		"Remediation queue and automatic remediation runs",
		{
			queue: "/api/remediation/queue",
			"auto-runs": "/api/remediation/auto-runs",
		},
	);

	const webhooks = program
		.command("webhooks")
		.description("Outgoing webhook endpoints and deliveries");
	webhooks
		.command("list")
		.action(async (_options: unknown, command: Command) => {
			const globals = globalsOf(command);
			render(
				await api({ path: "/api/webhooks", timeout: globals.timeout }),
				globals,
			);
		});
	webhooks
		.command("deliveries")
		.action(async (_options: unknown, command: Command) => {
			const globals = globalsOf(command);
			render(
				await api({
					path: "/api/webhooks/deliveries",
					timeout: globals.timeout,
				}),
				globals,
			);
		});
	webhooks
		.command("create")
		.requiredOption("--url <url>")
		.requiredOption("--events <events>")
		.action(
			async (options: { url: string; events: string }, command: Command) => {
				const globals = globalsOf(command);
				render(
					await api({
						path: "/api/webhooks",
						method: "POST",
						body: {
							url: options.url,
							events: options.events.split(",").map((event) => event.trim()),
						},
						timeout: globals.timeout,
					}),
					globals,
				);
			},
		);
	webhooks
		.command("delete")
		.requiredOption("--id <id>")
		.action(async (options: { id: string }, command: Command) => {
			const globals = globalsOf(command);
			render(
				await api({
					path: "/api/webhooks",
					method: "DELETE",
					body: { id: options.id },
					timeout: globals.timeout,
				}),
				globals,
			);
		});

	const siem = program.command("siem").description("SIEM integration");
	siem
		.command("push")
		.requiredOption("--event <json>")
		.action(async (options: { event: string }, command: Command) => {
			const globals = globalsOf(command);
			render(
				await api({
					path: "/api/siem/push",
					method: "POST",
					body: JSON.parse(options.event),
					timeout: globals.timeout,
				}),
				globals,
			);
		});

	const sandbox = program
		.command("sandbox")
		.description("Sandbox validation environments");
	sandbox
		.command("environment")
		.option("--tenant <slug>")
		.option("--repo <owner/name>")
		.action(async (options: ScopedOptions, command: Command) => {
			const { globals, query } = scoped(options, command);
			render(
				await api({
					path: "/api/sandbox/environment",
					query,
					timeout: globals.timeout,
				}),
				globals,
			);
		});
	sandbox
		.command("summary")
		.option("--tenant <slug>")
		.option("--repo <owner/name>")
		.action(async (options: ScopedOptions, command: Command) => {
			const { globals, query } = scoped(options, command);
			render(
				await api({
					path: "/api/sandbox/summary",
					query,
					timeout: globals.timeout,
				}),
				globals,
			);
		});

	const marketplace = program
		.command("marketplace")
		.description("Community marketplace");
	marketplace
		.command("contributions")
		.action(async (_options: unknown, command: Command) => {
			const globals = globalsOf(command);
			render(
				await api({
					path: "/api/marketplace/contributions",
					timeout: globals.timeout,
				}),
				globals,
			);
		});
	marketplace
		.command("stats")
		.action(async (_options: unknown, command: Command) => {
			const globals = globalsOf(command);
			render(
				await api({ path: "/api/marketplace/stats", timeout: globals.timeout }),
				globals,
			);
		});
	marketplace
		.command("vote")
		.requiredOption("--id <id>")
		.requiredOption("--value <value>")
		.action(
			async (options: { id: string; value: string }, command: Command) => {
				const globals = globalsOf(command);
				render(
					await api({
						path: "/api/marketplace/contributions/vote",
						method: "POST",
						body: { contributionId: options.id, value: options.value },
						timeout: globals.timeout,
					}),
					globals,
				);
			},
		);

	const mssp = program
		.command("mssp")
		.description("Managed security service provider operations");
	mssp
		.command("tenants")
		.action(async (_options: unknown, command: Command) => {
			const globals = globalsOf(command);
			render(
				await api({
					path: "/api/mssp/tenants",
					mssp: true,
					timeout: globals.timeout,
				}),
				globals,
			);
		});
	mssp
		.command("dashboard")
		.action(async (_options: unknown, command: Command) => {
			const globals = globalsOf(command);
			render(
				await api({
					path: "/api/mssp/dashboard",
					mssp: true,
					timeout: globals.timeout,
				}),
				globals,
			);
		});
}
