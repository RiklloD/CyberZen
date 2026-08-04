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
			repositoryFullName: repositoryName(options.repo ?? globals.repo),
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
		},
	);

	const attack = program.commands.find((c) => c.name() === "attack");
	if (attack) {
		attack
			.command("paths")
			.description("Attack path visualization for a repository or finding")
			.option("--tenant <slug>")
			.option("--repo <owner/name>")
			.option("--finding <id>", "Attack path for a specific finding")
			.action(
				async (
					options: ScopedOptions & { finding?: string },
					command: Command,
				) => {
					const globals = globalsOf(command);
					if (options.finding) {
						render(
							await api({
								path: "/api/attack-paths",
								query: { findingId: options.finding },
								timeout: globals.timeout,
							}),
							globals,
						);
						return;
					}
					const { query } = scoped(options, command);
					render(
						await api({
							path: "/api/attack-paths",
							query,
							timeout: globals.timeout,
						}),
						globals,
					);
				},
			);
		attack
			.command("blast-radius")
			.description("Blast radius snapshot for a finding")
			.requiredOption("--finding <id>", "Finding ID")
			.action(async (options: { finding: string }, command: Command) => {
				const globals = globalsOf(command);
				render(
					await api({
						path: "/api/blast-radius",
						query: { findingId: options.finding },
						timeout: globals.timeout,
					}),
					globals,
				);
			});
		attack
			.command("blast-radius-graph")
			.description("Architectural blast radius graph for a repository")
			.option("--tenant <slug>")
			.option("--repo <owner/name>")
			.action(async (options: ScopedOptions, command: Command) => {
				const { globals, query } = scoped(options, command);
				render(
					await api({
						path: "/api/blast-radius/graph",
						query,
						timeout: globals.timeout,
					}),
					globals,
				);
			});
	}

	const trust = program
		.command("trust")
		.description("Repository and dependency trust scores");
	trust
		.command("list")
		.option("--tenant <slug>")
		.option("--repo <owner/name>")
		.action(async (options: ScopedOptions, command: Command) => {
			const { globals, query } = scoped(options, command);
			render(
				await api({
					path: "/api/trust-scores",
					query,
					timeout: globals.timeout,
				}),
				globals,
			);
		});
	trust
		.command("detail")
		.description("Trust score for a specific package")
		.requiredOption("--package <name>", "Package name")
		.option("--tenant <slug>")
		.option("--repo <owner/name>")
		.action(
			async (
				options: ScopedOptions & { package: string },
				command: Command,
			) => {
				const { globals, query } = scoped(options, command);
				render(
					await api({
						path: "/api/trust-scores/detail",
						query: { ...query, package: options.package },
						timeout: globals.timeout,
					}),
					globals,
				);
			},
		);
	trust
		.command("history")
		.description("Trust score history for a specific package")
		.requiredOption("--package <name>", "Package name")
		.option("--tenant <slug>")
		.option("--repo <owner/name>")
		.action(
			async (
				options: ScopedOptions & { package: string },
				command: Command,
			) => {
				const { globals, query } = scoped(options, command);
				render(
					await api({
						path: "/api/trust-scores/history",
						query: { ...query, package: options.package },
						timeout: globals.timeout,
					}),
					globals,
				);
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
	registerReadGroup(program, "security", "Security timeline and debt", {
		timeline: "/api/security/timeline",
		debt: "/api/security/debt",
	});
	registerReadGroup(program, "crypto", "Cryptographic weakness analysis", {
		weaknesses: "/api/crypto/weaknesses",
	});
	registerReadGroup(
		program,
		"repository",
		"Repository health and lifecycle analysis",
		{
			"abandonment-scan": "/api/abandonment/scan",
			"eol-scan": "/api/eol/scan",
			"detection-rules": "/api/detection-rules",
			"health-score": "/api/repository/health-score",
			"sensitive-files": "/api/repository/sensitive-files",
			"branch-protection": "/api/repository/branch-protection",
			"commit-messages": "/api/repository/commit-messages",
			"git-integrity": "/api/repository/git-integrity",
			"high-risk-changes": "/api/repository/high-risk-changes",
			"security-config-drift": "/api/repository/security-config-drift",
			"test-coverage-gaps": "/api/repository/test-coverage-gaps",
			"database-security": "/api/repository/database-security",
			"container-hardening": "/api/repository/container-hardening",
			"cloud-security-drift": "/api/repository/cloud-security-drift",
			"build-config": "/api/repository/build-config",
			"dep-lock": "/api/repository/dep-lock",
		},
	);
	const traffic = program
		.command("traffic")
		.description("Traffic anomaly event ingestion");
	traffic
		.command("events")
		.description("Ingest traffic anomaly events (JSON array body)")
		.requiredOption("--events <json>", "JSON array of traffic events")
		.option("--tenant <slug>")
		.option("--repo <owner/name>")
		.action(
			async (
				options: { events: string; tenant?: string; repo?: string },
				command: Command,
			) => {
				const globals = globalsOf(command);
				let events: unknown;
				try {
					events = JSON.parse(options.events);
				} catch {
					throw new Error(
						"--events must be valid JSON (an array of traffic events)",
					);
				}
				if (!Array.isArray(events)) {
					throw new Error("--events must be a JSON array");
				}
				render(
					await api({
						path: "/api/traffic/events",
						method: "POST",
						query: {
							tenantSlug: requiredTenant(options.tenant ?? globals.tenant),
							repositoryFullName: repositoryName(options.repo ?? globals.repo),
						},
						body: events,
						timeout: globals.timeout,
					}),
					globals,
				);
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
				await api({
					path: "/api/webhooks",
					query: { tenantSlug: requiredTenant(globals.tenant) },
					timeout: globals.timeout,
				}),
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
					query: { tenantSlug: requiredTenant(globals.tenant) },
					timeout: globals.timeout,
				}),
				globals,
			);
		});
	webhooks
		.command("create")
		.requiredOption("--url <url>")
		.requiredOption("--events <events>")
		.option("--secret <secret>", "Optional webhook secret")
		.action(
			async (
				options: { url: string; events: string; secret?: string },
				command: Command,
			) => {
				const globals = globalsOf(command);
				render(
					await api({
						path: "/api/webhooks",
						method: "POST",
						body: {
							tenantSlug: requiredTenant(globals.tenant),
							url: options.url,
							events: options.events.split(",").map((event) => event.trim()),
							secret: options.secret,
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
					query: {
						tenantSlug: requiredTenant(globals.tenant),
						endpointId: options.id,
					},
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
		.requiredOption("--finding <id>", "Finding ID")
		.action(async (options: { finding: string }, command: Command) => {
			const globals = globalsOf(command);
			render(
				await api({
					path: "/api/sandbox/environment",
					query: { findingId: options.finding },
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
		.command("submit")
		.requiredOption("--payload <json>")
		.action(async (options: { payload: string }, command: Command) => {
			const globals = globalsOf(command);
			render(
				await api({
					path: "/api/marketplace/contributions",
					method: "POST",
					body: JSON.parse(options.payload),
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
		.command("tenant-summary")
		.requiredOption("--tenant <slug>")
		.action(async (options: { tenant: string }, command: Command) => {
			const globals = globalsOf(command);
			render(
				await api({
					path: "/api/mssp/tenant/summary",
					query: { tenantSlug: options.tenant },
					mssp: true,
					timeout: globals.timeout,
				}),
				globals,
			);
		});
	mssp
		.command("tenant-get")
		.requiredOption("--tenant <slug>")
		.action(async (options: { tenant: string }, command: Command) => {
			const globals = globalsOf(command);
			render(
				await api({
					path: "/api/mssp/tenant",
					query: { tenantSlug: options.tenant },
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

	const honeypot = program
		.command("honeypot")
		.description("Honeypot operations");
	honeypot
		.command("trigger")
		.requiredOption("--payload <json>")
		.action(async (options: { payload: string }, command: Command) => {
			const globals = globalsOf(command);
			render(
				await api({
					path: "/api/honeypot/trigger",
					method: "POST",
					body: JSON.parse(options.payload),
					timeout: globals.timeout,
				}),
				globals,
			);
		});
}
