import type { Command } from "commander";
import { api } from "../lib/api";
import { UsageError } from "../lib/errors";
import { globalsOf } from "../lib/globalFlags";
import { render } from "../lib/output";

export function registerFindings(program: Command): void {
	const findings = program
		.command("findings")
		.description("List and manage security findings");

	findings
		.command("list")
		.description("List findings for the authenticated tenant")
		.option("--status <status>")
		.option("--severity <severity>")
		.option(
			"--limit <n>",
			"Maximum results",
			(value) => Number.parseInt(value, 10),
			50,
		)
		.action(
			async (
				options: {
					status?: string;
					severity?: string;
					limit: number;
				},
				command: Command,
			) => {
				const globals = globalsOf(command);
				const data = await api({
					path: "/api/cli/findings",
					query: {
						status: options.status,
						severity: options.severity,
						limit: options.limit,
					},
					timeout: globals.timeout,
				});
				render(data, globals);
			},
		);

	findings
		.command("get <findingId>")
		.description("Show an enriched finding")
		.action(async (findingId: string, _options: unknown, command: Command) => {
			const globals = globalsOf(command);
			render(
				await api({
					path: "/api/cli/findings/detail",
					query: { findingId },
					timeout: globals.timeout,
				}),
				globals,
			);
		});

	findings
		.command("status <findingId> <newStatus>")
		.description("Update a finding status")
		.option("--reason <text>")
		.action(
			async (
				findingId: string,
				newStatus: string,
				options: { reason?: string },
				command: Command,
			) => {
				const globals = globalsOf(command);
				const allowed = [
					"open",
					"pr_opened",
					"merged",
					"resolved",
					"accepted_risk",
					"false_positive",
					"ignored",
					"snoozed",
				];
				if (!allowed.includes(newStatus))
					throw new UsageError(
						`Invalid status: ${newStatus}`,
						`Use one of: ${allowed.join(", ")}`,
					);
				render(
					await api({
						path: "/api/cli/findings/status",
						method: "POST",
						body: { findingId, newStatus, reason: options.reason },
						timeout: globals.timeout,
					}),
					globals,
				);
			},
		);
}
