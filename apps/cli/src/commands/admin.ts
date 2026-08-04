import type { Command } from "commander";
import { cliApi } from "../lib/api";
import { globalsOf } from "../lib/globalFlags";
import { render } from "../lib/output";

export function registerAdmin(program: Command): void {
	const admin = program
		.command("admin")
		.description("Tenant administration: audit log, feature flags");

	admin
		.command("audit-log")
		.description("List the tenant audit log")
		.option("--action <action>", "Filter by action name")
		.option(
			"--limit <n>",
			"Maximum results",
			(value) => Number.parseInt(value, 10),
			100,
		)
		.action(
			async (options: { action?: string; limit: number }, command: Command) => {
				const globals = globalsOf(command);
				render(
					await cliApi({
						path: "admin/audit-log",
						query: { action: options.action, limit: options.limit },
						timeout: globals.timeout,
					}),
					globals,
				);
			},
		);

	admin
		.command("feature-flags")
		.description("List feature flags enabled for the tenant's plan")
		.action(async (_options: unknown, command: Command) => {
			const globals = globalsOf(command);
			render(
				await cliApi({ path: "admin/feature-flags", timeout: globals.timeout }),
				globals,
			);
		});
}
