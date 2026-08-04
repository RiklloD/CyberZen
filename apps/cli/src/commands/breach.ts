import type { Command } from "commander";
import { cliApi } from "../lib/api";
import { globalsOf } from "../lib/globalFlags";
import { render } from "../lib/output";

export function registerBreach(program: Command): void {
	const breach = program
		.command("breach")
		.description("Breach intelligence: advisory disclosures and sync");

	breach
		.command("advisories")
		.description("List breach/advisory disclosures for the tenant")
		.option(
			"--limit <n>",
			"Maximum results",
			(value) => Number.parseInt(value, 10),
			50,
		)
		.action(async (options: { limit: number }, command: Command) => {
			const globals = globalsOf(command);
			render(
				await cliApi({
					path: "breach/advisories",
					query: { limit: options.limit },
					timeout: globals.timeout,
				}),
				globals,
			);
		});

	breach
		.command("sync")
		.description(
			"Trigger a manual advisory sync (schedules the background sync)",
		)
		.action(async (_options: unknown, command: Command) => {
			const globals = globalsOf(command);
			render(
				await cliApi({
					path: "breach/sync",
					method: "POST",
					timeout: globals.timeout,
				}),
				globals,
			);
		});
}
