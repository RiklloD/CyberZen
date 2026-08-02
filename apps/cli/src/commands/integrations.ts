import type { Command } from "commander";
import { cliApi } from "../lib/api";
import { globalsOf } from "../lib/globalFlags";
import { render } from "../lib/output";

export function registerIntegrations(program: Command): void {
	const integrations = program
		.command("integrations")
		.description("Connected integration health");
	integrations
		.command("catalog")
		.description("List supported integration types")
		.action(async (_options: unknown, command: Command) => {
			const globals = globalsOf(command);
			render(
				await cliApi({
					path: "integrations/catalog",
					timeout: globals.timeout,
				}),
				globals,
			);
		});
	integrations
		.command("health")
		.action(async (_options: unknown, command: Command) => {
			const globals = globalsOf(command);
			render(
				await cliApi({ path: "integrations/health", timeout: globals.timeout }),
				globals,
			);
		});
}
