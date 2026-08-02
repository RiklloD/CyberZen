import type { Command } from "commander";
import { cliApi } from "../lib/api";
import { globalsOf } from "../lib/globalFlags";
import { render } from "../lib/output";

/** Dashboard data exposed through the explicit, tenant-bound CLI endpoint. */
export function registerDashboard(program: Command): void {
	program
		.command("dashboard")
		.description("Show the current tenant security dashboard")
		.action(async (_options: unknown, command: Command) => {
			const globals = globalsOf(command);
			render(
				await cliApi({ path: "dashboard", timeout: globals.timeout }),
				globals,
			);
		});
}
