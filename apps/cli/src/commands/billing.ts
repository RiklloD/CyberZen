import type { Command } from "commander";
import { cliApi } from "../lib/api";
import { globalsOf } from "../lib/globalFlags";
import { render } from "../lib/output";

export function registerBilling(program: Command): void {
	program
		.command("billing")
		.description("Billing plan, subscription, invoices, and usage")
		.command("summary")
		.action(async (_options: unknown, command: Command) => {
			const globals = globalsOf(command);
			render(
				await cliApi({ path: "billing/summary", timeout: globals.timeout }),
				globals,
			);
		});
}
