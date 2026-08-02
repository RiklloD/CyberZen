import type { Command } from "commander";
import { cliApi } from "../lib/api";
import { globalsOf } from "../lib/globalFlags";
import { render } from "../lib/output";

export function registerJobs(program: Command): void {
	program
		.command("jobs")
		.description("Background job health and paused-job state")
		.command("summary")
		.action(async (_options: unknown, command: Command) => {
			const globals = globalsOf(command);
			render(
				await cliApi({ path: "jobs/summary", timeout: globals.timeout }),
				globals,
			);
		});
}
