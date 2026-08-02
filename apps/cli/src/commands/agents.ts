import type { Command } from "commander";
import { cliApi } from "../lib/api";
import { globalsOf } from "../lib/globalFlags";
import { render } from "../lib/output";

export function registerAgents(program: Command): void {
	const agents = program
		.command("agents")
		.description("CyberZen agent activity");
	agents
		.command("tasks")
		.option("--status <status>")
		.option("--agent-type <type>")
		.option("--limit <n>")
		.action(
			async (
				options: { status?: string; agentType?: string; limit?: string },
				command: Command,
			) => {
				const globals = globalsOf(command);
				render(
					await cliApi({
						path: "agent-tasks",
						query: {
							status: options.status,
							agentType: options.agentType,
							limit: options.limit,
						},
						timeout: globals.timeout,
					}),
					globals,
				);
			},
		);
}
