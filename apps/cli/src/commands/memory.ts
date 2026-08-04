import type { Command } from "commander";
import { cliApi } from "../lib/api";
import { globalsOf } from "../lib/globalFlags";
import { render } from "../lib/output";
import { repositoryName } from "../lib/tenant";

export function registerMemory(program: Command): void {
	const memory = program
		.command("memory")
		.description("CyberZen neural memory");
	memory
		.command("summary")
		.option("--repo <owner/name>")
		.description("Show real learned-memory statistics for a repository")
		.action(async (options: { repo?: string }, command: Command) => {
			const globals = globalsOf(command);
			render(
				await cliApi({
					path: "memory/summary",
					query: { repo: repositoryName(options.repo ?? globals.repo) },
					timeout: globals.timeout,
				}),
				globals,
			);
		});
}
