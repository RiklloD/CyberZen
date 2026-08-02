import type { Command } from "commander";
import { api } from "../lib/api";
import { UsageError } from "../lib/errors";
import { globalsOf } from "../lib/globalFlags";
import { render } from "../lib/output";
import { repositoryName, requiredTenant } from "../lib/tenant";

export function registerRepos(program: Command): void {
	const repos = program
		.command("repos")
		.description("Scan and inspect repositories");

	repos
		.command("list")
		.description("List repositories for the authenticated tenant")
		.action(async (_options: unknown, command: Command) => {
			const globals = globalsOf(command);
			render(
				await api({ path: "/api/cli/repos", timeout: globals.timeout }),
				globals,
			);
		});

	repos
		.command("scan")
		.description("Dispatch a real full repository scan")
		.requiredOption("--repo <owner/name>")
		.option("--tenant <slug>")
		.option("--branch <branch>")
		.action(
			async (
				options: { repo: string; tenant?: string; branch?: string },
				command: Command,
			) => {
				const globals = globalsOf(command);
				const workspace = requiredTenant(options.tenant ?? globals.tenant);
				render(
					await api({
						path: "/api/repositories/scan",
						method: "POST",
						body: {
							workspace,
							repository: repositoryName(options.repo),
							branch: options.branch,
						},
						timeout: globals.timeout,
					}),
					globals,
				);
			},
		);

	repos
		.command("health")
		.description("Show the repository health score")
		.option("--repo <owner/name>")
		.option("--tenant <slug>")
		.action(
			async (options: { repo?: string; tenant?: string }, command: Command) => {
				const globals = globalsOf(command);
				render(
					await api({
						path: "/api/repository/health-score",
						query: {
							tenantSlug: requiredTenant(options.tenant ?? globals.tenant),
							repositoryFullName: repositoryName(options.repo),
						},
						timeout: globals.timeout,
					}),
					globals,
				);
			},
		);

	repos
		.command("drift-posture")
		.description("Show aggregate repository security drift posture")
		.option("--repo <owner/name>")
		.option("--tenant <slug>")
		.action(
			async (options: { repo?: string; tenant?: string }, command: Command) => {
				const globals = globalsOf(command);
				render(
					await api({
						path: "/api/repository/drift-posture",
						query: {
							tenantSlug: requiredTenant(options.tenant ?? globals.tenant),
							repositoryFullName: repositoryName(options.repo),
						},
						timeout: globals.timeout,
					}),
					globals,
				);
			},
		);

	program
		.command("scan <repo>")
		.description("Alias for `repos scan --repo`")
		.option("--tenant <slug>")
		.option("--branch <branch>")
		.action(
			async (
				repo: string,
				options: { tenant?: string; branch?: string },
				command: Command,
			) => {
				const globals = globalsOf(command);
				const workspace = requiredTenant(options.tenant ?? globals.tenant);
				render(
					await api({
						path: "/api/repositories/scan",
						method: "POST",
						body: { workspace, repository: repo, branch: options.branch },
						timeout: globals.timeout,
					}),
					globals,
				);
			},
		);

	void UsageError;
}
