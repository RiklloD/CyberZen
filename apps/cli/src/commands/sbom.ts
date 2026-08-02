import type { Command } from "commander";
import { api } from "../lib/api";
import { globalsOf } from "../lib/globalFlags";
import { render } from "../lib/output";
import { repositoryName, requiredTenant } from "../lib/tenant";

function repoQuery(
	options: { tenant?: string; repo?: string },
	globals: ReturnType<typeof globalsOf>,
) {
	return {
		tenantSlug: requiredTenant(options.tenant ?? globals.tenant),
		repositoryFullName: repositoryName(options.repo),
	};
}

export function registerSbom(program: Command): void {
	const sbom = program
		.command("sbom")
		.description("Software bill of materials and supply-chain analysis");

	sbom
		.command("get")
		.option("--tenant <slug>")
		.option("--repo <owner/name>")
		.action(
			async (options: { tenant?: string; repo?: string }, command: Command) => {
				const globals = globalsOf(command);
				render(
					await api({
						path: "/api/sbom",
						query: repoQuery(options, globals),
						timeout: globals.timeout,
					}),
					globals,
				);
			},
		);

	sbom
		.command("export")
		.requiredOption("--snapshot-id <id>")
		.option("--format <format>", "cyclonedx or spdx", "cyclonedx")
		.action(
			async (
				options: { snapshotId: string; format: string },
				command: Command,
			) => {
				const globals = globalsOf(command);
				render(
					await api({
						path: "/api/sbom/export",
						query: { snapshotId: options.snapshotId, format: options.format },
						timeout: globals.timeout,
					}),
					globals,
				);
			},
		);

	const analysisRoutes: Record<string, string> = {
		"cve-scan": "/api/sbom/cve-scan",
		"license-scan": "/api/sbom/license-scan",
		"malicious-scan": "/api/sbom/malicious-scan",
		"confusion-scan": "/api/sbom/confusion-scan",
		attestation: "/api/sbom/attestation",
		"supply-chain-posture": "/api/sbom/supply-chain-posture",
		"container-image-scan": "/api/sbom/container-image-scan",
		"update-recommendations": "/api/sbom/update-recommendations",
	};
	for (const [name, path] of Object.entries(analysisRoutes)) {
		sbom
			.command(name)
			.option("--tenant <slug>")
			.option("--repo <owner/name>")
			.action(
				async (
					options: { tenant?: string; repo?: string },
					command: Command,
				) => {
					const globals = globalsOf(command);
					render(
						await api({
							path,
							query: repoQuery(options, globals),
							timeout: globals.timeout,
						}),
						globals,
					);
				},
			);
	}

	sbom
		.command("diff")
		.requiredOption("--from <snapshot-id>")
		.requiredOption("--to <snapshot-id>")
		.action(async (options: { from: string; to: string }, command: Command) => {
			const globals = globalsOf(command);
			render(
				await api({
					path: "/api/sbom/diff",
					query: { fromSnapshotId: options.from, toSnapshotId: options.to },
					timeout: globals.timeout,
				}),
				globals,
			);
		});
}
