import { ConvexHttpClient } from "convex/browser";
import { api } from "../convex/_generated/api.js";

function parseArgs(argv) {
	let provider = "";
	const flags = new Map();

	for (let index = 0; index < argv.length; index += 1) {
		const current = argv[index];

		if (current.startsWith("--")) {
			const next = argv[index + 1];
			if (!next || next.startsWith("--")) {
				throw new Error(`Missing value for ${current}`);
			}

			flags.set(current.slice(2), next);
			index += 1;
			continue;
		}

		if (!provider) {
			provider = current;
			continue;
		}

		throw new Error(`Unexpected positional argument: ${current}`);
	}

	if (!provider || (provider !== "github" && provider !== "osv")) {
		throw new Error(
			"Provider is required. Usage: bun run advisory:import -- <github|osv> --id <advisory-id> --tenant atlas-fintech --repository atlas-fintech/payments-api",
		);
	}

	const advisoryId = flags.get("id");
	if (!advisoryId) {
		throw new Error("Missing required --id value.");
	}

	return {
		provider,
		advisoryId,
		tenantSlug: flags.get("tenant") ?? "atlas-fintech",
		repositoryFullName:
			flags.get("repository") ?? "atlas-fintech/payments-api",
	};
}

function getConvexUrl() {
	const url = process.env.CONVEX_URL ?? process.env.VITE_CONVEX_URL;

	if (!url) {
		throw new Error(
			"Set CONVEX_URL or VITE_CONVEX_URL before importing an advisory.",
		);
	}

	return url;
}

async function main() {
	const options = parseArgs(process.argv.slice(2));
	const client = new ConvexHttpClient(getConvexUrl());

	const result =
		options.provider === "github"
			? await client.action(api.breachIngest.importGithubSecurityAdvisoryById, {
					tenantSlug: options.tenantSlug,
					repositoryFullName: options.repositoryFullName,
					ghsaId: options.advisoryId,
				})
			: await client.action(api.breachIngest.importOsvAdvisoryById, {
					tenantSlug: options.tenantSlug,
					repositoryFullName: options.repositoryFullName,
					osvId: options.advisoryId,
				});

	console.log(JSON.stringify(result, null, 2));
}

await main();
