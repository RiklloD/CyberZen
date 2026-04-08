import { ConvexHttpClient } from "convex/browser";
import { api } from "../convex/_generated/api.js";

function parseArgs(argv) {
	const flags = new Map();

	for (let index = 0; index < argv.length; index += 1) {
		const current = argv[index];

		if (!current.startsWith("--")) {
			throw new Error(`Unexpected positional argument: ${current}`);
		}

		const next = argv[index + 1];
		if (!next || next.startsWith("--")) {
			throw new Error(`Missing value for ${current}`);
		}

		flags.set(current.slice(2), next);
		index += 1;
	}

	return {
		tenantSlug: flags.get("tenant") ?? undefined,
		repositoryFullName: flags.get("repository") ?? undefined,
		maxRepositories: flags.has("repo-limit")
			? Number(flags.get("repo-limit"))
			: undefined,
		lookbackHours: flags.has("hours")
			? Number(flags.get("hours"))
			: undefined,
		githubLimit: flags.has("github-limit")
			? Number(flags.get("github-limit"))
			: undefined,
		osvLimit: flags.has("osv-limit")
			? Number(flags.get("osv-limit"))
			: undefined,
	};
}

function getConvexUrl() {
	const url = process.env.CONVEX_URL ?? process.env.VITE_CONVEX_URL;

	if (!url) {
		throw new Error(
			"Set CONVEX_URL or VITE_CONVEX_URL before syncing advisories.",
		);
	}

	return url;
}

async function main() {
	const options = parseArgs(process.argv.slice(2));
	const client = new ConvexHttpClient(getConvexUrl());

	if (Boolean(options.tenantSlug) !== Boolean(options.repositoryFullName)) {
		throw new Error(
			"--tenant and --repository must be provided together when targeting a single repository.",
		);
	}

	const result = await client.action(api.breachIngest.syncRecentAdvisories, {
		tenantSlug: options.tenantSlug,
		repositoryFullName: options.repositoryFullName,
		maxRepositories: options.maxRepositories,
		lookbackHours: options.lookbackHours,
		githubLimit: options.githubLimit,
		osvLimit: options.osvLimit,
	});

	console.log(JSON.stringify(result, null, 2));
}

await main();
