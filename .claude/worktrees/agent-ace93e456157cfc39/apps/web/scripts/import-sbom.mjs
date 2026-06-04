import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ConvexHttpClient } from "convex/browser";
import { api } from "../convex/_generated/api.js";

async function streamLikeToText(value) {
	if (value === undefined || value === null) {
		return "";
	}

	if (typeof value === "string") {
		return value;
	}

	if (typeof value.text === "function") {
		return await value.text();
	}

	if (typeof value.arrayBuffer === "function") {
		return new TextDecoder().decode(await value.arrayBuffer());
	}

	if (value instanceof ArrayBuffer) {
		return new TextDecoder().decode(value);
	}

	if (ArrayBuffer.isView(value)) {
		return new TextDecoder().decode(value);
	}

	return String(value);
}

function parseArgs(argv) {
	let repoPath = "";
	let dryRun = false;
	const flags = new Map();

	for (let index = 0; index < argv.length; index += 1) {
		const current = argv[index];

		if (current === "--dry-run") {
			dryRun = true;
			continue;
		}

		if (current.startsWith("--")) {
			const next = argv[index + 1];
			if (!next || next.startsWith("--")) {
				throw new Error(`Missing value for ${current}`);
			}

			flags.set(current.slice(2), next);
			index += 1;
			continue;
		}

		if (!repoPath) {
			repoPath = current;
			continue;
		}

		throw new Error(`Unexpected positional argument: ${current}`);
	}

	if (!repoPath) {
		throw new Error(
			"Repository path is required. Usage: bun run sbom:import -- <repo-path> --tenant atlas-fintech --repository atlas-fintech/payments-api --branch main --commit abc123 [--dry-run]",
		);
	}

	return {
		repoPath: resolve(repoPath),
		tenantSlug: flags.get("tenant") ?? "atlas-fintech",
		repositoryFullName:
			flags.get("repository") ?? "atlas-fintech/payments-api",
		branch: flags.get("branch") ?? "main",
		commitSha: flags.get("commit") ?? `local-${Date.now().toString(36)}`,
		dryRun,
	};
}

async function resolvePythonCommand() {
	if (process.env.PYTHON_BIN) {
		return process.env.PYTHON_BIN;
	}

	if (process.platform === "win32") {
		const pyPath = (await Bun.$`where.exe py`.quiet().nothrow().text()).trim();
		if (pyPath) {
			return "py";
		}

		const pythonPath = (
			await Bun.$`where.exe python`.quiet().nothrow().text()
		).trim();
		if (pythonPath) {
			return "python";
		}
	} else {
		const python3Path = (await Bun.$`which python3`.quiet().nothrow().text()).trim();
		if (python3Path) {
			return "python3";
		}

		const pythonPath = (await Bun.$`which python`.quiet().nothrow().text()).trim();
		if (pythonPath) {
			return "python";
		}
	}

	throw new Error("No Python runtime was available for SBOM ingestion.");
}

async function runSbomWorker(repoPath) {
	const scriptDir = dirname(fileURLToPath(import.meta.url));
	const workerRoot = resolve(scriptDir, "..", "..", "..", "services", "sbom-ingest");
	const workerSrc = resolve(workerRoot, "src");
	const pathSeparator = process.platform === "win32" ? ";" : ":";
	const pythonPath = process.env.PYTHONPATH
		? `${workerSrc}${pathSeparator}${process.env.PYTHONPATH}`
		: workerSrc;
	const pythonCommand = await resolvePythonCommand();

	const command =
		process.platform === "win32"
			? `& ${pythonCommand} -m sentinel_sbom_ingest.cli "${repoPath}"`
			: `${pythonCommand} -m sentinel_sbom_ingest.cli "${repoPath}"`;

	const shellResult =
		process.platform === "win32"
			? await Bun.$`powershell.exe -NoProfile -Command ${command}`
					.cwd(workerRoot)
					.env({
						...process.env,
						PYTHONPATH: pythonPath,
					})
					.quiet()
					.nothrow()
			: await Bun.$`${pythonCommand} -m sentinel_sbom_ingest.cli ${repoPath}`
					.cwd(workerRoot)
					.env({
						...process.env,
						PYTHONPATH: pythonPath,
					})
					.quiet()
					.nothrow();

	if (shellResult.exitCode !== 0) {
		const stderr = await streamLikeToText(shellResult.stderr);
		const stdout = await streamLikeToText(shellResult.stdout);
		throw new Error(
			`SBOM worker failed with code ${shellResult.exitCode}.\n${stderr || stdout}`,
		);
	}

	const stdout = await streamLikeToText(shellResult.stdout);
	return JSON.parse(stdout);
}

function getConvexUrl() {
	const url = process.env.CONVEX_URL ?? process.env.VITE_CONVEX_URL;

	if (!url) {
		throw new Error(
			"Set CONVEX_URL or VITE_CONVEX_URL before importing an SBOM snapshot.",
		);
	}

	return url;
}

async function main() {
	const options = parseArgs(process.argv.slice(2));
	const snapshot = await runSbomWorker(options.repoPath);

	if (options.dryRun) {
		console.log(
			JSON.stringify(
				{
					tenantSlug: options.tenantSlug,
					repositoryFullName: options.repositoryFullName,
					branch: options.branch,
					commitSha: options.commitSha,
					sourceFiles: snapshot.sourceFiles,
					componentCount: snapshot.components.length,
					preview: snapshot.components.slice(0, 5),
				},
				null,
				2,
			),
		);
		return;
	}

	const client = new ConvexHttpClient(getConvexUrl());
	const result = await client.mutation(api.sbom.ingestRepositoryInventory, {
		tenantSlug: options.tenantSlug,
		repositoryFullName: options.repositoryFullName,
		branch: options.branch,
		commitSha: options.commitSha,
		sourceFiles: snapshot.sourceFiles,
		components: snapshot.components,
	});

	console.log(
		JSON.stringify(
			{
				snapshotId: result.snapshotId,
				componentCount: result.componentCount,
				sourceFiles: snapshot.sourceFiles,
			},
			null,
			2,
		),
	);
}

await main();
