#!/usr/bin/env node
import { Command } from "commander";
import { registerAll } from "./commands/index.js";
import { handleError } from "./lib/errors.js";
import { applyGlobalFlags } from "./lib/globalFlags.js";

const program = new Command()
	.name("cyberzen")
	.description("CyberZen — security operations from the terminal")
	.version(
		process.env.CYBERZEN_CLI_VERSION ?? "0.1.0",
		"-v, --version",
		"Print the CLI version",
	);

applyGlobalFlags(program);
registerAll(program);

program.exitOverride();

/** Commander only parses parent options before a subcommand. Normalize the
 * documented global flags so agents and humans may place them anywhere. */
function normalizeGlobalArgs(args: string[]): string[] {
	const flagsWithValues = new Set([
		"--tenant",
		"--profile",
		"--token",
		"--api-url",
		"--site-url",
		"--timeout",
	]);
	const booleanFlags = new Set([
		"--json",
		"--ndjson",
		"--verbose",
		"--no-color",
	]);
	const globals: string[] = [];
	const rest: string[] = [];
	for (let index = 2; index < args.length; index += 1) {
		const arg = args[index];
		if (flagsWithValues.has(arg)) {
			globals.push(arg);
			if (index + 1 < args.length) {
				index += 1;
				const value = args[index];
				if (value !== undefined) globals.push(value);
			}
		} else if (booleanFlags.has(arg)) {
			globals.push(arg);
		} else {
			rest.push(arg);
		}
	}
	return [...args.slice(0, 2), ...globals, ...rest];
}

try {
	await program.parseAsync(normalizeGlobalArgs(process.argv));
} catch (err) {
	handleError(err);
}
