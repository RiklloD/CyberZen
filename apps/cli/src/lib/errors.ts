/**
 * Central error taxonomy + exit-code mapping.
 *
 * Hard rule for agent use: data → stdout, diagnostics/errors → stderr.
 *
 * Exit codes:
 *   0  success
 *   1  API / runtime error
 *   2  auth error (missing/invalid credentials)
 *   64 usage error (bad flags / missing required input)
 */

export class CyberzenError extends Error {
	constructor(
		message: string,
		readonly exitCode: number = 1,
		readonly hint?: string,
	) {
		super(message);
		this.name = new.target.name;
	}
}

export class AuthError extends CyberzenError {
	constructor(
		message = "Not authenticated.",
		hint = "Run `cyberzen login` (browser) or `cyberzen login --token <czk_…>`.",
	) {
		super(message, 2, hint);
	}
}

export class UsageError extends CyberzenError {
	constructor(message: string, hint?: string) {
		super(message, 64, hint);
	}
}

export class ApiError extends CyberzenError {
	constructor(
		readonly status: number,
		readonly url: string,
		body: string,
		hint?: string,
	) {
		super(`HTTP ${status} ${url}${body ? `: ${body}` : ""}`, 1, hint);
	}
}

/** Map any thrown value to a clean stderr message + process exit. */
export function handleError(err: unknown): never {
	const verbose = process.argv.includes("--verbose");
	if (err instanceof CyberzenError) {
		process.stderr.write(`error: ${err.message}\n`);
		if (err.hint) process.stderr.write(`hint:  ${err.hint}\n`);
		if (verbose && err.stack) process.stderr.write(`${err.stack}\n`);
		process.exit(err.exitCode);
	}
	// commander throws CommanderError for --help / usage; preserve its exit code.
	const code = (err as { exitCode?: number })?.exitCode;
	if (typeof code === "number") {
		const msg = (err as { message?: string })?.message;
		if (msg && code !== 0) process.stderr.write(`${msg}\n`);
		process.exit(code);
	}
	process.stderr.write(
		`error: ${err instanceof Error ? err.message : String(err)}\n`,
	);
	if (verbose && err instanceof Error && err.stack)
		process.stderr.write(`${err.stack}\n`);
	process.exit(1);
}
