import open from "open";
import { type AuthFile, readAuth, siteUrl, writeAuth } from "./config";
import { AuthError, UsageError } from "./errors";

export interface TokenOptions {
	token?: string;
	profile?: string;
}

/** Resolve credentials without ever printing the secret. */
export function getToken(options: TokenOptions = {}): string | null {
	if (options.token) return options.token;
	if (process.env.CYBERZEN_API_KEY) return process.env.CYBERZEN_API_KEY;
	const stored = readAuth();
	if (!stored) return null;
	if (options.profile && stored.profiles?.[options.profile]) {
		return stored.profiles[options.profile]?.token ?? null;
	}
	return stored.token;
}

export function requireToken(options: TokenOptions = {}): string {
	const token = getToken(options);
	if (!token) throw new AuthError();
	return token;
}

export function saveToken(
	token: string,
	metadata: Omit<Partial<AuthFile>, "token" | "createdAt"> = {},
): void {
	writeAuth({ token, createdAt: Date.now(), ...metadata });
}

export function tokenPreview(token: string): string {
	if (token.length <= 8) return "********";
	return `${token.slice(0, 4)}…${token.slice(-4)}`;
}

export interface DeviceLoginOptions {
	baseUrl?: string;
	openBrowser?: boolean;
	timeoutMs?: number;
}

export interface DeviceLoginResult {
	token: string;
	tenantSlug?: string;
}

export async function deviceLogin(
	options: DeviceLoginOptions = {},
): Promise<DeviceLoginResult> {
	const baseUrl = options.baseUrl ?? siteUrl();
	const start = await fetch(new URL("/api/cli/device/start", baseUrl), {
		method: "POST",
		headers: { Accept: "application/json" },
	});
	if (!start.ok)
		throw new AuthError(`Device login could not start (HTTP ${start.status}).`);
	const challenge = (await start.json()) as {
		deviceCode: string;
		userCode: string;
		verificationUrl: string;
		expiresIn: number;
		interval: number;
	};

	process.stderr.write(`Open ${challenge.verificationUrl}\n`);
	process.stderr.write(`Authorization code: ${challenge.userCode}\n`);
	if (options.openBrowser !== false) {
		try {
			await open(challenge.verificationUrl);
		} catch {
			/* print URL is sufficient */
		}
	}

	const deadline =
		Date.now() + (options.timeoutMs ?? challenge.expiresIn * 1000);
	while (Date.now() < deadline) {
		await new Promise((resolve) =>
			setTimeout(resolve, challenge.interval * 1000),
		);
		const poll = await fetch(new URL("/api/cli/device/poll", baseUrl), {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Accept: "application/json",
			},
			body: JSON.stringify({ deviceCode: challenge.deviceCode }),
		});
		if (!poll.ok)
			throw new AuthError(`Device login polling failed (HTTP ${poll.status}).`);
		const result = (await poll.json()) as {
			status: string;
			token?: string;
			tenantSlug?: string;
		};
		if (result.status === "authorized" && result.token) {
			saveToken(result.token, { tenantSlug: result.tenantSlug });
			return { token: result.token, tenantSlug: result.tenantSlug };
		}
		if (result.status === "denied" || result.status === "expired")
			throw new AuthError(`Device login ${result.status}.`);
	}
	throw new UsageError(
		"Device login timed out.",
		"Run `cyberzen auth login` again.",
	);
}
