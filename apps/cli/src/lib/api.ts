import { requireToken } from "./auth";
import { apiUrl, siteUrl } from "./config";
import { ApiError, AuthError } from "./errors";

export interface ApiOptions {
	path: string;
	method?: string;
	body?: unknown;
	query?: Record<string, string | number | boolean | undefined>;
	/** Use the separate MSSP credential header for MSSP endpoints. */
	mssp?: boolean;
	token?: string;
	timeout?: number;
	baseUrl?: string;
}

function buildUrl(
	base: string,
	path: string,
	query?: ApiOptions["query"],
): string {
	const url = new URL(path, `${base.replace(/\/$/, "")}/`);
	for (const [key, value] of Object.entries(query ?? {})) {
		if (value !== undefined) url.searchParams.set(key, String(value));
	}
	return url.toString();
}

export async function api<T = unknown>(options: ApiOptions): Promise<T> {
	const token = options.token ?? requireToken();
	const url = buildUrl(
		options.baseUrl ?? siteUrl(),
		options.path,
		options.query,
	);
	const controller = new AbortController();
	const timeout = setTimeout(
		() => controller.abort(),
		options.timeout ?? 30_000,
	);
	const headers: Record<string, string> = {
		Accept: "application/json",
		Authorization: `Bearer ${token}`,
	};
	if (options.mssp) {
		delete headers.Authorization;
		headers["X-MSSP-Api-Key"] = token;
	}
	if (options.body !== undefined) headers["Content-Type"] = "application/json";

	try {
		const response = await fetch(url, {
			method: options.method ?? (options.body === undefined ? "GET" : "POST"),
			headers,
			body:
				options.body === undefined ? undefined : JSON.stringify(options.body),
			signal: controller.signal,
		});
		const text = await response.text();
		let payload: unknown = text;
		try {
			payload = text ? JSON.parse(text) : null;
		} catch {
			// Preserve non-JSON response bodies for diagnostics.
		}
		if (response.status === 401) {
			throw new AuthError(
				typeof payload === "object" && payload !== null && "error" in payload
					? String((payload as { error: unknown }).error)
					: "API key was rejected.",
			);
		}
		if (response.status === 429) {
			const retryAfter = response.headers.get("retry-after");
			throw new ApiError(
				response.status,
				url,
				formatBody(payload),
				retryAfter ? `Retry after ${retryAfter} seconds.` : undefined,
			);
		}
		if (!response.ok)
			throw new ApiError(response.status, url, formatBody(payload));
		return payload as T;
	} catch (error) {
		if (error instanceof DOMException && error.name === "AbortError") {
			throw new ApiError(408, url, "Request timed out.");
		}
		throw error;
	} finally {
		clearTimeout(timeout);
	}
}

export function endpoint(path: string, base = siteUrl()): string {
	return buildUrl(base, path);
}

function formatBody(body: unknown): string {
	if (typeof body === "string") return body;
	return body ? JSON.stringify(body) : "";
}

/** Keep verbose diagnostics safe: never include Authorization values. */
export function redactHeaders(
	headers: Record<string, string>,
): Record<string, string> {
	return Object.fromEntries(
		Object.entries(headers).map(([key, value]) =>
			/authorization|api-key/i.test(key) ? [key, "[REDACTED]"] : [key, value],
		),
	);
}

void apiUrl; // Keep the client URL import available for the Convex transport added later.
