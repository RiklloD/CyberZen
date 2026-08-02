import { afterEach, describe, expect, mock, test } from "bun:test";
import { rmSync } from "node:fs";
import { api, redactHeaders } from "./api";
import { writeAuth } from "./config";

const originalFetch = globalThis.fetch;
const tempDir = `${process.cwd()}/.tmp-api-test`;

function setup(): void {
	process.env.CYBERZEN_CONFIG_DIR = tempDir;
	writeAuth({ token: "czk_test", createdAt: 1 });
}

afterEach(() => {
	globalThis.fetch = originalFetch;
	delete process.env.CYBERZEN_CONFIG_DIR;
	rmSync(tempDir, { recursive: true, force: true });
});

describe("HTTP client", () => {
	test("sends bearer auth and query parameters", async () => {
		setup();
		let request: Request | undefined;
		globalThis.fetch = mock(async (input: string | URL, init?: RequestInit) => {
			request = new Request(String(input), init);
			return new Response(JSON.stringify({ ok: true }), { status: 200 });
		}) as unknown as typeof fetch;
		await expect(
			api({ path: "/api/findings", query: { tenant: "acme", limit: 1 } }),
		).resolves.toEqual({ ok: true });
		expect(request?.headers.get("authorization")).toBe("Bearer czk_test");
		expect(request?.url).toContain("tenant=acme");
		expect(request?.url).toContain("limit=1");
	});

	test("uses MSSP header when requested", async () => {
		setup();
		let request: Request | undefined;
		globalThis.fetch = mock(async (input: string | URL, init?: RequestInit) => {
			request = new Request(String(input), init);
			return new Response("{}", { status: 200 });
		}) as unknown as typeof fetch;
		await api({ path: "/api/mssp/dashboard", mssp: true });
		expect(request?.headers.get("x-mssp-api-key")).toBe("czk_test");
		expect(request?.headers.get("authorization")).toBeNull();
	});

	test("maps 401 to AuthError and 429 to ApiError", async () => {
		setup();
		globalThis.fetch = mock(
			async () =>
				new Response(JSON.stringify({ error: "bad key" }), { status: 401 }),
		) as unknown as typeof fetch;
		await expect(api({ path: "/api/findings" })).rejects.toMatchObject({
			exitCode: 2,
		});
		globalThis.fetch = mock(
			async () =>
				new Response("slow down", {
					status: 429,
					headers: { "Retry-After": "4" },
				}),
		) as unknown as typeof fetch;
		await expect(api({ path: "/api/findings" })).rejects.toMatchObject({
			status: 429,
			hint: "Retry after 4 seconds.",
		});
	});

	test("redacts credentials from diagnostics", () => {
		expect(
			redactHeaders({
				Authorization: "Bearer secret",
				"X-MSSP-Api-Key": "msk_secret",
				Accept: "json",
			}),
		).toEqual({
			Authorization: "[REDACTED]",
			"X-MSSP-Api-Key": "[REDACTED]",
			Accept: "json",
		});
	});
});
