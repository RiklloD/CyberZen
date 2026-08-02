import { describe, expect, test } from "bun:test";
import { ApiError, AuthError, UsageError } from "./errors.js";

describe("error taxonomy", () => {
	test("auth errors use exit code 2 and login hint", () => {
		const error = new AuthError();
		expect(error.exitCode).toBe(2);
		expect(error.hint).toContain("cyberzen login");
	});

	test("usage errors use exit code 64", () => {
		const error = new UsageError("tenant is required");
		expect(error.exitCode).toBe(64);
		expect(error.message).toBe("tenant is required");
	});

	test("API errors preserve status and URL", () => {
		const error = new ApiError(
			429,
			"https://example.test/api/findings",
			"slow down",
		);
		expect(error.exitCode).toBe(1);
		expect(error.status).toBe(429);
		expect(error.url).toContain("/api/findings");
		expect(error.message).toContain("slow down");
	});
});

test("error classes have stable names", () => {
	expect(new AuthError().name).toBe("AuthError");
	expect(new UsageError("x").name).toBe("UsageError");
	expect(new ApiError(500, "url", "").name).toBe("ApiError");
});
