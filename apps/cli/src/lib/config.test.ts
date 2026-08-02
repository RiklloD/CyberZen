import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	apiUrl,
	authPath,
	configDir,
	DEFAULT_API_URL,
	DEFAULT_SITE_URL,
	deleteAuth,
	readAuth,
	readConfig,
	siteUrl,
	writeAuth,
	writeConfig,
} from "./config.js";

const originalConfigDir = process.env.CYBERZEN_CONFIG_DIR;
const originalApiUrl = process.env.CYBERZEN_API_URL;
const originalSiteUrl = process.env.CYBERZEN_SITE_URL;

afterEach(() => {
	if (originalConfigDir === undefined) delete process.env.CYBERZEN_CONFIG_DIR;
	else process.env.CYBERZEN_CONFIG_DIR = originalConfigDir;
	if (originalApiUrl === undefined) delete process.env.CYBERZEN_API_URL;
	else process.env.CYBERZEN_API_URL = originalApiUrl;
	if (originalSiteUrl === undefined) delete process.env.CYBERZEN_SITE_URL;
	else process.env.CYBERZEN_SITE_URL = originalSiteUrl;
});

function isolatedDir(): string {
	const dir = mkdtempSync(join(tmpdir(), "cyberzen-cli-test-"));
	process.env.CYBERZEN_CONFIG_DIR = dir;
	return dir;
}

describe("config persistence", () => {
	test("uses defaults when no config exists", () => {
		isolatedDir();
		expect(readAuth()).toBeNull();
		expect(readConfig()).toEqual({});
		expect(apiUrl()).toBe(DEFAULT_API_URL);
		expect(siteUrl()).toBe(DEFAULT_SITE_URL);
	});

	test("writes and reads auth credentials", () => {
		const dir = isolatedDir();
		const auth = { token: "czk_secret", tenantSlug: "acme", createdAt: 123 };
		writeAuth(auth);
		expect(readAuth()).toEqual(auth);
		expect(authPath()).toBe(join(dir, "auth.json"));
		expect(readFileSync(authPath(), "utf8")).toContain("czk_secret");
	});

	test("deletes auth credentials without affecting config", () => {
		isolatedDir();
		writeAuth({ token: "czk_secret", createdAt: Date.now() });
		writeConfig({ tenant: "acme", output: "json" });
		expect(deleteAuth()).toBe(true);
		expect(deleteAuth()).toBe(false);
		expect(existsSync(authPath())).toBe(false);
		expect(readConfig()).toEqual({ tenant: "acme", output: "json" });
	});

	test("environment URL overrides persisted config", () => {
		isolatedDir();
		writeConfig({
			apiUrl: "https://persisted.cloud",
			siteUrl: "https://persisted.site",
		});
		process.env.CYBERZEN_API_URL = "https://env.cloud";
		process.env.CYBERZEN_SITE_URL = "https://env.site";
		expect(apiUrl()).toBe("https://env.cloud");
		expect(siteUrl()).toBe("https://env.site");
		expect(apiUrl("https://flag.cloud")).toBe("https://flag.cloud");
		expect(siteUrl("https://flag.site")).toBe("https://flag.site");
	});

	test("malformed JSON is treated as missing", () => {
		const dir = isolatedDir();
		writeFileSync(join(dir, "config.json"), "{invalid");
		expect(readConfig()).toEqual({});
	});
});

void configDir;
