import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import {
	findProjectPath,
	linkProject,
	readProject,
	resolveTenant,
	unlinkProject,
} from "./project";

const root = join(process.cwd(), ".tmp-project-test");

afterEach(() => rmSync(root, { recursive: true, force: true }));

describe("project linkage", () => {
	test("writes and reads a directory link", () => {
		const path = linkProject(
			{ tenantSlug: "acme", repoFullName: "acme/app" },
			root,
		);
		expect(path).toContain(".cyberzen");
		expect(readProject(root)).toMatchObject({
			tenantSlug: "acme",
			repoFullName: "acme/app",
		});
		expect(findProjectPath(join(root, "nested"))).toBe(path);
	});

	test("unlinks a project", () => {
		linkProject({ tenantSlug: "acme" }, root);
		expect(unlinkProject(root)).toBe(true);
		expect(existsSync(join(root, ".cyberzen", "project.json"))).toBe(false);
		expect(unlinkProject(root)).toBe(false);
	});

	test("resolves tenant by explicit, env, then linked project precedence", () => {
		linkProject({ tenantSlug: "linked" }, root);
		expect(resolveTenant("explicit", root)).toBe("explicit");
		process.env.CYBERZEN_TENANT = "env";
		expect(resolveTenant(undefined, root)).toBe("env");
		delete process.env.CYBERZEN_TENANT;
		expect(resolveTenant(undefined, root)).toBe("linked");
	});
});
