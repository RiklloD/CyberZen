import {
	existsSync,
	mkdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";

export interface ProjectLink {
	tenantSlug: string;
	repoFullName?: string;
	linkedAt: number;
}

export function projectPath(directory = process.cwd()): string {
	return join(resolve(directory), ".cyberzen", "project.json");
}

export function readProject(directory = process.cwd()): ProjectLink | null {
	const path = findProjectPath(directory);
	if (!path) return null;
	try {
		return JSON.parse(readFileSync(path, "utf8")) as ProjectLink;
	} catch {
		return null;
	}
}

export function findProjectPath(directory = process.cwd()): string | null {
	let current = resolve(directory);
	while (true) {
		const candidate = join(current, ".cyberzen", "project.json");
		if (existsSync(candidate)) return candidate;
		const parent = dirname(current);
		if (parent === current) return null;
		current = parent;
	}
}

export function linkProject(
	link: Omit<ProjectLink, "linkedAt">,
	directory = process.cwd(),
): string {
	const path = projectPath(directory);
	mkdirSync(dirname(path), { recursive: true });
	writeFileSync(
		path,
		`${JSON.stringify({ ...link, linkedAt: Date.now() }, null, 2)}\n`,
		"utf8",
	);
	return path;
}

export function unlinkProject(directory = process.cwd()): boolean {
	const path = findProjectPath(directory);
	if (!path) return false;
	rmSync(path);
	return true;
}

export function resolveTenant(
	explicit?: string,
	directory = process.cwd(),
): string | undefined {
	return (
		explicit ??
		process.env.CYBERZEN_TENANT ??
		readProject(directory)?.tenantSlug
	);
}
