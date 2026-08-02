import { UsageError } from "./errors";
import { readProject, resolveTenant } from "./project";

export function requiredTenant(explicit?: string): string {
	const tenant = resolveTenant(explicit);
	if (!tenant) {
		throw new UsageError(
			"A tenant is required for this command.",
			"Pass `--tenant <slug>`, set CYBERZEN_TENANT, or run `cyberzen link --tenant <slug>`.",
		);
	}
	return tenant;
}

export function repositoryName(explicit?: string): string {
	if (explicit) return explicit;
	const linked = readProject()?.repoFullName;
	if (linked) return linked;
	throw new UsageError(
		"A repository is required.",
		"Pass `--repo <owner/name>` or link one with `cyberzen link --repo <owner/name>`.",
	);
}
