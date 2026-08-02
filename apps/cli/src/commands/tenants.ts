import type { Command } from "commander";
import { api } from "../lib/api";
import { readAuth, writeConfig } from "../lib/config";
import { UsageError } from "../lib/errors";
import { globalsOf } from "../lib/globalFlags";
import { render } from "../lib/output";
import { resolveTenant } from "../lib/project";

export function registerTenants(program: Command): void {
	const tenants = program
		.command("tenants")
		.description("Manage tenant/workspace selection");

	tenants.command("current").action((_options: unknown, command: Command) => {
		const globals = globalsOf(command);
		const stored = readAuth();
		const tenant = resolveTenant(globals.tenant) ?? stored?.tenantSlug;
		render(
			{
				tenant: tenant ?? null,
				source: globals.tenant
					? "flag-or-env"
					: stored?.tenantSlug
						? "stored-auth"
						: "project-link",
			},
			globals,
		);
	});

	tenants
		.command("use <slug>")
		.description("Set the default tenant")
		.action((slug: string, _options: unknown, command: Command) => {
			const globals = globalsOf(command);
			writeConfig({ tenant: slug });
			render({ tenant: slug, selected: true }, globals);
		});

	tenants
		.command("list")
		.description("List tenants visible to the current credential")
		.action(async (_options: unknown, command: Command) => {
			const globals = globalsOf(command);
			// This endpoint is MSSP-scoped; regular tenant discovery is provided by
			// the authenticated bridge in the next phase. Keep this command real by
			// exposing the existing endpoint and its explicit credential requirement.
			render(
				await api({
					path: "/api/mssp/tenants",
					mssp: true,
					timeout: globals.timeout,
				}),
				globals,
			);
		});

	tenants
		.command("create")
		.description("Create a tenant")
		.requiredOption("--slug <slug>")
		.action(() => {
			throw new UsageError(
				"Tenant creation requires the authenticated Convex bridge.",
				"Use `cyberzen tenants use <slug>` for an existing tenant. The bridge is being implemented next.",
			);
		});
}
