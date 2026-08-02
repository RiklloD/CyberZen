import type { Command } from "commander";
import { api } from "../lib/api";
import { deviceLogin, getToken, saveToken, tokenPreview } from "../lib/auth";
import { deleteAuth, readAuth } from "../lib/config";
import { AuthError, UsageError } from "../lib/errors";
import { globalsOf } from "../lib/globalFlags";
import { render } from "../lib/output";

export function registerAuth(program: Command): void {
	const auth = program
		.command("auth")
		.description("Manage CyberZen authentication");

	auth
		.command("login")
		.description("Authenticate with an existing tenant API key")
		.option("--token <key>", "Tenant API key (czk_) or MSSP key (msk_)")
		.option("--tenant <slug>", "Default tenant slug")
		.option("--email <email>", "Email label for this credential")
		.action(
			async (
				options: { token?: string; tenant?: string; email?: string },
				command: Command,
			) => {
				const globals = globalsOf(command);
				const token = options.token ?? globals.token;
				if (!token) {
					const result = await deviceLogin({
						baseUrl: globals.siteUrl,
						openBrowser: process.env.CI !== "true",
					});
					render(
						{
							authenticated: true,
							token: tokenPreview(result.token),
							tenant: result.tenantSlug,
						},
						globals,
					);
					return;
				}
				if (!token)
					throw new UsageError(
						"A token is required in non-interactive mode.",
						"Use `cyberzen auth login --token czk_…`.",
					);
				if (!/^(czk_|msk_)/.test(token))
					throw new UsageError("Token must start with czk_ or msk_.");
				// Validate before persisting. A one-item findings request is the least
				// surprising authenticated endpoint and does not mutate server state.
				await api({
					path: "/api/findings",
					query: { limit: 1 },
					token,
					timeout: globals.timeout,
				});
				saveToken(token, {
					tenantSlug: options.tenant ?? globals.tenant,
					email: options.email,
				});
				render(
					{
						authenticated: true,
						token: tokenPreview(token),
						tenant: options.tenant ?? globals.tenant,
					},
					globals,
				);
			},
		);

	auth
		.command("whoami")
		.description("Show the currently stored credential")
		.action(async (_options: unknown, command: Command) => {
			const globals = globalsOf(command);
			const token = getToken(globals);
			if (!token) throw new AuthError();
			const stored = readAuth();
			render(
				{
					authenticated: true,
					token: tokenPreview(token),
					tenant: globals.tenant ?? stored?.tenantSlug,
					email: stored?.email,
					source: globals.token ? "flag-or-environment" : "stored-auth",
				},
				globals,
			);
		});

	auth
		.command("logout")
		.description("Remove the locally stored credential")
		.action(() => {
			const removed = deleteAuth();
			render({ loggedOut: true, removed });
		});
}
