import type { Command } from "commander";
import { cliApi } from "../lib/api";
import { globalsOf } from "../lib/globalFlags";
import { render } from "../lib/output";

export function registerSettings(program: Command): void {
	const settings = program
		.command("settings")
		.description("Tenant settings: 2FA, IP allowlist, retention, SSO");

	const twoFactor = settings
		.command("2fa")
		.description("Two-factor authentication for the API key owner");

	twoFactor
		.command("status")
		.description("Show 2FA enrollment status")
		.action(async (_options: unknown, command: Command) => {
			const globals = globalsOf(command);
			render(
				await cliApi({
					path: "settings/two-factor/status",
					timeout: globals.timeout,
				}),
				globals,
			);
		});

	twoFactor
		.command("enroll")
		.description(
			"Start TOTP enrollment; prints secret, otpauth URI, and backup codes",
		)
		.action(async (_options: unknown, command: Command) => {
			const globals = globalsOf(command);
			render(
				await cliApi({
					path: "settings/two-factor/enroll",
					method: "POST",
					timeout: globals.timeout,
				}),
				globals,
			);
		});

	twoFactor
		.command("verify <code>")
		.description("Complete enrollment with a 6-digit TOTP code")
		.action(async (code: string, _options: unknown, command: Command) => {
			const globals = globalsOf(command);
			render(
				await cliApi({
					path: "settings/two-factor/verify",
					method: "POST",
					body: { code },
					timeout: globals.timeout,
				}),
				globals,
			);
		});

	twoFactor
		.command("disable <code>")
		.description("Disable 2FA with a current TOTP code")
		.action(async (code: string, _options: unknown, command: Command) => {
			const globals = globalsOf(command);
			render(
				await cliApi({
					path: "settings/two-factor/disable",
					method: "POST",
					body: { code },
					timeout: globals.timeout,
				}),
				globals,
			);
		});

	settings
		.command("ip-allowlist")
		.description("Read or update the tenant IP allowlist")
		.option("--set <cidrs>", "Comma-separated CIDRs to set (replaces the list)")
		.action(async (options: { set?: string }, command: Command) => {
			const globals = globalsOf(command);
			if (options.set !== undefined) {
				const cidrs = options.set
					.split(",")
					.map((value) => value.trim())
					.filter((value) => value.length > 0);
				render(
					await cliApi({
						path: "settings/ip-allowlist",
						method: "PUT",
						body: { cidrs },
						timeout: globals.timeout,
					}),
					globals,
				);
				return;
			}
			render(
				await cliApi({
					path: "settings/ip-allowlist",
					timeout: globals.timeout,
				}),
				globals,
			);
		});

	settings
		.command("retention")
		.description("Read or update data retention policies")
		.option(
			"--findings <days>",
			"Retention for closed findings",
			Number.parseInt,
		)
		.option(
			"--audit <days>",
			"Retention for audit log entries",
			Number.parseInt,
		)
		.option(
			"--usage <days>",
			"Retention for API usage records",
			Number.parseInt,
		)
		.option(
			"--webhooks <days>",
			"Retention for webhook deliveries",
			Number.parseInt,
		)
		.action(
			async (
				options: {
					findings?: number;
					audit?: number;
					usage?: number;
					webhooks?: number;
				},
				command: Command,
			) => {
				const globals = globalsOf(command);
				const hasUpdate =
					options.findings !== undefined ||
					options.audit !== undefined ||
					options.usage !== undefined ||
					options.webhooks !== undefined;
				if (hasUpdate) {
					const current = (await cliApi({
						path: "settings/retention",
						timeout: globals.timeout,
					})) as {
						findingsDays: number;
						auditLogsDays: number;
						apiUsageRecordsDays: number;
						webhookDeliveriesDays: number;
					};
					render(
						await cliApi({
							path: "settings/retention",
							method: "PUT",
							body: {
								findingsDays: options.findings ?? current.findingsDays,
								auditLogsDays: options.audit ?? current.auditLogsDays,
								apiUsageRecordsDays:
									options.usage ?? current.apiUsageRecordsDays,
								webhookDeliveriesDays:
									options.webhooks ?? current.webhookDeliveriesDays,
							},
							timeout: globals.timeout,
						}),
						globals,
					);
					return;
				}
				render(
					await cliApi({
						path: "settings/retention",
						timeout: globals.timeout,
					}),
					globals,
				);
			},
		);

	settings
		.command("sso")
		.description("List SSO configurations for the tenant")
		.action(async (_options: unknown, command: Command) => {
			const globals = globalsOf(command);
			render(
				await cliApi({ path: "settings/sso", timeout: globals.timeout }),
				globals,
			);
		});
}
