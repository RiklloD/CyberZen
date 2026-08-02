import type { Command } from "commander";

/**
 * Central command registry. Each feature group lives in its own module and
 * exports a `registerX(program)` function. Groups are added here as they are
 * implemented (see docs/plans/2026-08-02-cyberzen-cli.md).
 */
import { registerAuth } from "./auth";
import { registerDrift } from "./drift";
import { registerFindings } from "./findings";
import { registerLink } from "./link";
import { registerOperations } from "./operations";
import { registerRepos } from "./repos";
import { registerSbom } from "./sbom";
import { registerStatus, registerSystem } from "./system";
import { registerTenants } from "./tenants";

export function registerAll(program: Command): void {
	registerAuth(program);
	registerTenants(program);
	registerLink(program);
	registerFindings(program);
	registerRepos(program);
	registerSbom(program);
	registerDrift(program);
	registerOperations(program);
	registerSystem(program);
	registerStatus(program);
}
