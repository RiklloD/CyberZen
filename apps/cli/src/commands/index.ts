import type { Command } from 'commander'

/**
 * Central command registry. Each feature group lives in its own module and
 * exports a `registerX(program)` function. Groups are added here as they are
 * implemented (see docs/plans/2026-08-02-cyberzen-cli.md).
 */
import { registerAuth } from './auth'
import { registerLink } from './link'

export function registerAll(program: Command): void {
  registerAuth(program)
  registerLink(program)
}
