#!/usr/bin/env node
import { Command } from 'commander'
import { applyGlobalFlags } from './lib/globalFlags.js'
import { handleError } from './lib/errors.js'
import { registerAll } from './commands/index.js'

const program = new Command()
  .name('cyberzen')
  .description('CyberZen — security operations from the terminal')
  .version(process.env.CYBERZEN_CLI_VERSION ?? '0.1.0', '-v, --version', 'Print the CLI version')

applyGlobalFlags(program)
registerAll(program)

program.exitOverride()
try {
  await program.parseAsync(process.argv)
} catch (err) {
  handleError(err)
}
