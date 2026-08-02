#!/usr/bin/env bun
/**
 * Build the cyberzen CLI into dist/.
 * `bun build` for the JS entrypoint, prepending a node shebang and making it
 * executable. Kept as a script (not a package.json one-liner) because bun's
 * CLI arg parser mangles an inline `--banner:js '#!/usr/bin/env node'`.
 */
import { $ } from 'bun'
import { chmodSync, readFileSync, writeFileSync } from 'node:fs'

const entry = 'src/index.ts'
const outfile = 'dist/cyberzen.js'

// Bundle everything in so dist/cyberzen.js is self-contained (no node_modules
// needed at runtime). This keeps both the npm `bin` and `bun build --compile`
// single-binary flows working.
await $`bun build ${entry} --outfile ${outfile} --target node --format esm`.quiet()

const built = readFileSync(outfile, 'utf8')
if (!built.startsWith('#!')) {
  writeFileSync(outfile, `#!/usr/bin/env node\n${built}`)
}
try {
  chmodSync(outfile, 0o755)
} catch {
  // Windows: chmod is a no-op / best-effort.
}
console.log(`built ${outfile}`)
