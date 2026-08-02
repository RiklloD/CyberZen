import { afterEach, describe, expect, test } from 'bun:test'
import { existsSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import {
  authPath,
  configDir,
  configPath,
  deleteAuth,
  readAuth,
  readConfig,
  writeAuth,
  writeConfig,
} from './config'

const tempDir = `${process.cwd()}/.tmp-config-test`

function withTempConfig(): void {
  process.env.CYBERZEN_CONFIG_DIR = tempDir
  rmSync(tempDir, { recursive: true, force: true })
}

afterEach(() => {
  rmSync(tempDir, { recursive: true, force: true })
  delete process.env.CYBERZEN_CONFIG_DIR
})

describe('config persistence', () => {
  test('uses CYBERZEN_CONFIG_DIR override', () => {
    withTempConfig()
    expect(configDir()).toBe(tempDir)
    expect(authPath()).toBe(join(tempDir, 'auth.json'))
    expect(configPath()).toBe(join(tempDir, 'config.json'))
  })

  test('round-trips auth and config', () => {
    withTempConfig()
    expect(readAuth()).toBeNull()
    writeAuth({ token: 'czk_test', tenantSlug: 'acme', createdAt: 1 })
    writeConfig({ siteUrl: 'https://example.test', output: 'json' })
    expect(readAuth()).toEqual({ token: 'czk_test', tenantSlug: 'acme', createdAt: 1 })
    expect(readConfig()).toEqual({ siteUrl: 'https://example.test', output: 'json' })
  })

  test('deleteAuth removes credentials and reports whether it existed', () => {
    withTempConfig()
    expect(deleteAuth()).toBe(false)
    writeAuth({ token: 'czk_test', createdAt: 1 })
    expect(existsSync(authPath())).toBe(true)
    expect(deleteAuth()).toBe(true)
    expect(readAuth()).toBeNull()
    expect(deleteAuth()).toBe(false)
  })
})
