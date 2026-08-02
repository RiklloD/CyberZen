import { afterEach, describe, expect, mock, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { deviceLogin } from './auth'
import { readAuth } from './config'

const originalFetch = globalThis.fetch
const tempDir = `${process.cwd()}/.tmp-device-auth-test`

afterEach(() => {
  globalThis.fetch = originalFetch
  delete process.env.CYBERZEN_CONFIG_DIR
  rmSync(tempDir, { recursive: true, force: true })
})

describe('device login', () => {
  test('starts, polls, and persists the authorized token', async () => {
    process.env.CYBERZEN_CONFIG_DIR = tempDir
    let calls = 0
    globalThis.fetch = mock(async (_input: string | URL, init?: RequestInit) => {
      calls += 1
      if (calls === 1) {
        return new Response(JSON.stringify({
          deviceCode: 'device-1',
          userCode: 'ABCD-2345',
          verificationUrl: 'https://example.test/cli/device?code=ABCD-2345',
          expiresIn: 60,
          interval: 0,
        }), { status: 200 })
      }
      expect(init?.body).toBe(JSON.stringify({ deviceCode: 'device-1' }))
      return new Response(JSON.stringify({ status: 'authorized', token: 'czk_test.secret', tenantSlug: 'acme' }), { status: 200 })
    }) as unknown as typeof fetch

    const result = await deviceLogin({ baseUrl: 'https://example.test', openBrowser: false })
    expect(result).toEqual({ token: 'czk_test.secret', tenantSlug: 'acme' })
    expect(readAuth()).toMatchObject({ token: 'czk_test.secret', tenantSlug: 'acme' })
    expect(calls).toBe(2)
  })

  test('fails clearly when the device is denied', async () => {
    let calls = 0
    globalThis.fetch = mock(async () => {
      calls += 1
      if (calls === 1) {
        return new Response(JSON.stringify({
          deviceCode: 'device-1', userCode: 'ABCD-2345', verificationUrl: 'https://example.test', expiresIn: 60, interval: 0,
        }), { status: 200 })
      }
      return new Response(JSON.stringify({ status: 'denied' }), { status: 200 })
    }) as unknown as typeof fetch
    await expect(deviceLogin({ baseUrl: 'https://example.test', openBrowser: false })).rejects.toMatchObject({ exitCode: 2 })
  })
})
