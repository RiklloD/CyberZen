import { chmodSync, existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs'
import { homedir, platform } from 'node:os'
import { join } from 'node:path'

/**
 * Persistent CLI state, Vercel/Convex style.
 *
 * Global config dir:
 *   Windows: %APPDATA%/cyberzen
 *   POSIX:   ~/.config/cyberzen
 *   override: CYBERZEN_CONFIG_DIR
 *
 * Files:
 *   auth.json   — credentials (chmod 600)
 *   config.json — non-secret settings
 *
 * Per-directory linkage (.cyberzen/project.json) lives in project.ts.
 */

export interface AuthFile {
  token: string
  tenantSlug?: string
  email?: string
  createdAt: number
  /** Named profiles for multi-tenant / multi-env users. */
  profiles?: Record<string, Omit<AuthFile, 'profiles'>>
}

export interface ConfigFile {
  apiUrl?: string
  siteUrl?: string
  tenant?: string
  telemetry?: boolean
  output?: 'table' | 'json'
}

export const DEFAULT_API_URL = 'https://animated-viper-811.eu-west-1.convex.cloud'
export const DEFAULT_SITE_URL = 'https://animated-viper-811.eu-west-1.convex.site'

export function configDir(): string {
  if (process.env.CYBERZEN_CONFIG_DIR) return process.env.CYBERZEN_CONFIG_DIR
  if (platform() === 'win32') {
    const appData = process.env.APPDATA ?? join(homedir(), 'AppData', 'Roaming')
    return join(appData, 'cyberzen')
  }
  const xdg = process.env.XDG_CONFIG_HOME ?? join(homedir(), '.config')
  return join(xdg, 'cyberzen')
}

export function authPath(): string {
  return join(configDir(), 'auth.json')
}

export function configPath(): string {
  return join(configDir(), 'config.json')
}

function readJson<T>(path: string): T | null {
  if (!existsSync(path)) return null
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as T
  } catch {
    return null
  }
}

function writeJson(path: string, value: unknown, secret: boolean): void {
  mkdirSync(configDir(), { recursive: true })
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, 'utf8')
  if (secret) {
    try {
      chmodSync(path, 0o600)
    } catch {
      // Windows: POSIX perms are best-effort.
    }
  }
}

export function readAuth(): AuthFile | null {
  return readJson<AuthFile>(authPath())
}

export function writeAuth(auth: AuthFile): void {
  writeJson(authPath(), auth, true)
}

export function deleteAuth(): boolean {
  if (!existsSync(authPath())) return false
  try {
    unlinkSync(authPath())
    return true
  } catch {
    return false
  }
}

export function readConfig(): ConfigFile {
  return readJson<ConfigFile>(configPath()) ?? {}
}

export function writeConfig(config: ConfigFile): void {
  writeJson(configPath(), config, false)
}

/** Resolve the Convex cloud (client) URL. */
export function apiUrl(override?: string): string {
  return override ?? process.env.CYBERZEN_API_URL ?? readConfig().apiUrl ?? DEFAULT_API_URL
}

/** Resolve the Convex HTTP Actions (site) URL. */
export function siteUrl(override?: string): string {
  return override ?? process.env.CYBERZEN_SITE_URL ?? readConfig().siteUrl ?? DEFAULT_SITE_URL
}
