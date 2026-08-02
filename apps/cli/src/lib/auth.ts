import { AuthError } from './errors'
import { readAuth, writeAuth, type AuthFile } from './config'

export interface TokenOptions {
  token?: string
  profile?: string
}

/** Resolve credentials without ever printing the secret. */
export function getToken(options: TokenOptions = {}): string | null {
  if (options.token) return options.token
  if (process.env.CYBERZEN_API_KEY) return process.env.CYBERZEN_API_KEY
  const stored = readAuth()
  if (!stored) return null
  if (options.profile && stored.profiles?.[options.profile]) {
    return stored.profiles[options.profile]?.token ?? null
  }
  return stored.token
}

export function requireToken(options: TokenOptions = {}): string {
  const token = getToken(options)
  if (!token) throw new AuthError()
  return token
}

export function saveToken(token: string, metadata: Omit<Partial<AuthFile>, 'token' | 'createdAt'> = {}): void {
  writeAuth({ token, createdAt: Date.now(), ...metadata })
}

export function tokenPreview(token: string): string {
  if (token.length <= 8) return '********'
  return `${token.slice(0, 4)}…${token.slice(-4)}`
}
