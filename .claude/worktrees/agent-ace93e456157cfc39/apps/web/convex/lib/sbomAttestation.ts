// WS-40 — SBOM Attestation: pure computation library.
//
// Generates and verifies integrity attestations for SBOM snapshots.
//
// An attestation proves:
//   1. The SBOM was captured at a specific point in time.
//   2. The component list has not changed since it was attested.
//   3. The proof is tenant-scoped — cross-tenant collisions are impossible.
//
// Implementation strategy:
//   Canonical component data → SHA-256 content hash.
//   Content hash + tenantSlug + snapshotId → SHA-256 attestation hash.
//   Storing the attestation hash at ingest time lets any future re-hash
//   of the same snapshot detect tampering.
//
// SHA-256 is implemented in pure JavaScript (FIPS 180-4) so this module
// works identically in Convex mutations (synchronous, no crypto.subtle),
// Vitest tests, and any other JS runtime.
//
// Zero network calls. Zero Convex imports. Safe to use in tests without mocking.

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AttestationStatus =
  | 'valid'         // re-computed hash matches the stored attestation hash
  | 'tampered'      // re-computed hash differs — component list was altered
  | 'unverified'    // attestation exists but has not yet been re-verified

export type SbomComponent = {
  name: string
  version: string
  ecosystem: string
}

export type AttestationRecord = {
  snapshotId: string
  tenantSlug: string
  /** SHA-256 of the canonical component data alone (tenant-independent). */
  contentHash: string
  /** SHA-256 of (contentHash + ':' + tenantSlug + ':' + snapshotId + ':' + capturedAt). */
  attestationHash: string
  componentCount: number
  capturedAt: number
  attestedAt: number
  /** Library version — increment when the canonicalization algorithm changes. */
  attestationVersion: number
}

export type VerificationResult = {
  status: AttestationStatus
  storedHash: string
  recomputedHash: string
  /** True when storedHash === recomputedHash. */
  integrityOk: boolean
  verifiedAt: number
}

// ---------------------------------------------------------------------------
// SHA-256 (pure JS — FIPS 180-4)
// ---------------------------------------------------------------------------

/** Round constants (first 32 bits of fractional parts of cube roots of primes). */
const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
])

function rotr32(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0
}

/**
 * Compute SHA-256 of a UTF-8 string and return the lowercase hex digest.
 * Pure JavaScript — no Web Crypto API, no Node.js `crypto` module.
 */
export function sha256Hex(message: string): string {
  // Encode as UTF-8 bytes.
  const encoder = new TextEncoder()
  const msg = encoder.encode(message)
  const msgLen = msg.length

  // Pad: append 0x80, zeros, then 64-bit big-endian bit length.
  const paddedLen = Math.ceil((msgLen + 9) / 64) * 64
  const padded = new Uint8Array(paddedLen)
  padded.set(msg)
  padded[msgLen] = 0x80
  // Bit-length as big-endian 64-bit (we only write the lower 32 bits —
  // sufficient for messages up to ~512 MB).
  const bitLen = msgLen * 8
  padded[paddedLen - 4] = (bitLen >>> 24) & 0xff
  padded[paddedLen - 3] = (bitLen >>> 16) & 0xff
  padded[paddedLen - 2] = (bitLen >>> 8) & 0xff
  padded[paddedLen - 1] = bitLen & 0xff

  // Initial hash values (first 32 bits of fractional parts of sqrt of first 8 primes).
  let h0 = 0x6a09e667
  let h1 = 0xbb67ae85
  let h2 = 0x3c6ef372
  let h3 = 0xa54ff53a
  let h4 = 0x510e527f
  let h5 = 0x9b05688c
  let h6 = 0x1f83d9ab
  let h7 = 0x5be0cd19

  const w = new Uint32Array(64)

  for (let i = 0; i < paddedLen; i += 64) {
    // Load message block into schedule.
    for (let j = 0; j < 16; j++) {
      const off = i + j * 4
      w[j] =
        (padded[off] << 24) |
        (padded[off + 1] << 16) |
        (padded[off + 2] << 8) |
        padded[off + 3]
    }
    // Extend schedule.
    for (let j = 16; j < 64; j++) {
      const s0 =
        rotr32(w[j - 15], 7) ^ rotr32(w[j - 15], 18) ^ (w[j - 15] >>> 3)
      const s1 =
        rotr32(w[j - 2], 17) ^ rotr32(w[j - 2], 19) ^ (w[j - 2] >>> 10)
      w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0
    }

    // Working variables.
    let a = h0
    let b = h1
    let c = h2
    let d = h3
    let e = h4
    let f = h5
    let g = h6
    let h = h7

    // 64 compression rounds.
    for (let j = 0; j < 64; j++) {
      const S1 = (rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)) >>> 0
      const ch = ((e & f) ^ (~e & g)) >>> 0
      const temp1 = (h + S1 + ch + SHA256_K[j] + w[j]) >>> 0
      const S0 = (rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)) >>> 0
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0
      const temp2 = (S0 + maj) >>> 0

      h = g
      g = f
      f = e
      e = (d + temp1) >>> 0
      d = c
      c = b
      b = a
      a = (temp1 + temp2) >>> 0
    }

    h0 = (h0 + a) >>> 0
    h1 = (h1 + b) >>> 0
    h2 = (h2 + c) >>> 0
    h3 = (h3 + d) >>> 0
    h4 = (h4 + e) >>> 0
    h5 = (h5 + f) >>> 0
    h6 = (h6 + g) >>> 0
    h7 = (h7 + h) >>> 0
  }

  return [h0, h1, h2, h3, h4, h5, h6, h7]
    .map((n) => (n >>> 0).toString(16).padStart(8, '0'))
    .join('')
}

// ---------------------------------------------------------------------------
// Canonicalization
// ---------------------------------------------------------------------------

/**
 * Convert a component list to a deterministic canonical string suitable
 * for hashing.
 *
 * Canonicalization rules:
 *   1. Each component is represented as `ecosystem:name@version`.
 *   2. Components are sorted lexicographically so insertion order doesn't
 *      affect the hash.
 *   3. Duplicates are deduplicated before sorting.
 *   4. The final string is newline-joined with a known prefix.
 *
 * Version 1 of this format — bump `ATTESTATION_VERSION` if it ever changes.
 */
export const ATTESTATION_VERSION = 1

export function canonicalizeSbomComponents(components: SbomComponent[]): string {
  const seen = new Set<string>()
  const entries: string[] = []

  for (const c of components) {
    const entry = `${c.ecosystem.toLowerCase()}:${c.name.toLowerCase()}@${c.version}`
    if (!seen.has(entry)) {
      seen.add(entry)
      entries.push(entry)
    }
  }

  entries.sort()
  return `sentinel-sbom-v${ATTESTATION_VERSION}\n${entries.join('\n')}`
}

// ---------------------------------------------------------------------------
// Content hash
// ---------------------------------------------------------------------------

/**
 * Compute the SHA-256 content hash of the canonicalized SBOM components.
 * This hash is independent of tenant — it represents the SBOM content alone.
 */
export function computeContentHash(components: SbomComponent[]): string {
  return sha256Hex(canonicalizeSbomComponents(components))
}

// ---------------------------------------------------------------------------
// Attestation hash (tenant-scoped)
// ---------------------------------------------------------------------------

/**
 * Compute the attestation hash: SHA-256 of the canonical content combined
 * with the tenant slug, snapshot ID, and capture timestamp.
 *
 * This binds the content hash to a specific:
 *   • tenant (prevents cross-tenant hash reuse)
 *   • snapshot (ties the attestation to a point in time)
 *   • capture timestamp (prevents replay of an identical component list from a different date)
 */
export function computeAttestationHash(
  contentHash: string,
  tenantSlug: string,
  snapshotId: string,
  capturedAt: number,
): string {
  const attestationInput = [contentHash, tenantSlug, snapshotId, String(capturedAt)].join(':')
  return sha256Hex(attestationInput)
}

// ---------------------------------------------------------------------------
// generateSbomAttestation
// ---------------------------------------------------------------------------

/**
 * Generate a full attestation record for an SBOM snapshot.
 * Should be called immediately after an SBOM snapshot is written to the DB.
 */
export function generateSbomAttestation(
  snapshotId: string,
  components: SbomComponent[],
  tenantSlug: string,
  capturedAt: number,
  nowMs?: number,
): AttestationRecord {
  const contentHash = computeContentHash(components)
  const attestationHash = computeAttestationHash(
    contentHash,
    tenantSlug,
    snapshotId,
    capturedAt,
  )

  return {
    snapshotId,
    tenantSlug,
    contentHash,
    attestationHash,
    componentCount: new Set(
      components.map((c) => `${c.ecosystem}:${c.name}@${c.version}`),
    ).size,
    capturedAt,
    attestedAt: nowMs ?? Date.now(),
    attestationVersion: ATTESTATION_VERSION,
  }
}

// ---------------------------------------------------------------------------
// verifyAttestation
// ---------------------------------------------------------------------------

/**
 * Re-compute the attestation hash for the current component list and compare
 * it against the stored hash.
 *
 * Returns:
 *   'valid'    — hashes match; the SBOM has not been tampered with.
 *   'tampered' — hashes differ; the component list has changed since attest time.
 */
export function verifyAttestation(
  components: SbomComponent[],
  tenantSlug: string,
  snapshotId: string,
  capturedAt: number,
  storedAttestationHash: string,
  nowMs?: number,
): VerificationResult {
  const contentHash = computeContentHash(components)
  const recomputedHash = computeAttestationHash(
    contentHash,
    tenantSlug,
    snapshotId,
    capturedAt,
  )
  const integrityOk = recomputedHash === storedAttestationHash

  return {
    status: integrityOk ? 'valid' : 'tampered',
    storedHash: storedAttestationHash,
    recomputedHash,
    integrityOk,
    verifiedAt: nowMs ?? Date.now(),
  }
}
