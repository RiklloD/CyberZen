# Auth Readiness Review

**Date**: 2026-05-16  
**Reviewer**: Automated audit (§7.5)  
**Scope**: `apps/web/convex/auth.ts`, `apps/web/convex/auth.config.ts`  
**Convex Auth version**: 0.0.92 (pre-1.0)

---

## Current State

### `auth.ts`

```ts
import { Password } from '@convex-dev/auth/providers/Password'
import { convexAuth } from '@convex-dev/auth/server'

export const { auth, signIn, signOut, store, isAuthenticated } = convexAuth({
  providers: [Password],
})
```

- Single provider: **Password** only.
- Exports the standard Convex Auth surface: `auth`, `signIn`, `signOut`, `store`, `isAuthenticated`.
- No custom sign-in / sign-up flows configured.
- No MFA / TOTP integration.
- No OAuth providers (GitHub, Google, etc.) enabled.

### `auth.config.ts`

```ts
export default {
  providers: [
    {
      domain: process.env.CONVEX_SITE_URL,
      applicationID: 'convex',
    },
  ],
}
```

- Minimal JWT/session configuration referencing the Convex site URL.
- No custom claims, no role injection, no audience validation beyond defaults.

---

## Findings

### 1. Single-Factor Auth Only (Risk: HIGH)

The platform uses password-only authentication with no second factor. For a security product handling vulnerability data, blast-radius graphs, and compliance evidence, this is a gap.

**Recommendation**:  
- Add TOTP-based 2FA (see §6.27 — `apps/web/convex/twoFactor.ts` is already planned).  
- Enforce 2FA for admin/owner roles at minimum.

### 2. No OAuth / SSO (Risk: MEDIUM)

No social login or enterprise SSO is configured. Enterprise customers (the target market per §8.1 Enterprise tier) will expect SAML/OIDC.

**Recommendation**:  
- Add GitHub OAuth as a provider (lowest friction for developer users).  
- Plan SAML bridge for Enterprise tier (see §6.26).  
- Convex Auth supports `@convex-dev/auth/providers/GitHub` out of the box.

### 3. Session Management (Risk: LOW)

Convex Auth uses JWT-based sessions by default. Session refresh and expiry are handled by the Convex platform but are opaque to the application layer.

**Recommendation**:  
- Verify session TTL defaults are appropriate (Convex default: ~1 hour access token, ~30 day refresh).  
- Add explicit session revocation endpoint for admin-initiated logout (e.g., when removing a team member).

### 4. Password Policy (Risk: MEDIUM)

No password complexity requirements are visible in the auth configuration. The `Password` provider uses Convex Auth defaults.

**Recommendation**:  
- Enforce minimum 12-character passwords.  
- Add breach-check (HaveIBeenPwned k-anonymity API) on sign-up.  
- These can be layered via Convex Auth's `validate` hook on the Password provider.

### 5. Pre-1.0 API Surface (Risk: MEDIUM)

Convex Auth 0.0.92 is pre-1.0. Breaking API changes are possible. The current usage is minimal (5 exports) which limits migration surface.

**Recommendation**:  
- Pin the exact version in `package.json`.  
- Monitor Convex Auth changelog for 1.0 GA.  
- Expected migration: likely minimal (function signature tweaks, not architectural).

### 6. No CSRF Protection Visibility (Risk: LOW)

Convex Auth handles CSRF internally via same-site cookies. No explicit CSRF token management is needed, but this should be verified after any Convex platform upgrade.

### 7. Tenant Scoping (Risk: MEDIUM)

Auth is global — no per-tenant isolation at the auth layer. Tenant membership is enforced at the query/mutation level (via `tenantId` lookups).

**Recommendation**:  
- This is acceptable for the current multi-tenant model.  
- Consider adding a `tenantId` claim to the JWT for faster lookups if performance becomes a concern.  
- Ensure every query that reads tenant-scoped data verifies membership (audit pattern already exists in workspace-scoped queries).

---

## Upgrade Path to 1.0

1. **Pin dependencies**: `@convex-dev/auth@0.0.92` in `package.json`.
2. **Monitor**: Watch `convex-dev/auth` GitHub releases and CHANGELOG.
3. **Expected changes**: Provider configuration API may stabilize; `auth.config.ts` format may change.
4. **Migration window**: Low risk — only 2 files to update, no custom provider logic.
5. **Blocking issues**: None identified. The current API surface is stable enough for production use.

---

## Checklist for Production Readiness

- [x] Password auth working
- [ ] 2FA / TOTP enforcement (§6.27)
- [ ] OAuth provider (GitHub) for developer UX
- [ ] SAML/OIDC for Enterprise tier (§6.26)
- [ ] Password complexity policy
- [ ] Session revocation on member removal
- [ ] Rate limiting on sign-in endpoint
- [ ] Audit logging for auth events (sign-in, sign-out, password change)
- [ ] Pin Convex Auth version
- [ ] Verify CSRF handling after platform upgrades

---

## Conclusion

The auth layer is **functional but minimal**. It is sufficient for development and early beta but requires 2FA enforcement, at least one OAuth provider, and explicit password policies before production GA. The pre-1.0 Convex Auth dependency is low-risk due to minimal API surface usage. No blocking issues found.
