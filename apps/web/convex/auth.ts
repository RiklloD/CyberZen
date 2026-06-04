import { Password } from '@convex-dev/auth/providers/Password'
import GitHub from '@auth/core/providers/github'
import { convexAuth } from '@convex-dev/auth/server'

export const { auth, signIn, signOut, store, isAuthenticated } = convexAuth({
  providers: [Password, GitHub],
})
