import { useAuth } from "@clerk/tanstack-react-start";

/**
 * Compatibility hook — returns an empty string.
 * With Clerk + ConvexProviderWithClerk, the auth token is attached
 * automatically to every Convex request. The `authToken` parameter
 * in backend functions is kept for backwards compatibility but is
 * now optional and ignored.
 */
export function useAuthToken(): string {
	return "";
}

export function useAuthActions() {
	return { signIn: async () => {}, signOut: async () => {} };
}
