import { useAuth } from "@clerk/tanstack-react-start";

/**
 * Compatibility hook — returns an empty string.
 * With Clerk + ConvexProviderWithClerk, the auth token is attached
 * automatically to every Convex request. The `authToken` parameter
 * in backend functions is kept for backwards compatibility but is
 * now optional and ignored.
 */
export function useAuthToken(): string {
	const { getToken } = useAuth();
	// getToken is available if callers need the raw Clerk JWT,
	// but for Convex calls it's no longer needed.
	return "";
}

export function useAuthActions() {
	return { signIn: async () => {}, signOut: async () => {} };
}
