import { useAuthToken } from "../lib/clerk-compat";
import { useQuery } from "convex/react";
import {
	createContext,
	createElement,
	type ReactNode,
	useContext,
} from "react";
import { api } from "#/lib/convex";
import { TENANT_SLUG } from "./config";

const WorkspaceSlugContext = createContext<string | null>(null);

export function WorkspaceSlugProvider({
	slug,
	children,
}: {
	slug: string;
	children: ReactNode;
}) {
	return createElement(
		WorkspaceSlugContext.Provider,
		{ value: slug },
		children,
	);
}

export function useWorkspaceState() {
	const authToken = useAuthToken();
	return useQuery(api.workspaceAuth.currentWorkspace);
}

export function useTenantSlug() {
	const workspaceSlug = useContext(WorkspaceSlugContext);
	return workspaceSlug ?? TENANT_SLUG;
}

export function useWorkspaces() {
	const workspace = useWorkspaceState();
	return workspace?.workspaces ?? [];
}
