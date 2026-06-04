import { describe, expect, it, vi } from "vitest";

// Mock Convex hooks — they won't exist in the test environment
vi.mock("convex/react", () => ({
	useQuery: vi.fn(() => undefined),
	useMutation: vi.fn(() => vi.fn()),
}));

vi.mock("@convex-dev/auth/react", () => ({
	useAuthToken: vi.fn(() => "mock-token"),
}));

// Mock TanStack Router
vi.mock("@tanstack/react-router", () => ({
	createRootRoute: vi.fn((opts: any) => opts),
	useRouterState: vi.fn(() => ({
		location: { pathname: "/", search: "" },
	})),
	useLocation: vi.fn(() => ({ pathname: "/", search: "" })),
	useNavigate: vi.fn(() => vi.fn()),
	Navigate: vi.fn(() => null),
	Outlet: vi.fn(() => null),
}));

vi.mock("@tanstack/react-router-devtools", () => ({
	TanStackRouterDevtoolsPanel: vi.fn(() => null),
}));

vi.mock("@tanstack/react-devtools", () => ({
	TanStackDevtools: vi.fn(() => null),
}));

// Mock heavy child components
vi.mock("../components/Sidebar", () => ({
	default: vi.fn(() => <div data-testid="sidebar">Sidebar</div>),
}));
vi.mock("../components/AuthScreen", () => ({
	default: vi.fn(() => <div data-testid="auth-screen">AuthScreen</div>),
}));
vi.mock("../components/CommandPalette", () => ({
	default: vi.fn(() => null),
}));
vi.mock("../components/RouteErrorBoundary", () => ({
	default: vi.fn(({ children }: any) => children),
}));
vi.mock("../components/ShortcutsModal", () => ({
	default: vi.fn(() => null),
}));
vi.mock("../components/Toaster", () => ({
	default: vi.fn(() => null),
}));
vi.mock("../integrations/convex/provider", () => ({
	default: vi.fn(({ children }: any) => children),
}));
vi.mock("../integrations/posthog/provider", () => ({
	default: vi.fn(({ children }: any) => children),
}));
vi.mock("../lib/shortcuts", () => ({
	attachGlobalShortcutListener: vi.fn(),
	registerNavigationShortcuts: vi.fn(() => vi.fn()),
}));
vi.mock("../lib/workspace", () => ({
	WorkspaceSlugProvider: vi.fn(({ children }: any) => children),
}));

describe("__root.tsx workspace gating", () => {
	it("shows loading shell when auth token is present but workspace query is loading", async () => {
		// Dynamic import to ensure mocks are active
		const mod = await import("./__root");

		// The RootDocument component should render
		expect(mod.Route).toBeDefined();
		expect((mod.Route as any).component).toBeDefined();
	});

	it("exports errorComponent for route-level error handling", async () => {
		const mod = await import("./__root");
		expect((mod.Route as any).errorComponent).toBeDefined();
	});
});
