import { TanStackDevtools } from "@tanstack/react-devtools";
import { createRootRoute, Outlet } from "@tanstack/react-router";
import { TanStackRouterDevtoolsPanel } from "@tanstack/react-router-devtools";
import Sidebar from "../components/Sidebar";
import ConvexProvider from "../integrations/convex/provider";
import PostHogProvider from "../integrations/posthog/provider";

export const Route = createRootRoute({
	component: RootDocument,
});

function RootDocument() {
	return (
		<ConvexProvider>
			<PostHogProvider>
				<div className="app-shell">
					<Sidebar />
					<div className="app-content">
						<Outlet />
					</div>
				</div>
				{import.meta.env.DEV && (
					<TanStackDevtools
						config={{ position: "bottom-right" }}
						plugins={[
							{
								name: "Tanstack Router",
								render: <TanStackRouterDevtoolsPanel />,
							},
						]}
					/>
				)}
			</PostHogProvider>
		</ConvexProvider>
	);
}
