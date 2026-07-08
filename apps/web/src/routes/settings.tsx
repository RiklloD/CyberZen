import { createFileRoute, Outlet } from "@tanstack/react-router";
import SettingsLayout from "../components/SettingsLayout";
import RouteErrorBoundary from "../components/RouteErrorBoundary";

/**
 * Layout route for all /settings/* pages.
 *
 * Renders the settings sub-navigation sidebar and wraps every
 * settings sub-page inside SettingsLayout.
 */
export const Route = createFileRoute("/settings")({
	errorComponent: RouteErrorBoundary,
	component: SettingsLayoutRoute,
});

function SettingsLayoutRoute() {
	return (
		<SettingsLayout>
			<Outlet />
		</SettingsLayout>
	);
}
