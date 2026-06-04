import { ConvexQueryClient } from "@convex-dev/react-query";
import { ConvexProvider } from "convex/react";
import { env } from "#/env";

const convexQueryClient = env.VITE_CONVEX_URL
	? new ConvexQueryClient(env.VITE_CONVEX_URL)
	: null;

export default function AppConvexProvider({
	children,
}: {
	children: React.ReactNode;
}) {
	if (!convexQueryClient) {
		return <>{children}</>;
	}

	return (
		<ConvexProvider client={convexQueryClient.convexClient}>
			{children}
		</ConvexProvider>
	);
}
