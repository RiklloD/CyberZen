import { createEnv } from "@t3-oss/env-core";
import { z } from "zod";

export const env = createEnv({
	server: {
		SERVER_URL: z.string().url().optional(),
		CLERK_SECRET_KEY: z.string().min(1).optional(),
	},

	clientPrefix: "VITE_",

	client: {
		VITE_APP_TITLE: z.string().min(1).default("CyberZen"),
		VITE_CONVEX_URL: z.string().url().optional(),
		VITE_POSTHOG_KEY: z.string().min(1).optional(),
		VITE_POSTHOG_HOST: z.string().url().default("https://us.i.posthog.com"),
		VITE_TENANT_SLUG: z.string().min(1),
		VITE_CLERK_PUBLISHABLE_KEY: z.string().min(1).optional(),
	},

	runtimeEnv: import.meta.env,

	emptyStringAsUndefined: true,
});
