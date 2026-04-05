import { createEnv } from "@t3-oss/env-core";
import { z } from "zod";

export const env = createEnv({
	server: {
		SERVER_URL: z.string().url().optional(),
	},

	clientPrefix: "VITE_",

	client: {
		VITE_APP_TITLE: z.string().min(1).default("CyberZen"),
		VITE_CONVEX_URL: z.string().url().optional(),
		VITE_POSTHOG_KEY: z.string().min(1).optional(),
		VITE_POSTHOG_HOST: z.string().url().default("https://us.i.posthog.com"),
	},

	runtimeEnv: import.meta.env,

	emptyStringAsUndefined: true,
});
