import tailwindcss from "@tailwindcss/vite";
import { devtools } from "@tanstack/devtools-vite";
import { TanStackRouterVite } from "@tanstack/router-plugin/vite";
import viteReact from "@vitejs/plugin-react";
import path from "path";
import tsconfigPaths from "vite-tsconfig-paths";
import { defineConfig } from "vitest/config";

const config = defineConfig({
	plugins: [
		TanStackRouterVite({ autoCodeSplitting: true }),
		devtools(),
		tsconfigPaths({ projects: ["./tsconfig.json"] }),
		tailwindcss(),
		viteReact(),
	],
	resolve: {
		alias: {
			// Stub out Node-only modules pulled in by @clerk/tanstack-react-start.
			// In client-only SPA mode (defaultSsr: false) there is no server runtime.
			"node:async_hooks": path.resolve(__dirname, "src/lib/async-hooks-shim.ts"),
			"@tanstack/start-storage-context": path.resolve(__dirname, "src/lib/start-storage-shim.ts"),
		},
	},
	test: {
		environment: "jsdom",
		globals: true,
		include: ["src/**/*.test.{ts,tsx}"],
	},
});

export default config;
