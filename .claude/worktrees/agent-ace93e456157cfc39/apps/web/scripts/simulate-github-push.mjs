/**
 * Simulate a GitHub push webhook against the Convex HTTP endpoint.
 *
 * Usage:
 *   bun scripts/simulate-github-push.mjs \
 *     --url  https://quick-echidna-102.eu-west-1.convex.site/webhooks/github \
 *     --secret <GITHUB_WEBHOOK_SECRET> \
 *     [--repo  atlas-fintech/payments-api] \
 *     [--branch main] \
 *     [--commit abc123def456] \
 *     [--files services/auth/jwt.py,requirements.txt]
 *
 * The script builds a minimal valid GitHub push payload, signs it with
 * HMAC-SHA256, and POSTs it to the target URL. It then prints the full
 * response so you can verify the Convex webhook path end-to-end without
 * needing a real GitHub repository webhook configured.
 */

import { createHmac } from "node:crypto";

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

function parseArgs(argv) {
	const flags = new Map();

	for (let i = 0; i < argv.length; i += 1) {
		const current = argv[i];

		if (!current.startsWith("--")) {
			throw new Error(`Unexpected positional argument: ${current}`);
		}

		const next = argv[i + 1];

		if (current === "--files") {
			// --files is optional and can be absent (no next token)
			if (!next || next.startsWith("--")) {
				flags.set("files", "");
				continue;
			}
		}

		if (!next || next.startsWith("--")) {
			throw new Error(`Missing value for ${current}`);
		}

		flags.set(current.slice(2), next);
		i += 1;
	}

	return {
		url: flags.get("url"),
		secret: flags.get("secret"),
		repo: flags.get("repo") ?? "atlas-fintech/payments-api",
		branch: flags.get("branch") ?? "main",
		commit: flags.get("commit") ?? randomHex(40),
		files: (flags.get("files") ?? "requirements.txt,services/auth/jwt.py")
			.split(",")
			.map((f) => f.trim())
			.filter(Boolean),
	};
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function randomHex(length) {
	let out = "";
	const chars = "0123456789abcdef";
	for (let i = 0; i < length; i++) {
		out += chars[Math.floor(Math.random() * chars.length)];
	}
	return out;
}

function signPayload(secret, body) {
	const sig = createHmac("sha256", secret).update(body).digest("hex");
	return `sha256=${sig}`;
}

function buildPushPayload(opts) {
	const [owner, repoName] = opts.repo.split("/");
	const now = new Date().toISOString();

	return {
		ref: `refs/heads/${opts.branch}`,
		before: randomHex(40),
		after: opts.commit,
		repository: {
			id: 123456789,
			name: repoName,
			full_name: opts.repo,
			owner: {
				name: owner,
				login: owner,
			},
			default_branch: opts.branch,
			private: true,
		},
		pusher: {
			name: "sentinel-sim",
			email: "sentinel-sim@example.com",
		},
		commits: [
			{
				id: opts.commit,
				message: "chore: simulated push from sentinel webhook simulator",
				timestamp: now,
				url: `https://github.com/${opts.repo}/commit/${opts.commit}`,
				author: {
					name: "Sentinel Simulator",
					email: "sentinel-sim@example.com",
					username: "sentinel-sim",
				},
				added: [],
				removed: [],
				modified: opts.files,
			},
		],
		head_commit: {
			id: opts.commit,
			message: "chore: simulated push from sentinel webhook simulator",
			timestamp: now,
			url: `https://github.com/${opts.repo}/commit/${opts.commit}`,
			author: {
				name: "Sentinel Simulator",
				email: "sentinel-sim@example.com",
				username: "sentinel-sim",
			},
			added: [],
			removed: [],
			modified: opts.files,
		},
	};
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
	const args = parseArgs(process.argv.slice(2));

	if (!args.url) {
		console.error(
			"Error: --url is required.\n" +
				"  Example: --url https://quick-echidna-102.eu-west-1.convex.site/webhooks/github",
		);
		process.exit(1);
	}

	if (!args.secret) {
		console.error(
			"Error: --secret is required.\n" +
				"  This must match the GITHUB_WEBHOOK_SECRET set in your Convex deployment.",
		);
		process.exit(1);
	}

	const payload = buildPushPayload(args);
	const body = JSON.stringify(payload, null, 2);
	const signature = signPayload(args.secret, body);
	const deliveryId = randomHex(16);

	console.log("=== Sentinel GitHub Push Webhook Simulator ===\n");
	console.log("Target:    ", args.url);
	console.log("Delivery:  ", deliveryId);
	console.log("Repository:", args.repo);
	console.log("Branch:    ", args.branch);
	console.log("Commit:    ", args.commit);
	console.log("Files:     ", args.files.join(", "));
	console.log("Signature: ", signature);
	console.log("");

	let response;
	try {
		response = await fetch(args.url, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"X-GitHub-Event": "push",
				"X-GitHub-Delivery": deliveryId,
				"X-Hub-Signature-256": signature,
				"User-Agent": "GitHub-Hookshot/sentinel-sim",
			},
			body,
		});
	} catch (err) {
		console.error("Network error:", err.message);
		process.exit(1);
	}

	let responseText;
	try {
		responseText = await response.text();
	} catch {
		responseText = "(could not read response body)";
	}

	console.log("=== Response ===");
	console.log("Status:", response.status, response.statusText);

	try {
		const parsed = JSON.parse(responseText);
		console.log(JSON.stringify(parsed, null, 2));
	} catch {
		console.log(responseText);
	}

	if (response.ok) {
		console.log("\n✓ Webhook delivery accepted.");
	} else {
		console.error("\n✗ Webhook delivery rejected — check the output above.");
		process.exit(1);
	}
}

await main();
