import { SignIn } from "@clerk/react";
import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/sign-in/$")({
	component: Page });

function Page() {
	return (
		<div
			style={{
				display: "flex",
				minHeight: "100vh",
				alignItems: "center",
				justifyContent: "center",
				background: "var(--page-bg, #0d1117)" }}
		>
			<SignIn
				appearance={{
					elements: {
						rootBox: {
							width: "100%",
							maxWidth: "420px",
							padding: "1rem" },
						card: {
							background: "var(--panel-bg, #161b22)",
							border: "1px solid var(--border, #30363d)",
							borderRadius: "1rem",
							boxShadow: "none" },
						headerTitle: {
							color: "var(--sea-ink, #e6edf3)" },
						headerSubtitle: {
							color: "var(--sea-ink-soft, #8b949e)" },
						dividerLine: {
							background: "var(--border, #30363d)" },
						dividerText: {
							color: "var(--sea-ink-soft, #8b949e)" },
						formFieldLabel: {
							color: "var(--sea-ink, #e6edf3)" },
						formFieldInput: {
							background: "var(--surface-soft, #0d1117)",
							border: "1px solid var(--border, #30363d)",
							color: "var(--sea-ink, #e6edf3)" },
						footerActionLink: {
							color: "var(--signal, #58a6ff)" },
						socialButtonsBlockButton: {
							border: "1px solid var(--border, #30363d)",
							color: "var(--sea-ink, #e6edf3)",
							background: "transparent" } } }}
			/>
		</div>
	);
}
