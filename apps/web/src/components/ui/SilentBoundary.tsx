import { Component, type ReactNode } from "react";

/**
 * Error boundary for optional widgets: if a non-essential query throws
 * (e.g. a permission check for a member-only list), hide the widget instead
 * of taking down the whole page.
 */
export default class SilentBoundary extends Component<
	{ children: ReactNode; fallback?: ReactNode },
	{ failed: boolean }
> {
	state = { failed: false };

	static getDerivedStateFromError() {
		return { failed: true };
	}

	componentDidCatch(error: unknown) {
		console.warn("[SilentBoundary]", error);
	}

	render() {
		return this.state.failed ? (this.props.fallback ?? null) : this.props.children;
	}
}
