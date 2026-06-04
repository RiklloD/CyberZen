import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import {
	EmptyState,
	PanelContainer,
	PanelSkeleton,
} from "./SharedPanelComponents";

describe("PanelSkeleton", () => {
	it("renders a single skeleton block by default", () => {
		const { container } = render(<PanelSkeleton />);
		const blocks = container.querySelectorAll(".loading-panel");
		expect(blocks).toHaveLength(1);
	});

	it("renders the correct number of blocks with count prop", () => {
		const { container } = render(<PanelSkeleton count={4} />);
		const blocks = container.querySelectorAll(".loading-panel");
		expect(blocks).toHaveLength(4);
	});

	it("renders shimmer rows when rows prop is provided", () => {
		const { container } = render(<PanelSkeleton rows={5} />);
		const block = container.querySelector(".loading-panel");
		expect(block).not.toBeNull();
		const rows = block!.querySelectorAll(".space-y-2 > div");
		expect(rows).toHaveLength(5);
	});
});

describe("EmptyState", () => {
	it("renders the message text", () => {
		render(<EmptyState message="No data available." />);
		expect(screen.getByText("No data available.")).toBeDefined();
	});

	it("renders an icon when provided", () => {
		const { container } = render(
			<EmptyState
				icon={<span data-testid="test-icon">🛡️</span>}
				message="Empty"
			/>,
		);
		expect(container.querySelector("[data-testid='test-icon']")).not.toBeNull();
	});

	it("does not render an icon slot when icon is omitted", () => {
		const { container } = render(<EmptyState message="Empty" />);
		expect(container.querySelector(".opacity-40")).toBeNull();
	});
});

describe("PanelContainer", () => {
	it("renders the title", () => {
		render(
			<PanelContainer title="Test Panel">
				<span>content</span>
			</PanelContainer>,
		);
		expect(screen.getByText("Test Panel")).toBeDefined();
	});

	it("renders subtitle when provided", () => {
		render(
			<PanelContainer title="Title" subtitle="A subtitle">
				<span>content</span>
			</PanelContainer>,
		);
		expect(screen.getByText("A subtitle")).toBeDefined();
	});

	it("renders children", () => {
		render(
			<PanelContainer title="Title">
				<span data-testid="child">Hello</span>
			</PanelContainer>,
		);
		expect(screen.getByTestId("child")).toBeDefined();
	});

	it("renders actions slot when provided", () => {
		render(
			<PanelContainer
				title="Title"
				actions={<button type="button">Action</button>}
			>
				<span>content</span>
			</PanelContainer>,
		);
		expect(screen.getByText("Action")).toBeDefined();
	});
});
