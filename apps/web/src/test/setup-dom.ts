// Provide required VITE_ env vars that t3-oss/env-core validates at module load.
// Must run before any test file imports src/env.ts (preload guarantees this).
if (!process.env.VITE_TENANT_SLUG) {
	process.env.VITE_TENANT_SLUG = "test-tenant";
}

import { JSDOM } from "jsdom";

const dom = new JSDOM("<!DOCTYPE html><html><body></body></html>", {
	url: "http://localhost/",
	pretendToBeVisual: true,
});

const { window } = dom;

// Expose jsdom globals to Bun/Node runtime so @testing-library/react can render
const domGlobals: Record<string, unknown> = {
	window,
	document: window.document,
	navigator: window.navigator,
	location: window.location,
	history: window.history,
	screen: window.screen,
	Element: window.Element,
	HTMLElement: window.HTMLElement,
	HTMLInputElement: window.HTMLInputElement,
	HTMLButtonElement: window.HTMLButtonElement,
	HTMLDivElement: window.HTMLDivElement,
	HTMLFormElement: window.HTMLFormElement,
	HTMLSelectElement: window.HTMLSelectElement,
	HTMLTextAreaElement: window.HTMLTextAreaElement,
	HTMLAnchorElement: window.HTMLAnchorElement,
	Node: window.Node,
	NodeList: window.NodeList,
	Event: window.Event,
	CustomEvent: window.CustomEvent,
	MouseEvent: window.MouseEvent,
	KeyboardEvent: window.KeyboardEvent,
	FocusEvent: window.FocusEvent,
	InputEvent: window.InputEvent,
	PointerEvent: window.PointerEvent,
	EventTarget: window.EventTarget,
	MutationObserver: window.MutationObserver,
	ResizeObserver: window.ResizeObserver,
	IntersectionObserver: (window as unknown as Record<string, unknown>)
		.IntersectionObserver,
	getComputedStyle: window.getComputedStyle.bind(window),
	requestAnimationFrame: window.requestAnimationFrame.bind(window),
	cancelAnimationFrame: window.cancelAnimationFrame.bind(window),
	SVGElement: window.SVGElement,
	Text: window.Text,
	Comment: window.Comment,
	DocumentFragment: window.DocumentFragment,
	DOMParser: window.DOMParser,
	Range: window.Range,
	TreeWalker: window.TreeWalker,
	NodeFilter: window.NodeFilter,
	XMLSerializer: window.XMLSerializer,
};

for (const [key, value] of Object.entries(domGlobals)) {
	if (value !== undefined) {
		Object.defineProperty(globalThis, key, {
			value,
			writable: true,
			configurable: true,
		});
	}
}
