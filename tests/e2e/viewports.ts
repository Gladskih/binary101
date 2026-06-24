"use strict";

// WCAG 2.2 Reflow uses 320 CSS pixels as its narrow-width target:
// https://www.w3.org/WAI/WCAG22/Understanding/reflow.html
// The height matches playwright.config.mjs because these tests intentionally vary only width.
export const NARROW_LAYOUT_VIEWPORT = { width: 320, height: 720 };
