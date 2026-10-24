import { expect, test } from "@playwright/test";
import { createPeWithCodeViewBuildInfo } from "../fixtures/pe-codeview-build.js";

for (const width of [390, 1280]) {
  test(`CodeView build and source records retain readable strings at width ${width}`, async ({ page }, testInfo) => {
    const file = createPeWithCodeViewBuildInfo();
    await page.setViewportSize({ width, height: 960 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
    const panel = page.locator('[data-pe-lazy-section="debug"]');
    await panel.locator(":scope > details > summary").click();
    await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
    const build = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-buildInfo"]');
    await expect(build.getByRole("cell", { name: "cl.exe", exact: true })).toBeVisible();
    await expect(build.getByRole("cell", { name: "/c /DNAME=<value>&amp;", exact: true })).toBeVisible();
    const sources = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-typeSources"]');
    await expect(sources.getByRole("cell", { name: "<source>&amp;.cpp", exact: true })).toBeVisible();
    await expect(sources.getByRole("cell", { name: "module 2 string-table offset #32 (external)", exact: true })).toBeVisible();
    await expect(sources.getByRole("columnheader", { name: "Sort by Source line", exact: true })).toHaveClass(/peNumeric/);
    const derived = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-derivedTypes"]');
    await expect(derived.getByRole("cell", { name: "<Derived>&amp;", exact: true })).toBeVisible();
    await expect(derived.getByRole("cell", { name: "not translated", exact: true })).toBeVisible();
    const parts = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-stringComponents"]');
    await expect(parts.getByRole("cell", { name: "<source>&amp;.cpp", exact: true })).toBeVisible();
    const stored = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-typeStrings"]');
    await expect(stored.getByRole("cell", { name: "<source>&amp;.cpp", exact: true })).toBeVisible();
    await expect(panel).not.toContainText("CodeView type record:");
    await page.screenshot({ path: testInfo.outputPath("codeview-build.png"), fullPage: true });
  });
}
