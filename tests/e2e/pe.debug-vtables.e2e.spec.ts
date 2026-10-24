import { expect, test } from "@playwright/test";
import { createPeWithCodeViewVtables } from "../fixtures/pe-codeview-vtables.js";

for (const width of [390, 1280]) {
  test(`CodeView virtual tables retain owner, placement and stored names at width ${width}`, async ({ page }, testInfo) => {
    const file = createPeWithCodeViewVtables();
    await page.setViewportSize({ width, height: 960 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
    const panel = page.locator('[data-pe-lazy-section="debug"]');
    await panel.locator(":scope > details > summary").click();
    await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
    const layouts = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-virtualTables"]');
    await expect(layouts.getByRole("cell", { name: "<Derived>&amp;::table", exact: true })).toBeVisible();
    await expect(layouts.getByRole("cell", { name: "<Derived>&amp;", exact: true })).toBeVisible();
    await expect(layouts.getByRole("columnheader", { name: "Sort by Pointer offset", exact: true })).toHaveClass(/peNumeric/);
    const paths = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-vtablePaths"]');
    await expect(paths.getByRole("cell", { name: "<Derived>&amp; → Base", exact: true })).toHaveCount(2);
    const strings = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-typeStrings"]');
    await expect(strings.getByRole("cell", { name: "<write>&amp;", exact: true })).toBeVisible();
    await expect(panel).not.toContainText("CodeView type record:");
    await page.screenshot({ path: testInfo.outputPath("codeview-vtables.png"), fullPage: true });
  });
}
