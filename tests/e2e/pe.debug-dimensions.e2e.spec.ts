import { expect, test } from "@playwright/test";
import { createPeWithCodeViewDimensions } from "../fixtures/pe-codeview-dimensions.js";

for (const width of [390, 1280]) {
  test(`CodeView array dimensions retain named bounds at width ${width}`, async ({ page }, testInfo) => {
    const file = createPeWithCodeViewDimensions();
    await page.setViewportSize({ width, height: 960 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
    const panel = page.locator('[data-pe-lazy-section="debug"]');
    await panel.locator(":scope > details > summary").click();
    await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
    const bounds = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-arrayBounds"]');
    await expect(bounds.getByRole("cell", { name: "<Grid>&amp; (rank: 2)", exact: true })).toHaveCount(2);
    await expect(bounds.getByRole("cell", { name: "<limit>&amp;", exact: true })).toBeVisible();
    await expect(bounds.getByRole("cell", { name: "18446744073709551615", exact: true })).toBeVisible();
    await expect(bounds.getByRole("columnheader", { name: "Sort by Lower bound", exact: true })).toHaveClass(/peNumeric/);
    await expect(bounds.getByRole("cell", { name: "(language default)", exact: true })).toBeVisible();
    await expect(bounds.getByRole("cell", { name: "(unspecified)", exact: true })).toBeVisible();
    const types = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-types"]');
    await expect(types.getByRole("cell", { name: "not stored", exact: true })).toHaveCount(2);
    await expect(panel).not.toContainText("truncated bounds");
    await page.screenshot({ path: testInfo.outputPath("codeview-dimensions.png"), fullPage: true });
  });
}
