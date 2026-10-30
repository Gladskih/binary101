import { expect, test } from "@playwright/test";
import { createPeWithTd32Semantics } from "../fixtures/pe-td32-semantics.js";

for (const width of [390, 1280]) {
  test(`TD32 semantic summaries and named types remain readable at width ${width}`, async ({ page }, testInfo) => {
    const file = createPeWithTd32Semantics();
    await page.setViewportSize({ width, height: 960 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
    const panel = page.locator('[data-pe-lazy-section="debug"]');
    await panel.locator(":scope > details > summary").click();
    await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
    const procedures = panel.locator('[data-sort-state-key="pe-debug-entry-0-td32-procedures"]');
    const types = panel.locator('[data-sort-state-key="pe-debug-entry-0-td32-typeaggregates"]');
    await expect(procedures).toContainText("<worker>");
    await expect(procedures).toContainText("64");
    await expect(types).toContainText("Widget");
    await expect(types).toContainText("24");
    await expect(panel.locator('[data-sort-state-key="pe-debug-entry-0-td32-typestatistics"]')).toContainText("Const");
    await expect(panel.locator('[data-sort-state-key="pe-debug-entry-0-td32-symbolmetadata"]')).toContainText("stored BP-relative offset -8");
    expect(await page.locator("body").evaluate(element => element.scrollWidth)).toBeLessThanOrEqual(width);
    await page.screenshot({ path: testInfo.outputPath("td32-semantics.png"), fullPage: true });
  });
}
