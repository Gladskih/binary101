import { expect, test } from "@playwright/test";
import { createPeWithProcedureRvas } from "../fixtures/pe-codeview-procedure-rva-file.js";

for (const width of [390, 1280]) {
  test(`CodeView procedures show image RVAs and unresolved range reasons at width ${width}`, async ({ page }, testInfo) => {
    const file = createPeWithProcedureRvas();
    await page.setViewportSize({ width, height: 960 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
    const panel = page.locator('[data-pe-lazy-section="debug"]');
    await panel.locator(":scope > details > summary").click();
    await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
    const procedures = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-procedureSymbols"]');
    await expect(panel.getByRole("heading", { name: "Procedure address resolution", exact: true })).toBeVisible();
    await expect(procedures).toContainText("<mapped>&amp;");
    await expect(procedures).toContainText("0x1030");
    await expect(procedures).toContainText("#1 .text");
    await expect(procedures).toContainText("Procedure exceeds logical segment bounds.");
    await expect(procedures.getByRole("row").filter({ hasText: "removed_function" }))
      .toContainText("Discarded symbol does not identify current image code.");
    const header = await procedures.getByRole("button", { name: "Sort by Stored segment:offset", exact: true }).boundingBox();
    expect(header?.height).toBeLessThan(60);
    expect(await page.locator("body").evaluate(element => element.scrollWidth)).toBeLessThanOrEqual(width);
    await page.screenshot({ path: testInfo.outputPath("procedure-rvas.png"), fullPage: true });
  });
}
