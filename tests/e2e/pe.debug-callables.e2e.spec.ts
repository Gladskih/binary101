import { expect, test } from "@playwright/test";
import { createPeWithCodeViewCallables } from "../fixtures/pe-codeview-callables.js";

for (const width of [390, 1280]) {
  test(`CodeView function types show readable signatures at width ${width}`, async ({ page }, testInfo) => {
    const file = createPeWithCodeViewCallables();
    await page.setViewportSize({ width, height: 960 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
    const panel = page.locator('[data-pe-lazy-section="debug"]');
    await panel.locator(":scope > details > summary").click();
    await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
    const table = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-functions"]');
    await expect(table).toBeVisible();
    await expect(table.getByRole("cell", { name: "<convert>", exact: true })).toBeVisible();
    await expect(table.getByRole("cell", { name: "int32, float64", exact: true })).toBeVisible();
    await expect(table.getByRole("cell", { name: "stdcall (near)", exact: true })).toBeVisible();
    await expect(table.getByRole("columnheader", { name: "Declared parameters" })).toBeVisible();
    await expect(panel).not.toContainText("payload is not decoded");
    await page.screenshot({ path: testInfo.outputPath("codeview-callables.png"), fullPage: true });
  });
}
