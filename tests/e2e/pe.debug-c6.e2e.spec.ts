import { expect, test } from "@playwright/test";
import { createPeWithC6CodeView } from "../fixtures/pe-codeview-c6.js";

for (const width of [390, 1280]) {
test(`C6 names and statistics remain readable and pageable at width ${width}`, async ({ page }, testInfo) => {
  const file = createPeWithC6CodeView();
  await page.setViewportSize({ width, height: 960 });
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
  const panel = page.locator('[data-pe-lazy-section="debug"]');
  await panel.locator(":scope > details > summary").click();
  await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
  await expect(panel).toContainText("NB02");
  await expect(panel).toContainText("legacy.obj");
  await expect(panel).toContainText("legacy.lib");
  await expect(panel).toContainText("public_name");
  await expect(panel).toContainText("legacy.c");
  await expect(panel).toContainText("<Alias>");
  await expect(panel).toContainText("<member>");
  await expect(panel).toContainText("FORTRAN array bounds");
  const symbols = panel.locator('[data-paged-sortable-table-id="pe-debug-entry-0-legacy-symbols"]');
  await expect(symbols.getByRole("cell", { name: "<stack_0>", exact: true })).toBeVisible();
  await expect(symbols.getByRole("cell", { name: "Stack variable (32-bit offsets)", exact: true })).toHaveCount(100);
  await symbols.getByRole("button", { name: "Next", exact: true }).click();
  await expect(symbols.getByRole("cell", { name: "<stack_100>", exact: true })).toBeVisible();
  await expect(panel.locator("script")).toHaveCount(0);
  await page.screenshot({ path: testInfo.outputPath("codeview-c6.png"), fullPage: true });
});
}
