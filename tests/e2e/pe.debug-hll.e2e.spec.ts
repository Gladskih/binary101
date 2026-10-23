import { expect, test } from "@playwright/test";
import { createHllInspection, createHllSourceInspection } from "../fixtures/pe-hll.js";
import { createPeCodeViewOverlay, createPeDirectHll } from "../fixtures/pe-codeview-locations.js";

for (const [create, width] of [[createPeCodeViewOverlay, 390], [createPeDirectHll, 1280]] as const) {
test(`HLL source ${create.name} keeps names and statistics readable at ${width}`, async ({ page }, testInfo) => {
  const file = create(createHllInspection());
  await page.setViewportSize({ width, height: 960 });
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
  const panel = page.locator('[data-pe-lazy-section="debug"]');
  await expect(panel).toContainText("CodeView sources: 1");
  await panel.locator(":scope > details > summary").click();
  await panel.locator("summary").filter({ hasText: /^CodeView source #1:/ }).click();
  await expect(panel).toContainText("NB04");
  await expect(panel).toContainText("HL (version 4.0)");
  await expect(panel).toContainText("<Alias>");
  await expect(panel).toContainText("<field>");
  await expect(panel).toContainText("A+B");
  await expect(panel).toContainText("<source.c>");
  const symbols = panel.locator('[data-paged-sortable-table-id="pe-debug-codeviewSource-0-legacy-symbols"]');
  await expect(symbols.getByRole("cell", { name: "<variable_0>", exact: true })).toBeVisible();
  await symbols.getByRole("button", { name: "Next", exact: true }).click();
  await expect(symbols.getByRole("cell", { name: "<variable_100>", exact: true })).toBeVisible();
  const source = panel.locator('[data-sort-state-key="pe-debug-codeviewSource-0-legacy-hllSource"]');
  await expect(source.getByRole("cell", { name: "Source lines", exact: true })).toBeVisible();
  await expect(source.getByRole("columnheader", { name: /Distinct lines or path codes/ })).toHaveClass(/peNumeric/);
  await expect(panel.locator("script")).toHaveCount(0);
  await page.screenshot({ path: testInfo.outputPath("codeview-hll.png"), fullPage: true });
});
}

for (const version of [0x500, 0x600]) {
test(`HLL ${version} source names and line summaries remain available`, async ({ page }) => {
  const file = createPeCodeViewOverlay(createHllSourceInspection(version));
  await page.setViewportSize({ width: 390, height: 960 });
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
  const panel = page.locator('[data-pe-lazy-section="debug"]');
  await panel.locator(":scope > details > summary").click();
  await panel.locator("summary").filter({ hasText: /^CodeView source #1:/ }).click();
  await expect(panel).toContainText(`HL (version ${version >> 8}.0)`);
  await expect(panel).toContainText("<source.c>");
  await expect(panel).toContainText("Source lines");
  await expect(panel).not.toContainText("Unsupported HLL source format");
});
}
