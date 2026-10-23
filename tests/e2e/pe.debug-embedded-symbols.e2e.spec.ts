import { expect, test } from "@playwright/test";
import { createPeWithEmbeddedCodeView } from "../fixtures/pe-codeview-embedded-symbols.js";

for (const width of [390, 1280]) {
test(`CodeView embedded names and discard summaries remain readable at width ${width}`, async ({ page }, testInfo) => {
  const file = createPeWithEmbeddedCodeView();
  await page.setViewportSize({ width, height: 960 });
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
  const panel = page.locator('[data-pe-lazy-section="debug"]');
  await panel.locator(":scope > details > summary").click();
  await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
  const names = panel.locator('[data-paged-sortable-table-id="pe-debug-entry-0-legacy-embeddedSymbols"]');
  await expect(names.getByRole("cell", { name: "<discarded_0>", exact: true })).toBeVisible();
  await names.getByRole("button", { name: "Next", exact: true }).click();
  await expect(names.getByRole("cell", { name: "<discarded_100>", exact: true })).toBeVisible();
  await expect(names.getByRole("row").filter({ hasText: "This pointer" })).toContainText("thisAlias");
  await expect(names.getByRole("row").filter({ hasText: "Referenced symbol" })).toContainText("referenced");
  await expect(names.getByRole("row").filter({ has: page.getByRole("cell",
    { name: "Pointer", exact: true }) })).toContainText("basedValue");
  await expect(panel).toContainText("BaseType");
  await expect(panel).toContainText("<annotation>");
  const summary = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-discardedSymbols"]');
  await expect(summary.getByRole("cell", { name: "Not referenced", exact: true })).toBeVisible();
  await expect(summary.getByRole("cell", { name: "42", exact: true })).toBeVisible();
  await expect(summary.getByRole("cell", { name: "90", exact: true })).toBeVisible();
  await expect(summary.getByRole("columnheader", { name: /Last source line/ })).toHaveClass(/peNumeric/);
  expect(await summary.evaluate(table =>
    table.parentElement!.scrollWidth > table.parentElement!.clientWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath("codeview-embedded-symbols.png"), fullPage: true });
});
}
