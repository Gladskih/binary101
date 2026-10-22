import { expect, test } from "@playwright/test";
import { createPeWithDebugPayloads } from "../fixtures/pe-debug-file.js";
import { createLegacyCodeView, legacySymbol, legacyU16, legacyU32 } from "../fixtures/pe-legacy-codeview.js";
import { codeViewHashIndex, codeViewGlobalSymbols } from "../fixtures/pe-codeview-hash-index.js";

for (const width of [390, 1280]) {
test(`CodeView index tables show readable statistics at width ${width}`, async ({ page }, testInfo) => {
  const file = createPeWithDebugPayloads([{ type: 2, data: createLegacyCodeView([
    { type: 0x12a, module: 0xffff, data: Uint8Array.from(codeViewGlobalSymbols(legacySymbol(),
      codeViewHashIndex([0, 2, 1]), codeViewHashIndex([3, 0]))) },
    { type: 0x12e, module: 0xffff, data: new TextEncoder().encode(".text\0.data\0") },
    { type: 0x12d, module: 0xffff, data: Uint8Array.from([
      ...legacyU16(2), ...legacyU16(2),
      ...[0, 6].flatMap(name => [...legacyU16(0x10f), ...new Array<number>(6).fill(0),
        ...legacyU16(name), ...legacyU16(0), ...legacyU32(0), ...legacyU32(64)])
    ]) }
  ]) }]);
  await page.setViewportSize({ width, height: 960 });
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
  const panel = page.locator('[data-pe-lazy-section="debug"]');
  await panel.locator(":scope > details > summary").click();
  await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
  await expect(panel).toContainText("Symbol index statistics (declared counts)");
  const summary = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-indexes"]');
  const buckets = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-buckets"]');
  const sections = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-indexedSections"]');
  await expect(summary.getByRole("cell", { name: "XOR/rotate DWORD checksum", exact: true })).toBeVisible();
  await expect(buckets.getByRole("columnheader", { name: /References per bucket/ })).toBeVisible();
  await expect(sections.getByRole("row").filter({ hasText: ".text" })).toContainText("3");
  await expect(sections.getByRole("row").filter({ hasText: ".data" })).toContainText("0");
  await expect(sections.getByRole("cell", { name: ".data", exact: true })).toBeVisible();
  await expect(summary.getByRole("columnheader", { name: "Sort by References", exact: true })).toHaveClass(/peNumeric/);
  await expect(panel).not.toContainText("Chain offset");
  expect(await summary.evaluate(table =>
    table.parentElement!.scrollWidth > table.parentElement!.clientWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath("codeview-index-statistics.png"), fullPage: true });
});
}

test("CodeView index distributions retain rows after the first page", async ({ page }) => {
  const file = createPeWithDebugPayloads([{ type: 2, data: createLegacyCodeView([
    { type: 0x12a, module: 0xffff, data: Uint8Array.from(codeViewGlobalSymbols(legacySymbol(),
      codeViewHashIndex(Array.from({ length: 101 }, (_, index) => index)), codeViewHashIndex([]))) }
  ]) }]);
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
  const panel = page.locator('[data-pe-lazy-section="debug"]');
  await panel.locator(":scope > details > summary").click();
  await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
  const buckets = panel.locator('[data-paged-sortable-table-id="pe-debug-entry-0-legacy-buckets"]');
  await expect(buckets.getByRole("cell", { name: "99", exact: true })).toBeVisible();
  await buckets.getByRole("button", { name: "Next", exact: true }).click();
  await expect(buckets.getByRole("cell", { name: "100", exact: true })).toBeVisible();
});
