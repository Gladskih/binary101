import { expect, test } from "@playwright/test";
import { createPeWithDebugPayloads } from "../fixtures/pe-debug-file.js";
import { createLegacyCodeView, legacyU32 } from "../fixtures/pe-legacy-codeview.js";
import { codeViewTextRecord, codeViewUtf8 } from "../fixtures/pe-codeview-type-strings.js";
import { codeViewAnnotations, codeViewUtf16 } from "../fixtures/pe-codeview-symbol-strings.js";

test("CodeView annotation and environment text stays readable and paginated", async ({ page }, testInfo) => {
  const annotations = Array.from({ length: 101 }, (_, index) => codeViewUtf8(`<annotation_${index}>`)).flat();
  const file = createPeWithDebugPayloads([{ type: 2, data: createLegacyCodeView([
    { type: 0x125, module: 1, data: Uint8Array.from([...legacyU32(4),
      ...codeViewAnnotations(annotations, 101),
      ...codeViewTextRecord(0x113d, 5, [...codeViewUtf8("empty"), 0,
        ...codeViewUtf8("cwd"), ...codeViewUtf8("<workspace>"), 0]),
      ...codeViewTextRecord(0x1161, 4, [...codeViewUtf16("исходный.pdb"), ...codeViewUtf16("target.pdb")])]) }
  ]) }]);
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
  const panel = page.locator('[data-pe-lazy-section="debug"]');
  await panel.locator(":scope > details > summary").click();
  await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
  const strings = panel.locator('[data-paged-sortable-table-id="pe-debug-entry-0-legacy-symbolStrings"]');
  await expect(panel).toContainText("Stored symbol strings");
  await expect(strings.getByRole("cell", { name: "<annotation_0>", exact: true })).toBeVisible();
  await strings.getByRole("button", { name: "Next", exact: true }).click();
  await expect(strings.getByRole("cell", { name: "<annotation_100>", exact: true })).toBeVisible();
  const environment = strings.getByRole("row").filter({ hasText: "Environment" });
  await expect(environment.filter({ hasText: "cwd" }).getByRole("cell",
    { name: "<workspace>", exact: true })).toBeVisible();
  await expect(environment.filter({ hasText: "empty" }).getByRole("cell",
    { name: "(empty)", exact: true })).toBeVisible();
  await expect(strings.getByRole("row").filter({ hasText: "Source PDB" })).toContainText("исходный.pdb");
  await expect(strings.getByRole("row").filter({ hasText: "Destination PDB" })).toContainText("target.pdb");
  await expect(panel).not.toContainText("Symbol record 0x1019");
  await page.screenshot({ path: testInfo.outputPath("codeview-symbol-text.png"), fullPage: true });
});
