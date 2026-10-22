import { expect, test } from "@playwright/test";
import { createPeWithRawArm64ExceptionCopy } from "../fixtures/pe-debug-file.js";
import { createPeDebugFile, createPeWithDebugPayloads, createPeWithExceptionCopy, createPeWithRawExceptionCopy } from "../fixtures/pe-debug-file.js";
import { createLegacyCodeView, legacyU32, legacySymbol } from "../fixtures/pe-legacy-codeview.js";
import { createTd32, td32Names } from "../fixtures/pe-td32.js";
import { codeViewField, codeViewFieldList } from "../fixtures/pe-codeview-fields.js";
import { createPeTd32Overlay, createPeTd32Section } from "../fixtures/pe-td32-locations.js";

for (const [label, create] of [["appended", createPeTd32Overlay], ["section", createPeTd32Section]] as const) {
  test(`TD32 ${label} data remains accessible without a debug directory entry`, async ({ page }) => {
    const file = create(createTd32([{ type: 0x130, module: 0,
      data: td32Names(Array.from({ length: 101 }, (_, index) => `stored_name_${index}`)) }]));
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
    const panel = page.locator('[data-pe-lazy-section="debug"]');
    await expect(panel).toContainText("Debug information");
    await expect(panel).toContainText("TD32 sources: 1");
    await panel.locator(":scope > details > summary").click();
    await panel.locator("summary").filter({ hasText: /^TD32 source #1:/ }).click();
    await expect(panel.getByRole("cell", { name: "stored_name_0", exact: true })).toBeVisible();
    await panel.getByRole("button", { name: "Next", exact: true }).click();
    await expect(panel.getByRole("cell", { name: "stored_name_100", exact: true })).toBeVisible();
    await expect(panel).not.toContainText("Entry #1:");
  });
}

test("legacy CodeView member names remain readable beyond the first page", async ({ page }) => {
  const fields = Array.from({ length: 101 }, (_, index) =>
    codeViewField(0x407, [0x74, 0, 3, 0], `field_${index}`)).flat();
  const file = createPeWithDebugPayloads([{ type: 2, data: createLegacyCodeView([
    { type: 0x121, module: 1, data: Uint8Array.from([...legacyU32(1), ...codeViewFieldList(fields)]) }
  ]) }]);
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
  const panel = page.locator('[data-pe-lazy-section="debug"]');
  await panel.locator(":scope > details > summary").click();
  await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
  await expect(panel).toContainText("Member and enumerator names");
  const members = panel.locator('[data-paged-sortable-table-id="pe-debug-entry-0-legacy-members"]');
  await expect(members.getByRole("cell", { name: "field_0", exact: true })).toBeVisible();
  await members.getByRole("button", { name: "Next", exact: true }).click();
  await expect(members.getByRole("cell", { name: "field_100", exact: true })).toBeVisible();
});

test("TD32 in an UNKNOWN directory entry preserves names and exposes paginated details", async ({ page }) => {
  const file = createPeWithDebugPayloads([{ type: 0, data: createTd32([
    { type: 0x130, module: 0, data: td32Names(Array.from({ length: 101 }, (_, index) => `type_name_${index}`)) }
  ]) }]);
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
  const panel = page.locator('[data-pe-lazy-section="debug"]');
  await panel.locator(":scope > details > summary").click();
  await expect(panel).toContainText("Borland TD32 FB09");
  await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
  await expect(panel).toContainText("TD32 shared names");
  await expect(panel.getByRole("cell", { name: "type_name_0", exact: true })).toBeVisible();
  await panel.getByRole("button", { name: "Next", exact: true }).click();
  await expect(panel.getByRole("cell", { name: "type_name_100", exact: true })).toBeVisible();
  await expect(panel).not.toContainText("payload is not decoded");
});

test("SPGO debug type 18 stays explicitly undecoded even with a recognized POGO signature", async ({ page }) => {
  // DWORD 0x5350474f is SPGO inside a type-13 POGO record, not a type-18 contract.
  const file = createPeWithDebugPayloads([{ type: 18, data: Uint8Array.of(0x4f, 0x47, 0x50, 0x53) }]);
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
  const panel = page.locator('[data-pe-lazy-section="debug"]');
  await panel.locator(":scope > details > summary").click();
  await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
  await expect(panel).toContainText("SPGO payload is not decoded");
  await expect(panel).toContainText("no semantic decoding is available");
});

for (const create of [createPeWithExceptionCopy, createPeWithRawExceptionCopy]) {
test(`raw-only exception copy preserves unwind statistics: ${create.name}`, async ({ page }) => {
  const file = create();
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
  const panel = page.locator('[data-pe-lazy-section="debug"]');
  await panel.locator(":scope > details > summary").click();
  await panel.getByText("Entry #1:", { exact: false }).click();
  await expect(panel).toContainText("EXCEPTION");
  await panel.locator("summary").filter({ hasText: /^Exception directory/ }).click();
  await expect(panel).toContainText("Functions (RUNTIME_FUNCTION entries)");
  await expect(panel).toContainText("UNWIND_INFO v1 blocks");
  await expect(panel.locator("dt").filter({ hasText: "Missing/invalid ranges" }).locator("+ dd")).toHaveText("0");
  await expect(panel).not.toContainText("no raw-data RVA");
});
}

test("raw-only ARM64 exception copy exposes readable unwind statistics without a table RVA", async ({ page }) => {
  const file = createPeWithRawArm64ExceptionCopy();
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
  const panel = page.locator('[data-pe-lazy-section="debug"]');
  await panel.locator(":scope > details > summary").click();
  await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
  await panel.locator("summary").filter({ hasText: /^Exception directory/ }).click();
  await expect(panel.locator("dt").filter({ hasText: "Missing/invalid ranges" }).locator("+ dd")).toHaveText("0");
  await expect(panel).not.toContainText("not implemented");
  await expect(panel.getByRole("columnheader", { name: "RVA", exact: true })).toHaveCount(0);
});

test("PE inline CodeView preserves named records with pagination and no address matrix", async ({ page }, testInfo) => {
  const file = createPeWithDebugPayloads([{ type: 2, data: createLegacyCodeView([{ type: 0x125, module: 1,
    data: Uint8Array.from([...legacyU32(1), ...Array.from({ length: 101 },
      (_, index) => legacySymbol(0x203, `public_${index}`)).flat()]) }]) }]);
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
  const panel = page.locator('[data-pe-lazy-section="debug"]');
  await panel.locator(":scope > details > summary").click();
  await panel.getByText("Entry #1:", { exact: false }).click();
  await expect(panel).toContainText("Embedded NB09 CodeView");
  await expect(panel).toContainText("Symbol and type statistics");
  const symbols = panel.locator('[data-paged-sortable-table-id="pe-debug-entry-0-legacy-symbols"]');
  await expect(symbols).toContainText("public_0");
  await expect(panel.getByRole("columnheader", { name: "RVA", exact: true })).toHaveCount(0);
  await symbols.getByRole("button", { name: "Next", exact: true }).click();
  await expect(symbols).toContainText("public_100");
  await page.screenshot({ path: testInfo.outputPath("legacy-codeview.png"), fullPage: true });
});

test("PE debug shows embedded source mappings and readable layout statistics", async ({ page }, testInfo) => {
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  const file = createPeDebugFile();
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
  const panel = page.locator('[data-pe-lazy-section="debug"]');
  await panel.locator(":scope > details > summary").click();
  await panel.getByText("Entry #1:", { exact: false }).click();
  await expect(panel).toContainText("1 source document, 1 method with source mappings");
  await expect(panel).toContainText("Visible sequence points");
  await expect(panel).toContainText("Source documents: C#");
  await expect(panel).toContainText("source.cs");
  await expect(panel.getByRole("cell", { name: "local", exact: true })).toBeVisible();
  await expect(panel.getByRole("cell", { name: "constant", exact: true })).toBeVisible();
  await expect(panel.getByRole("cell", { name: "System", exact: true })).toBeVisible();
  await expect(panel).toContainText("int32: 3");
  await expect(panel).toContainText("https://example.invalid/source.cs");
  await panel.getByText("Entry #2:", { exact: false }).click();
  await expect(panel).toContainText("Frames with SEH");
  await expect(panel).toContainText("26");
  await panel.getByText("Entry #3:", { exact: false }).click();
  await expect(panel).toContainText("Unmapped regions");
  await panel.getByText("Entry #4:", { exact: false }).click();
  await expect(panel).toContainText(".text$largest");
  await expect(panel).toContainText(".text$first");
  await panel.getByText("Entry #5:", { exact: false }).click();
  await expect(panel).toContainText("first.dbg");
  await expect(panel).toContainText("second.dbg");
  await expect(panel.getByRole("columnheader", { name: "Start RVA", exact: true })).toHaveCount(0);
  await expect(panel.getByRole("columnheader", { name: "Raw RVA", exact: true })).toHaveCount(0);
  await expect(panel).not.toContainText("decompression failed");
  await expect(panel).not.toContainText("not decoded");
  expect(errors).toEqual([]);
  await page.screenshot({ path: testInfo.outputPath("pe-debug.png"), fullPage: true });
});

test("FIXUP displays type and named-section summaries without an address table", async ({ page }) => {
  const file = createPeWithDebugPayloads([{ type: 6, data: Uint8Array.of(
    1, 0, 0, 0, 0, 16, 0, 0, 4, 16, 0, 0,
    4, 0, 0, 128, 4, 16, 0, 0, 8, 16, 0, 0) }]);
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
  const panel = page.locator('[data-pe-lazy-section="debug"]');
  await panel.locator(":scope > details > summary").click();
  await panel.getByText("Entry #1:", { exact: false }).click();
  await expect(panel).toContainText("Link-time relocation metadata with 2 fixups");
  await expect(panel).toContainText("Distinct source locations");
  await expect(panel).toContainText("IMAGE_REL_AMD64_ADDR64");
  await expect(panel).toContainText("IMAGE_REL_AMD64_REL32");
  await expect(panel).toContainText(".text");
  await expect(panel.getByRole("columnheader", { name: "Source section", exact: true })).toBeVisible();
  await expect(panel.getByRole("columnheader", { name: "RVA", exact: true })).toHaveCount(0);
  await expect(panel).not.toContainText("not decoded");
});

test("POGO keeps names and sizes accessible through pagination", async ({ page }) => {
  const file = createPeDebugFile(101);
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
  const panel = page.locator('[data-pe-lazy-section="debug"]');
  await panel.locator(":scope > details > summary").click();
  await panel.getByText("Entry #4:", { exact: false }).click();
  const table = panel.locator('[data-paged-sortable-table-id="pe-debug-entry-3-pogo"]');
  await expect(table).toContainText(".text$first");
  await expect(table.locator("tbody tr")).toHaveCount(100);
  await table.getByRole("button", { name: "Next", exact: true }).click();
  await expect(table.locator("tbody tr")).toHaveCount(1);
  await expect(table).toContainText(".text$largest");
});
