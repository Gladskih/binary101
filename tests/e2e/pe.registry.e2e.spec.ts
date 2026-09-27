import { expect, test } from "@playwright/test";
import { createPeRegistryFile } from "../fixtures/pe-registry-file.js";

// UI policy: 50 rows/page. 125 = 2*50 + 25 exercises a partial third page;
// names use 3 decimal digits so lexicographic and numeric order agree through index 124.
// 51 resources = 50 + 1; 60 declarations = 50 + 10 exercise both nested paginators.
void test("ATL REGISTRY deep analysis displays COM, typed values and diagnostics locally", async ({ page }) => {
  const file = createPeRegistryFile();
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name,
    mimeType: "application/octet-stream", buffer: Buffer.from(file.data) });
  const resources = page.locator('[data-pe-lazy-section="resources"]');
  await resources.locator(":scope > details > summary").click();
  const group = resources.locator("details").filter({
    has: page.locator("summary", { hasText: /^REGISTRY\b/ })
  }).last();
  await group.locator(":scope > summary").click();
  await expect(group).toContainText("ATL registry script");
  await expect(group).toContainText("COM class (CLSID)");
  await expect(group).toContainText("In-process COM server");
  await expect(group).toContainText("%MODULE%");
  await expect(group).toContainText("REG_DWORD");
  await expect(group).toContainText("REG_MULTI_SZ");
  await expect(group).toContainText("00 aa ff");
  await expect(group).toContainText("missing assignment");
  await expect(group.locator("script, img")).toHaveCount(0);
  await group.getByText(/^RGS source/).click();
  await expect(group.locator("pre")).toContainText("<script>alert(1)</script>");
});

void test("ATL table pagination reaches the last declaration and survives lazy remounts", async ({ page }) => {
  const file = createPeRegistryFile("HKCU { " +
    Array.from({ length: 125 }, (_, index) => `Key${String(index).padStart(3, "0")}`).join(" ") + " }");
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name,
    mimeType: "application/octet-stream", buffer: Buffer.from(file.data) });
  const resources = page.locator('[data-pe-lazy-section="resources"]');
  await resources.locator(":scope > details > summary").click();
  const group = resources.locator("details").filter({
    has: page.locator("summary", { hasText: /^REGISTRY\b/ })
  }).last();
  await group.locator(":scope > summary").click();
  const table = group.locator('[data-paged-sortable-table-id="pe-registry-0-0"]');
  await expect(table.locator("tbody > tr")).toHaveCount(50);
  await table.getByRole("button", { name: "Last", exact: true }).click();
  await expect(table.locator("tbody > tr")).toHaveCount(25);
  await expect(table.locator("tbody")).toContainText("Key124");
  await expect(table.locator("[data-paged-sortable-page-input]")).toHaveValue("3");
  await resources.locator(":scope > details > summary").click();
  await resources.locator(":scope > details > summary").click();
  await expect(table.locator("[data-paged-sortable-page-input]")).toHaveValue("3");
  await expect(table.locator("tbody")).toContainText("Key124");
});

void test("nested registry pagination works after changing the resource page", async ({ page }) => {
  const file = createPeRegistryFile("HKCU { " + "Key ".repeat(60) + "}", 51);
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name,
    mimeType: "application/octet-stream", buffer: Buffer.from(file.data) });
  const resources = page.locator('[data-pe-lazy-section="resources"]');
  await resources.locator(":scope > details > summary").click();
  const group = resources.locator("details").filter({
    has: page.locator("summary", { hasText: /^REGISTRY\b/ })
  }).last();
  await group.locator(":scope > summary").click();
  const outer = group.locator('[data-paged-sortable-table-id="pe-resource-detail-0"]');
  const first = group.locator('[data-paged-sortable-table-id="pe-registry-0-0"]');
  await first.getByRole("button", { name: "Last", exact: true }).click();
  await expect(first.locator("[data-paged-sortable-page-input]")).toHaveValue("2");
  await expect(outer.locator(":scope > .pagedSortableTableToolbar [data-paged-sortable-page-input]")).toHaveValue("1");
  await outer.locator(":scope > .pagedSortableTableToolbar").getByRole("button", { name: "Last", exact: true }).click();
  const last = group.locator('[data-paged-sortable-table-id="pe-registry-0-50"]');
  await last.getByRole("button", { name: "Last", exact: true }).click();
  await expect(last.locator("tbody > tr")).toHaveCount(10);
  await outer.locator(":scope > .pagedSortableTableToolbar").getByRole("button", { name: "First", exact: true }).click();
  await expect(first.locator("[data-paged-sortable-page-input]")).toHaveValue("2");
  await resources.locator(":scope > details > summary").click();
  await resources.locator(":scope > details > summary").click();
  await expect(first.locator("[data-paged-sortable-page-input]")).toHaveValue("2");
});
