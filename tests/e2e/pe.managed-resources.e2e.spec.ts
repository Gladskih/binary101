"use strict";

import { expect, test } from "@playwright/test";
import { createPeManagedResourceFile } from "./fixtures/pe-managed-resource-file.js";

for (const width of [1280, 390]) {
  test(`managed resources preview and paginate at ${width}px`, async ({ page }) => {
    const file = createPeManagedResourceFile();
    const errors: string[] = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/");
    await page.locator("#fileInput").setInputFiles({
      name: file.name, mimeType: file.type, buffer: Buffer.from(file.data)
    });
    const clr = page.locator("section.peSection").filter({
      has: page.locator("summary", { hasText: /^CLR\b/ })
    });
    await clr.locator(":scope > details > summary").click();
    await clr.locator("summary").filter({ hasText: /^Managed resources \(51\)/ }).click();
    const resources = clr.locator('[data-paged-sortable-table-id="pe-clr-managed-resources"]');
    const values = resources.locator('[data-paged-sortable-table-id="pe-clr-managed-resource-values-1"]');
    await expect(resources.locator(".clrManagedResourcesTable__row")).toHaveCount(50);
    await expect(values).toContainText("entry-000");
    await values.locator(":scope > .pagedSortableTableToolbar").getByRole("button", { name: "Next" }).click();
    await expect(values).toContainText("Привет 世界");
    await expect(values).toContainText("Parsed XML tree");
    await expect(values.locator("img")).toHaveAttribute("src", /^data:image\/png;base64,/);
    await expect(values).toContainText("truncated or unsupported");
    await values.getByRole("button", { name: "Sort by Entry", exact: true }).click();
    await expect(values).toContainText("Broken");
    await resources.locator(":scope > .pagedSortableTableToolbar").getByRole("button", { name: "Next" }).click();
    await expect(resources).toContainText("Text-048");
    await expect(resources.locator(".clrManagedResourcesTable__row")).toHaveCount(1);
    expect(await page.evaluate(() =>
      globalThis.document.documentElement.scrollWidth <= globalThis.innerWidth)).toBe(true);
    expect(errors).toEqual([]);
  });
}
