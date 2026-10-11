"use strict";

import { expect, test } from "@playwright/test";
import { createPeManagedResourceFile } from "./fixtures/pe-managed-resource-file.js";
import { makeDotNetByteArrayResource, makeDotNetResources }
  from "../fixtures/dotnet-resource-file.js";

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

test("large managed resources and tables are fully available in the browser", async ({ page }) => {
  const file = createPeManagedResourceFile([
    { name: "Large.resources", bytes: makeDotNetByteArrayResource(8 * 1024 * 1024 + 1) },
    { name: "Many.resources", bytes: makeDotNetResources(Array.from({ length: 10001 }, (_, index) =>
      ({ name: `entry-${index}`, value: [0] }))) },
    { name: "Large.xml", bytes: new TextEncoder().encode(
      "<root><value>" + "x".repeat(128 * 1024 + 1) + "</value><complete-tail/></root>") }
  ]);
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.goto("/");
  await page.locator("#fileInput").setInputFiles({
    name: file.name, mimeType: file.type, buffer: Buffer.from(file.data)
  });
  const clr = page.locator("section.peSection").filter({
    has: page.locator("summary", { hasText: /^CLR\b/ })
  });
  await clr.locator(":scope > details > summary").click();
  const resources = clr.locator(".clrManagedResources");
  const many = resources.locator('[data-paged-sortable-table-id="pe-clr-managed-resource-values-2"]');
  await clr.locator("summary").filter({ hasText: /^Managed resources \(3\)/ }).click();
  await expect(resources).toContainText("8388609 bytes");
  await expect(many).toContainText("of 10001");
  await many.locator(":scope > .pagedSortableTableToolbar").getByRole("button", { name: "Last" }).click();
  await expect(many).toContainText("entry-10000");
  await expect(resources).toContainText("complete-tail");
  await expect(resources).not.toContainText("capped");
  expect(errors).toEqual([]);
});
