import { expect, test } from "@playwright/test";
import { createElfMetadataFile } from "../fixtures/elf-metadata-file.js";
import { createPeResourcePreviewFile } from "../fixtures/pe-resource-preview-file.js";
import { openInspectionSection } from "./inspection-navigation.js";

for (const width of [390, 1280]) {
  test(`single ELF imports and exports need no extra click at ${width}px`, async ({ page }) => {
    const file = createElfMetadataFile().file;
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
      buffer: Buffer.from(file.data) });
    await openInspectionSection(page, "Imports / exports");
    const panel = page.locator('.workspacePanel[aria-label="Imports / exports"]');
    await expect(panel.getByRole("cell", { name: "puts", exact: true })).toBeVisible();
    await expect(panel.getByRole("cell", { name: "my_func", exact: true })).toBeVisible();
    await expect(panel.locator("summary.collectionSummary")).toHaveCount(0);
  });
}

test("single resource references are displayed beside the resource", async ({ page }) => {
  const file = createPeResourcePreviewFile();
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
    buffer: Buffer.from(file.data) });
  await openInspectionSection(page, "Resources");
  const connection = page.locator("section.peResourceConnections").first();
  await expect(connection.getByRole("heading", { name: "Resource references" })).toBeVisible();
  await expect(connection.locator("tbody tr")).toHaveCount(1);
  await expect(connection.locator("tbody tr")).toBeVisible();
  await expect(connection.locator("summary")).toHaveCount(0);
});
