import { expect, test } from "@playwright/test";
import { createPagedPeExportsFile } from "../fixtures/pe-export-table-file.js";
import { openInspectionSection } from "./inspection-navigation.js";

test("global search includes unmounted sections and every paginated row", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: "search.exe", mimeType: "application/octet-stream",
    buffer: Buffer.from(createPagedPeExportsFile()) });
  await expect(page.locator("#fileAnalysisDurationDetail")).not.toHaveText("");
  await expect(page.locator('[data-paged-sortable-table-id="pe-exports"]')).toHaveCount(0);
  await page.locator("#workspaceFilter").fill("Beta&lt;");
  await expect(page.locator("#reportSearchResults")).toContainText("Beta&lt;");
  await expect(page.locator("#reportSearchResults script")).toHaveCount(0);
  await page.locator("#reportSearchResults").getByRole("button", { name: "Open Export directory" }).click();
  const table = page.locator('[data-paged-sortable-table-id="pe-exports"]');
  await expect(table).toContainText("Showing 251-251 of 251");
  await expect(table.locator(".reportSearchTarget")).toContainText("Alpha<Beta&lt;");
  await expect(page.locator("#workspaceFilter")).toHaveValue("");
  await page.locator("#workspaceFilter").fill("not-found-anywhere");
  await expect(page.locator("#reportSearchResults")).toContainText("0 text matches");
  await page.locator("#workspaceFilter").press("Escape");
  await expect(page.locator("#workspaceTitle")).toHaveText("Export directory");
});

test("section search and mobile navigation work without decoded string matches", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 800 });
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: "search.exe", mimeType: "application/octet-stream",
    buffer: Buffer.from(createPagedPeExportsFile()) });
  await page.locator("#workspaceFilter").fill("DOS header");
  await page.locator("#reportSearchResults").getByRole("button", { name: "DOS header", exact: true }).click();
  await expect(page.locator("#workspaceTitle")).toHaveText("DOS header");
  await openInspectionSection(page, "Overview");
  await expect(page.locator("#fileAnalysisDurationDetail")).not.toHaveText("");
});
