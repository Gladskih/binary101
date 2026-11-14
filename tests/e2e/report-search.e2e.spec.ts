import { expect, test } from "@playwright/test";
import { createPagedPeExportsFile } from "../fixtures/pe-export-table-file.js";
import { openInspectionSection } from "./inspection-navigation.js";
import { createElfMetadataFile } from "../fixtures/elf-metadata-file.js";

test("global search includes unmounted sections and every paginated row", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: "search.exe", mimeType: "application/octet-stream",
    buffer: Buffer.from(createPagedPeExportsFile()) });
  await expect(page.locator("#fileAnalysisDurationDetail")).not.toHaveText("");
  await expect(page.locator('[data-paged-sortable-table-id="pe-exports"]')).toHaveCount(0);
  await page.locator("#workspaceFilter").fill("Beta&lt;");
  await expect(page.locator("#reportSearchResults")).toContainText("Beta&lt;");
  await expect(page.locator("#reportSearchResults mark")).toHaveText("Beta&lt;");
  await expect(page.locator("#workspaceNavigation").getByRole("button", { name: /^DOS header/ }))
    .toBeVisible();
  await expect(page.locator("#workspaceNavigationEmpty")).toBeHidden();
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

for (const width of [390, 1280]) {
  for (const colorScheme of ["light", "dark"] as const) {
    test(`absent ELF tag search at ${width}px in ${colorScheme}`, async ({ page }) => {
      await page.setViewportSize({ width, height: 800 });
      await page.emulateMedia({ colorScheme });
      await page.goto("/");
      await page.setInputFiles("#fileInput", { name: "search.elf", mimeType: "application/x-elf",
        buffer: Buffer.from(await createElfMetadataFile().file.arrayBuffer()) });
      await expect(page.locator("#fileAnalysisDurationDetail")).not.toHaveText("");
      const linking = page.locator('[data-elf-lazy-section="linking"]');
      await expect(linking.locator(".peSectionBody")).toBeEmpty();
      await page.locator("#workspaceFilter").fill("rPaTh");
      const result = page.locator("#reportSearchResults").getByRole("button", {
        name: /Dynamic linking.*DT_RPATH/
      });
      await expect(result).toBeVisible();
      await expect(linking.locator(".peSectionBody")).toBeEmpty();
      await page.locator("html").evaluate(element => { element.style.zoom = "2"; });
      await expect(result).toBeVisible();
      await page.locator("html").evaluate(element => { element.style.zoom = "1"; });
      await page.screenshot({ path: `test-results/search-rpath-${width}-${colorScheme}.png` });
      await result.focus();
      await result.press("Enter");
      await expect(page.locator("#workspaceTitle")).toHaveText("Dynamic linking");
      await expect(linking.locator(".reportSearchTarget")).toHaveText(/DT_RPATH/);
      await expect(linking.locator("[data-elf-dynamic-coverage] dt")
        .filter({ hasText: /^DT_RPATH/ }).locator("+ dd")).toHaveText("Absent");
    });
  }
}

test("section search and mobile navigation work without decoded string matches", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 800 });
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: "search.exe", mimeType: "application/octet-stream",
    buffer: Buffer.from(createPagedPeExportsFile()) });
  await page.locator("#workspaceFilter").fill("DOS header");
  await page.locator("#reportSearchResults").getByRole("button", { name: "DOS header", exact: true }).click();
  await expect(page.locator("#workspaceTitle")).toHaveText("DOS header");
  await openInspectionSection(page, "File hashes");
  await expect(page.locator("#fileAnalysisDurationDetail")).not.toHaveText("");
});
