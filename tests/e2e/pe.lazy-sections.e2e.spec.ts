"use strict";

import { expect, test } from "@playwright/test";
import { createLargePeLegacyCoffSymbolFile } from "../fixtures/pe-coff-debug-fixtures.js";
import { createPeResourcePreviewFile } from "../fixtures/pe-resource-preview-file.js";
import { createPePlusFile } from "../fixtures/sample-files-pe.js";
import type { MockFile } from "../helpers/mock-file.js";

const toUpload = (file: MockFile) => ({
  buffer: Buffer.from(file.data),
  mimeType: file.type,
  name: file.name
});

test.describe("PE lazy sections", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Local File Inspector" })).toBeVisible();
  });

  void test("mounts resources lazily and restores nested expanded state", async ({ page }) => {
    const file = createPeResourcePreviewFile();
    await page.setInputFiles("#fileInput", toUpload(file));

    const section = page.locator('[data-pe-lazy-section="resources"]');
    const body = section.locator("[data-pe-lazy-section-body]");
    await expect(section.locator(":scope > details")).not.toHaveAttribute("open", "");
    await expect(body).toHaveJSProperty("childElementCount", 0);
    await expect(page.locator("[data-manifest-tree-viewer]")).toHaveCount(0);

    await section.locator(":scope > details > summary").click();
    await expect(body).not.toHaveJSProperty("childElementCount", 0);

    const manifest = page.locator("#analysisValue details details").filter({
      has: page.locator("summary", { hasText: /^MANIFEST\b/ })
    }).first();
    await manifest.locator(":scope > summary").click();
    const firstTreeDetails = manifest.locator("[data-manifest-tree] details").first();
    await firstTreeDetails.locator(":scope > summary").click();
    await expect(firstTreeDetails).toHaveJSProperty("open", true);

    await section.locator(":scope > details > summary").click();
    await expect(body).toHaveJSProperty("childElementCount", 0);
    await expect(page.locator("[data-manifest-tree-viewer]")).toHaveCount(0);

    await section.locator(":scope > details > summary").click();
    await expect(manifest).toHaveJSProperty("open", true);
    await expect(firstTreeDetails).toHaveJSProperty("open", true);
  });

  void test("pages legacy COFF tail symbols lazily and restores pager state", async ({ page }) => {
    const file = createLargePeLegacyCoffSymbolFile();
    await page.setInputFiles("#fileInput", toUpload(file));

    const section = page.locator('[data-pe-lazy-section="legacy-coff-tail"]');
    const details = section.locator(":scope > details");
    const body = section.locator("[data-pe-lazy-section-body]");
    await expect(section).toContainText("251 symbol-table records");
    await expect(body).toHaveJSProperty("childElementCount", 0);

    await details.locator(":scope > summary").click();
    const table = body.locator('[data-paged-sortable-table-id="pe-coff-symbols-symbols"]');
    const symbolNameCells = table.locator("tbody td:nth-child(2)");
    await expect(table).toContainText("Showing 1-250 of 251");
    await expect(table.locator("tbody tr")).toHaveCount(250);
    await expect(symbolNameCells.filter({ hasText: /^sym250$/ })).toHaveCount(0);

    await table.getByRole("button", { name: "Next" }).click();
    await expect(table).toContainText("Showing 251-251 of 251");
    await expect(table.locator("tbody tr")).toHaveCount(1);
    await expect(symbolNameCells.filter({ hasText: /^sym250$/ })).toHaveCount(1);

    await details.locator(":scope > summary").click();
    await expect(body).toHaveJSProperty("childElementCount", 0);
    await expect(page.locator('[data-paged-sortable-table-id="pe-coff-symbols-symbols"]'))
      .toHaveCount(0);

    await details.locator(":scope > summary").click();
    await expect(table).toContainText("Showing 251-251 of 251");
    await expect(table.locator("tbody tr")).toHaveCount(1);
    await expect(symbolNameCells.filter({ hasText: /^sym250$/ })).toHaveCount(1);
  });

  void test("restores keyless table sorting after lazy section remount", async ({ page }) => {
    const file = createPePlusFile();
    await page.setInputFiles("#fileInput", toUpload(file));

    const section = page.locator('[data-pe-lazy-section="data-directories"]');
    const details = section.locator(":scope > details");
    const body = section.locator("[data-pe-lazy-section-body]");
    await details.locator(":scope > summary").click();

    const sortButton = body.getByRole("button", { name: "Sort by Directory" });
    const firstDirectoryCell = body.locator(".peDataDirectoryTable tbody tr").first()
      .locator(".peDataDirectoryTable__directory");
    await sortButton.click();
    await expect(sortButton.locator("..")).toHaveAttribute("aria-sort", "ascending");
    await expect(firstDirectoryCell).toHaveText("ARCHITECTURE");

    await details.locator(":scope > summary").click();
    await expect(body).toHaveJSProperty("childElementCount", 0);

    await details.locator(":scope > summary").click();
    await expect(sortButton.locator("..")).toHaveAttribute("aria-sort", "ascending");
    await expect(firstDirectoryCell).toHaveText("ARCHITECTURE");
  });
});

test.describe("PE section entropy", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Local File Inspector" })).toBeVisible();
  });

  void test("calculates all sections only after the explicit action", async ({ page }) => {
    const file = createPePlusFile();
    await page.setInputFiles("#fileInput", toUpload(file));

    const section = page.locator('[data-pe-lazy-section="section-headers"]');
    await section.locator(":scope > details > summary").click();
    const entropyValue = section.locator('[data-section-entropy-index="0"]');
    await expect(entropyValue).toHaveText("Not calculated");

    await section.getByRole("button", { name: "Calculate entropy for all sections" }).click();

    await expect(entropyValue).toHaveText(/^\d+\.\d{2}$/);
    await expect(section.getByRole("button", {
      name: "Recalculate entropy for all sections"
    })).toBeVisible();
    await expect(section.locator("[data-section-entropy-status]")).toHaveText(
      "Calculated for 1 of 1 sections."
    );
  });
});
