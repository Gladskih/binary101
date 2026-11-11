import { toggleInspectionSection } from "./inspection-navigation.js";
"use strict";

import { expect, test } from "@playwright/test";
import { createPeImportNamesFile } from "../fixtures/pe-import-names-file.js";

test("eager and delay MSVC imports retain signatures through paging and lazy remount", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", {
    buffer: Buffer.from(createPeImportNamesFile()), name: "imports.exe",
    mimeType: "application/octet-stream"
  });
  for (const section of ["imports", "delay-imports"]) {
    const details = page.locator(`[data-pe-lazy-section="${section}"] > details`);
    await toggleInspectionSection(details.locator(":scope > summary"));
    await toggleInspectionSection(details.locator("details").first().locator(":scope > summary"));
    const table = details.locator("[data-paged-sortable-table-root]");
    await table.getByRole("button", { name: "Next", exact: true }).click();
    await expect(table).toContainText("int __cdecl demo::square<int>(int)");
    await expect(table).toContainText("??$square@H@demo@@YAHH@Z");
    await toggleInspectionSection(details.locator(":scope > summary"));
    await toggleInspectionSection(details.locator(":scope > summary"));
    await expect(table).toContainText("int __cdecl demo::square<int>(int)");
    await table.getByRole("button", { name: "First", exact: true }).click();
    await table.getByRole("button", { name: "Sort by #", exact: true }).click();
    await table.getByRole("button", { name: "Sort by #", exact: true }).click();
    await expect(table.locator("tbody tr").first()).toContainText("demo::square<int>");
  }
});

test("unavailable import WASM preserves raw names and the next file recovers", async ({ page }) => {
  await page.route("**/*llvm-msvc-demangle*.wasm", route => route.abort());
  await page.goto("/");
  const file = { buffer: Buffer.from(createPeImportNamesFile()), name: "imports.exe",
    mimeType: "application/octet-stream" };
  await page.setInputFiles("#fileInput", file);
  const details = page.locator('[data-pe-lazy-section="imports"] > details');
  await toggleInspectionSection(details.locator(":scope > summary"));
  await expect(details).toContainText("Import name demangling unavailable:");
  await toggleInspectionSection(details.locator("details").first().locator(":scope > summary"));
  await details.getByRole("button", { name: "Next", exact: true }).click();
  await expect(details).toContainText("??$square@H@demo@@YAHH@Z");
  await page.unroute("**/*llvm-msvc-demangle*.wasm");
  await page.setInputFiles("#fileInput", file);
  await toggleInspectionSection(details.locator(":scope > summary"));
  await toggleInspectionSection(details.locator("details").first().locator(":scope > summary"));
  await details.getByRole("button", { name: "Next", exact: true }).click();
  await expect(details).toContainText("int __cdecl demo::square<int>(int)");
});
