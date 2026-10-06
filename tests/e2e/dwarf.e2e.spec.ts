"use strict";

import { expect, test } from "@playwright/test";
import {
  createPeCompressedDwarfFile,
  createPeDwarfFile, createPeSemanticDwarfFile
} from "../fixtures/pe-dwarf-file.js";
import {
  createElfCompressedDwarfFile,
  createElfDwarfFile, createElfSemanticDwarfFile
} from "../fixtures/elf-dwarf-file.js";

const toUpload = (file: ReturnType<typeof createPeDwarfFile>) => ({
  name: file.name,
  mimeType: file.type,
  buffer: Buffer.from(file.data)
});

void test("renders PE DWARF analysis lazily from long COFF section names", async ({ page }) => {
  const file = createPeDwarfFile();
  await page.goto("/");
  await page.setInputFiles("#fileInput", toUpload(file));

  const summary = page.locator('[data-pe-lazy-section="dwarf"] > details > summary');
  await expect(summary).toContainText("DWARF debug information");
  await expect(page.getByText("main.c", { exact: true })).toHaveCount(0);
  await summary.click();
  await expect(page.getByText("main.c", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("fixture compiler", { exact: true })).toBeVisible();
  await expect(page.getByText("DW_TAG_subprogram", { exact: true })).toBeAttached();
});

void test("renders ELF DWARF analysis in the build/debug section", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", toUpload(createElfDwarfFile()));

  await page.locator(".peSectionSummary").filter({ hasText: "Build / debug" }).click();
  const summary = page.getByText("DWARF debug information (1 unit)", { exact: true });
  await expect(summary).toBeVisible();
  await summary.click();
  await expect(page.getByText("main.c", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("fixture compiler", { exact: true })).toBeVisible();
});

void test("decompresses and renders GNU zlib DWARF from PE", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", toUpload(createPeCompressedDwarfFile()));

  const summary = page.locator('[data-pe-lazy-section="dwarf"] > details > summary');
  await expect(summary).toContainText("DWARF debug information");
  await summary.click();
  await expect(page.getByText("main.c", { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("heading", { name: "Line programs" })).toBeVisible();
  await expect(page.getByText("decompressed; decoded", { exact: true }).first()).toBeVisible();
});

void test("decompresses and renders ELF64 SHF_COMPRESSED DWARF", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", toUpload(createElfCompressedDwarfFile()));

  await page.locator(".peSectionSummary").filter({ hasText: "Build / debug" }).click();
  const summary = page.getByText("DWARF debug information (1 unit)", { exact: true });
  await expect(summary).toBeVisible();
  await summary.click();
  await expect(page.getByText("main.c", { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("heading", { name: "Line programs" })).toBeVisible();
  await expect(page.getByText("decompressed; decoded", { exact: true }).first()).toBeVisible();
});

void test("PE DWARF shows function types, source declarations, and parameter storage", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", toUpload(createPeSemanticDwarfFile()));
  await page.locator('[data-pe-lazy-section="dwarf"] > details > summary').click();

  const entities = page.getByRole("heading", { name: "Program entities" }).locator("+ div");
  await expect(entities.getByRole("cell", { name: "calculate::input", exact: true })).toBeVisible();
  await expect(entities.getByRole("cell", { name: "/project/src/main.c:7", exact: true })).toBeVisible();
  await expect(entities.getByRole("columnheader", { name: "Code bytes" })).toBeVisible();
  await entities.getByText("Attributes", { exact: true }).last().click();
  await expect(entities.getByText("frame base \u22128 bytes", { exact: true })).toBeVisible();
});

void test("ELF DWARF shows complete program entities without address arithmetic", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", toUpload(createElfSemanticDwarfFile()));
  await page.locator(".peSectionSummary").filter({ hasText: "Build / debug" }).click();
  await page.getByText("DWARF debug information (1 unit)", { exact: true }).click();

  await expect(page.getByRole("cell", { name: "calculate::input", exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "/project/src/main.c:7", exact: true })).toBeVisible();
});

void test("PE DWARF page navigation reaches every entity", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", toUpload(createPeSemanticDwarfFile(201)));
  await page.locator('[data-pe-lazy-section="dwarf"] > details > summary').click();
  const table = page.locator('[data-paged-sortable-table-id="dwarf-entities"]');

  await expect(table.getByRole("cell", { name: "calculate::input200", exact: true })).toHaveCount(0);
  await table.getByRole("button", { name: "Last", exact: true }).click();
  await expect(table.getByRole("cell", { name: "calculate::input200", exact: true })).toBeVisible();
  await table.getByRole("button", { name: "First", exact: true }).click();
  await expect(table.getByRole("cell", { name: "int", exact: true }).first()).toBeVisible();
});

void test("ELF DWARF page navigation reaches every entity", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", toUpload(createElfSemanticDwarfFile(201)));
  await page.locator(".peSectionSummary").filter({ hasText: "Build / debug" }).click();
  await page.getByText("DWARF debug information (1 unit)", { exact: true }).click();
  const table = page.locator('[data-paged-sortable-table-id="dwarf-entities"]');

  await table.getByRole("button", { name: "Last", exact: true }).click();
  await expect(table.getByRole("cell", { name: "calculate::input200", exact: true })).toBeVisible();
});
