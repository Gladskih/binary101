"use strict";

import { expect, test } from "@playwright/test";
import {
  createPeCompressedDwarfFile,
  createPeDwarfFile
} from "../fixtures/pe-dwarf-file.js";
import {
  createElfCompressedDwarfFile,
  createElfDwarfFile
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
  await expect(page.getByText("main.c", { exact: true })).toBeVisible();
  await expect(page.getByText("fixture compiler", { exact: true })).toBeVisible();
  await expect(page.getByText("DW_TAG_subprogram", { exact: true })).toBeAttached();
});

void test("renders ELF DWARF analysis in the build/debug section", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", toUpload(createElfDwarfFile()));

  const summary = page.getByText("DWARF debug information (1 unit)", { exact: true });
  await expect(summary).toBeVisible();
  await summary.click();
  await expect(page.getByText("main.c", { exact: true })).toBeVisible();
  await expect(page.getByText("fixture compiler", { exact: true })).toBeVisible();
});

void test("decompresses and renders GNU zlib DWARF from PE", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", toUpload(createPeCompressedDwarfFile()));

  const summary = page.locator('[data-pe-lazy-section="dwarf"] > details > summary');
  await expect(summary).toContainText("DWARF debug information");
  await summary.click();
  await expect(page.getByText("main.c", { exact: true })).toBeVisible();
  await expect(page.getByText("decompressed; decoded", { exact: true }).first()).toBeVisible();
});

void test("decompresses and renders ELF64 SHF_COMPRESSED DWARF", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", toUpload(createElfCompressedDwarfFile()));

  const summary = page.getByText("DWARF debug information (1 unit)", { exact: true });
  await expect(summary).toBeVisible();
  await summary.click();
  await expect(page.getByText("main.c", { exact: true })).toBeVisible();
  await expect(page.getByText("decompressed; decoded", { exact: true }).first()).toBeVisible();
});
