import { expect, test } from "@playwright/test";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createElfNativeAotFixture } from "../helpers/elf-native-aot-fixture.js";

const REAL_NATIVE_AOT_ELF = join(tmpdir(), "binary101-nativeaot-elf", "HelloElfAot");

test("renders relocation-confirmed NativeAOT from ELF in the browser", async ({ page }) => {
  const fixture = createElfNativeAotFixture();
  await page.goto("/");

  await page.setInputFiles("#fileInput", {
    name: "native-aot.elf",
    mimeType: "application/x-elf",
    buffer: Buffer.from(fixture.bytes)
  });

  await expect(page.locator("#fileBinaryTypeDetail")).toContainText("ELF 64-bit LSB");
  const analysis = page.locator("#analysisValue");
  await expect(analysis).toContainText("NativeAOT metadata");
  await expect(analysis).toContainText("relative REL/RELA relocations");
  await expect(analysis.locator(".nativeAotSectionsTable tbody tr")).toHaveCount(2);
  await expect(analysis).toContainText("Embedded reflection metadata");
});

test("renders NativeAOT metadata from a real ELF binary in the browser", async ({ page }) => {
  test.skip(
    process.platform !== "win32" || !existsSync(REAL_NATIVE_AOT_ELF),
    "The locally published NativeAOT ELF fixture is unavailable."
  );
  await page.goto("/");

  await page.setInputFiles("#fileInput", REAL_NATIVE_AOT_ELF);

  await expect(page.locator("#fileBinaryTypeDetail")).toContainText("ELF 64-bit LSB");
  const analysis = page.locator("#analysisValue");
  await expect(analysis).toContainText("NativeAOT metadata");
  await expect(analysis).toContainText("relative REL/RELA relocations");
  await expect(analysis.locator(".nativeAotSectionsTable tbody tr")).toHaveCount(34);
  await expect(analysis.locator(".nativeAotScopesTable tbody tr")).toHaveCount(6);
  await expect(analysis).toContainText("System.Private.CoreLib.dll");
  await expect(analysis).toContainText("Showing 1-100 of 399");
  await analysis.locator(
    '[data-paged-sortable-table-id="native-aot-reflection-types"] ' +
    '[data-paged-sortable-action="next"]'
  ).click();
  await expect(analysis).toContainText("Showing 101-200 of 399");
});
