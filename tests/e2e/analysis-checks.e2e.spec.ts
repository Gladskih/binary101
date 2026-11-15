import { expect, test } from "@playwright/test";
import { createPePlusFile } from "../fixtures/sample-files-pe.js";
import { createPeDwarfFile } from "../fixtures/pe-dwarf-file.js";
import { createElfMetadataFile } from "../fixtures/elf-metadata-file.js";
import { createElfNativeAotFixture } from "../helpers/elf-native-aot-fixture.js";
import { openInspectionSection } from "./inspection-navigation.js";

for (const width of [390, 1258]) {
  for (const colorScheme of ["dark", "light"] as const) {
    test(`automatic checks form a flat list of undetected features at ${width}px in ${colorScheme}`,
      async ({ page }) => {
        await page.setViewportSize({ width, height: 900 });
        await page.emulateMedia({ colorScheme });
        await page.goto("/");
        const file = createPePlusFile();
        await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
          buffer: Buffer.from(file.data) });
        await openInspectionSection(page, "Checks without findings");

        const checks = page.locator(".checksWithoutFindings");
        await expect(checks.getByRole("list")).toHaveCount(1);
        await expect(checks.locator("ul ul,dl,table")).toHaveCount(0);
        await expect(checks.getByText("Go runtime metadata", { exact: true })).toBeVisible();
        await expect(checks.getByText("DWARF debug information", { exact: true })).toBeVisible();
        await expect(checks.getByText("Qt RCC", { exact: true })).toBeVisible();
        await expect(checks.getByText("GLib GResource", { exact: true })).toBeVisible();
        await expect(checks).not.toContainText("PE packagers");
        await expect(checks).toContainText("not detected does not mean absent");
        expect(await page.locator("html").evaluate(element => element.scrollWidth))
          .toBeLessThanOrEqual(width);
      });
    test(`undetected ELF metadata is listed at ${width}px in ${colorScheme}`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await page.emulateMedia({ colorScheme });
      await page.goto("/");
      const file = createElfMetadataFile().file;
      await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
        buffer: Buffer.from(file.data) });
      await openInspectionSection(page, "Checks without findings");

      const checks = page.locator(".checksWithoutFindings");
      await expect(checks.getByText("NativeAOT", { exact: true })).toBeVisible();
      await expect(checks.getByText("DWARF debug information", { exact: true })).toBeVisible();
      await expect(checks.getByText("Go build information", { exact: true })).toBeVisible();
      await expect(checks.getByText("ReadyToRun", { exact: true })).toHaveCount(0);
      await expect(checks.locator("ul ul")).toHaveCount(0);
    });
  }
}

test("found DWARF is not reported among searches without evidence", async ({ page }) => {
  await page.goto("/");
  const file = createPeDwarfFile();
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
    buffer: Buffer.from(file.data) });
  await openInspectionSection(page, "Checks without findings");

  await expect(page.locator(".checksWithoutFindings")
    .getByText("DWARF debug information", { exact: true })).toHaveCount(0);
  await openInspectionSection(page, "DWARF debug information");
  await expect(page.locator("#workspaceTitle")).toHaveText("DWARF debug information");
});

test("found ELF NativeAOT remains in its detail view and not in the undetected list", async ({ page }) => {
  await page.goto("/");
  const file = createElfNativeAotFixture().file;
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
    buffer: Buffer.from(file.data) });
  await openInspectionSection(page, "Checks without findings");

  await expect(page.locator(".checksWithoutFindings")
    .getByText("NativeAOT", { exact: true })).toHaveCount(0);
  await openInspectionSection(page, "NativeAOT metadata");
  await expect(page.locator('[data-elf-lazy-section="native-aot"]')).toContainText("ReadyToRun");
});
