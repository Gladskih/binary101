import { expect, test } from "@playwright/test";
import { createPePlusFile, createPeRomFile } from "../fixtures/sample-files-pe.js";
import { createElfMetadataFile } from "../fixtures/elf-metadata-file.js";
import { openInspectionSection } from "./inspection-navigation.js";

for (const width of [390, 1258, 2530]) {
  for (const colorScheme of ["dark", "light"] as const) {
    test(`PE and ELF open their native headers at ${width}px in ${colorScheme}`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await page.emulateMedia({ colorScheme });
      await page.goto("/");
      const pe = createPePlusFile();
      await page.setInputFiles("#fileInput", { name: pe.name, mimeType: pe.type, buffer: Buffer.from(pe.data) });

      await expect(page.locator("#workspaceTitle")).toHaveText("PE/COFF headers");
      await expect(page.locator('[data-pe-lazy-section="pe-headers"] .peSectionBody')).toBeVisible();
      await expect(page.locator('[data-pe-lazy-section="dos-header"]')).toBeHidden();
      await expect(page.locator("#workspaceOverview,.workspaceCard")).toHaveCount(0);
      await expect(page.locator("#workspaceNavigation")).not.toContainText("Overview");
      const elf = createElfMetadataFile().file;
      await page.setInputFiles("#fileInput", { name: elf.name, mimeType: elf.type,
        buffer: Buffer.from(await elf.arrayBuffer()) });

      await expect(page.locator("#workspaceTitle")).toHaveText("ELF header");
      await expect(page.locator('[data-elf-lazy-section="header"]')).toBeVisible();
      await expect(page.locator('[data-elf-lazy-section="header"]')).toContainText("Machine");
      await expect(page.locator("#workspaceNavigation")).not.toContainText("Overview");
    });
  }
}

test("Back returns to the header without reopening the selected file", async ({ page }) => {
  await page.goto("/");
  const pe = createPePlusFile();
  await page.setInputFiles("#fileInput", { name: pe.name, mimeType: pe.type, buffer: Buffer.from(pe.data) });
  await expect(page.locator("#workspaceTitle")).toHaveText("PE/COFF headers");
  const duration = await page.locator("#fileAnalysisDurationDetail").textContent();
  await openInspectionSection(page, "DOS header");

  await page.goBack();

  await expect(page.locator("#workspaceTitle")).toHaveText("PE/COFF headers");
  await expect(page.locator("#fileNameDetail")).toHaveText(pe.name);
  await expect(page.locator("#fileAnalysisDurationDetail")).toHaveText(duration!);
  await page.goForward();
  await expect(page.locator("#workspaceTitle")).toHaveText("DOS header");
});

test("obsolete overview history entries fall back to the native header", async ({ page }) => {
  await page.goto("/");
  const pe = createPePlusFile();
  await page.setInputFiles("#fileInput", { name: pe.name, mimeType: pe.type, buffer: Buffer.from(pe.data) });
  await expect(page.locator("#workspaceTitle")).toHaveText("PE/COFF headers");
  await page.evaluate(() => {
    globalThis.history.replaceState({ ...globalThis.history.state, section: "overview" }, "");
  });
  await openInspectionSection(page, "DOS header");

  await page.goBack();

  await expect(page.locator("#workspaceTitle")).toHaveText("PE/COFF headers");
  await expect(page.locator("#fileNameDetail")).toHaveText(pe.name);
});

test("ROM PE files also open PE/COFF headers", async ({ page }) => {
  await page.goto("/");
  const pe = createPeRomFile();
  await page.setInputFiles("#fileInput", { name: pe.name, mimeType: pe.type, buffer: Buffer.from(pe.data) });

  await expect(page.locator("#workspaceTitle")).toHaveText("PE/COFF headers");
  await expect(page.locator('[data-pe-lazy-section="pe-headers"]')).toContainText("Machine");
});
