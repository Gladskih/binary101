import { expect, test } from "@playwright/test";
import { createSanitizerPeFile } from "../fixtures/sanitizer-pe-file.js";
import { createElfMetadataFile } from "../fixtures/elf-metadata-file.js";

for (const width of [390, 1280]) {
  test(`PE sanitizer evidence stays lazy and survives reopening at width ${width}`, async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.setViewportSize({ width, height: 720 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: "asan.exe", mimeType: "application/octet-stream",
      buffer: Buffer.from(createSanitizerPeFile()) });
    const section = page.locator('[data-pe-lazy-section="sanitizers"]');
    await expect(section.locator(".peSectionBody")).toBeEmpty();
    await section.locator("summary").first().click();
    await expect(section.getByRole("columnheader", { name: "Evidence kind" })).toBeVisible();
    await expect(section).toContainText("Runtime dependency");
    await expect(section).toContainText("__asan_report_load4");
    await expect(section).toContainText("does not prove");
    await section.locator("summary").first().click();
    await expect(section.locator(".peSectionBody")).toBeEmpty();
    await section.locator("summary").first().click();
    await expect(section).toContainText("__asan_report_load4");
    expect(errors).toEqual([]);
  });

  test(`ELF distinguishes runtime dependencies from inconclusive absence at width ${width}`, async ({ page }) => {
    const file = createElfMetadataFile(["libasan.so.8", "libc.so.6"]).file;
    await page.setViewportSize({ width, height: 720 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
      buffer: Buffer.from(file.data) });
    const section = page.locator('[data-elf-lazy-section="sanitizers"]');
    await expect(section.locator(".peSectionBody")).toBeEmpty();
    await section.locator("summary").first().click();
    await expect(section).toContainText("libasan.so.8");
    await expect(section).toContainText("Runtime dependency");
    await expect(section).not.toContainText("ABI reference");
    const plain = createElfMetadataFile().file;
    await page.setInputFiles("#fileInput", { name: plain.name, mimeType: plain.type,
      buffer: Buffer.from(plain.data) });
    await section.locator("summary").first().click();
    await expect(section).toContainText("No supported sanitizer evidence");
    await expect(section).toContainText("trap-only");
  });
}
