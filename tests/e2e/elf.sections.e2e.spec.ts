import { openInspectionSection, toggleInspectionSection } from "./inspection-navigation.js";
import { expect, test } from "@playwright/test";
import { createElfFile } from "../fixtures/elf-sample-file.js";

for (const width of [390, 1280]) {
  test(`ELF sections stay lazy and hashes remain a file tool at width ${width}`, async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", error => errors.push(error.message));
    const file = createElfFile();
    await page.setViewportSize({ width, height: 720 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", {
      name: file.name, mimeType: file.type, buffer: Buffer.from(file.data)
    });
    const panel = page.locator("#elfInstructionSetsPanel > details");
    await expect(panel).not.toHaveAttribute("open");
    await expect(panel).toHaveClass("analysisPanel");
    await expect(panel.locator("summary")).toHaveClass("analysisPanelSummary");
    await openInspectionSection(page, "File hashes");
    await expect(page.locator("#hashDetails")).toBeVisible();
    await expect(panel).toBeHidden();
    const headers = page.locator("#analysisValue > section").filter({
      has: page.locator(".peSectionSummary", { hasText: "Section headers" })
    });
    await expect(headers.locator(".peSectionBody")).toBeEmpty();
    await toggleInspectionSection(headers.locator("summary"));
    await expect(headers.locator("table")).toBeVisible();
    await expect(headers.locator("details")).toHaveCount(1);
    await toggleInspectionSection(headers.locator("summary"));
    await expect(headers.locator(".peSectionBody")).toBeEmpty();
    await toggleInspectionSection(headers.locator("summary"));
    await expect(headers.locator("table")).toBeVisible();
    await toggleInspectionSection(panel.locator("summary").first());
    await page.locator("#elfInstructionSetsAnalyzeButton").click();
    await expect(page.locator("#elfInstructionSetsAnalyzeButton"))
      .toHaveText("Instruction sets analyzed");
    await expect(page.locator("#elfInstructionSetsPanel > details")).toHaveAttribute("open", "");
    await toggleInspectionSection(panel.locator("summary").first());
    await expect(panel.locator(".analysisPanelBody")).toBeEmpty();
    await toggleInspectionSection(panel.locator("summary").first());
    await expect(page.locator("#elfInstructionSetsAnalyzeButton"))
      .toHaveText("Instruction sets analyzed");
    expect(errors).toEqual([]);
  });
}
