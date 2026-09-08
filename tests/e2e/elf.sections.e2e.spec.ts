import { expect, test } from "@playwright/test";
import { createElfFile } from "../fixtures/elf-sample-file.js";

for (const width of [390, 1280]) {
  test(`ELF sections collapse and follow hashes at width ${width}`, async ({ page }) => {
    const file = createElfFile();
    await page.setViewportSize({ width, height: 720 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", {
      name: file.name, mimeType: file.type, buffer: Buffer.from(file.data)
    });
    const panel = page.locator("#elfInstructionSetsPanel > details");
    await expect(panel).not.toHaveAttribute("open");
    const hashBox = await page.locator("#hashDetails").boundingBox();
    const panelBox = await panel.boundingBox();
    const gap = await page.locator("#fileInfoCard").evaluate(element =>
      parseFloat(element.ownerDocument.defaultView!.getComputedStyle(element)
        .getPropertyValue("--content-section-gap"))
    );
    expect(panelBox!.y - hashBox!.y - hashBox!.height).toBeCloseTo(gap, 0);
    const headers = page.locator("#analysisValue > section").filter({
      has: page.locator(".peSectionSummary", { hasText: "Section headers" })
    });
    await expect(headers.locator("table")).toBeHidden();
    await headers.locator("summary").click();
    await expect(headers.locator("table")).toBeVisible();
    await expect(headers.locator("details")).toHaveCount(1);
    await headers.locator("summary").click();
    await expect(headers.locator("table")).toBeHidden();
    await panel.locator("summary").first().click();
    await page.locator("#elfInstructionSetsAnalyzeButton").click();
    await expect(page.locator("#elfInstructionSetsAnalyzeButton"))
      .toHaveText("Re-analyze instruction sets");
    await expect(page.locator("#elfInstructionSetsPanel > details")).toHaveAttribute("open", "");
  });
}
