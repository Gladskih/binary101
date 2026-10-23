import { expect, test } from "@playwright/test";
import { createPeCodeViewOverlay } from "../fixtures/pe-codeview-locations.js";
import { createCv3CodeView, cv3Trailer } from "../fixtures/pe-codeview-cv3.js";

test("NB00 overlay retains names and source summaries on a narrow screen", async ({ page }, testInfo) => {
  const file = createPeCodeViewOverlay(cv3Trailer(createCv3CodeView()));
  await page.setViewportSize({ width: 390, height: 960 });
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
  const panel = page.locator('[data-pe-lazy-section="debug"]');
  await panel.locator(":scope > details > summary").click();
  await panel.locator("summary").filter({ hasText: /^CodeView source #1:/ }).click();
  await expect(panel).toContainText("NB00");
  await expect(panel).toContainText("Modules (CV3)");
  await expect(panel).toContainText("wide.obj");
  await expect(panel).toContainText("old.c");
  await expect(panel).toContainText("Alias");
  await expect(panel).toContainText("stack_name");
  await expect(panel).toContainText("Distinct source lines");
  await page.screenshot({ path: testInfo.outputPath("codeview-cv3.png"), fullPage: true });
});
