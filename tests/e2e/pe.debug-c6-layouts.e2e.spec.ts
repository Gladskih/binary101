import { expect, test } from "@playwright/test";
import { createPeWithC6Layouts } from "../fixtures/pe-codeview-c6-layouts.js";

for (const width of [390, 1280]) {
  test(`C6 type layouts keep names and exact bounds with anonymous layout statistics at width ${width}`,
    async ({ page }, testInfo) => {
      const file = createPeWithC6Layouts();
      await page.setViewportSize({ width, height: 960 });
      await page.goto("/");
      await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
      const panel = page.locator('[data-pe-lazy-section="debug"]');
      await panel.locator(":scope > details > summary").click();
      await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
      const layouts = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-legacyTypeDetails"]');
      await expect(panel.getByRole("heading", { name: "C6 type layout statistics", exact: true })).toBeVisible();
      await expect(layouts).toContainText("<Array>&amp;");
      await expect(layouts).toContainText("Packet");
      await expect(layouts).toContainText("-9223372036854775808");
      await expect(layouts).toContainText("18446744073709551615");
      await expect(panel).toContainText("bit position 17; signed integer");
      await expect(layouts).not.toContainText("(unnamed)");
      await page.screenshot({ path: testInfo.outputPath("c6-type-layouts.png"), fullPage: true });
    });
}
