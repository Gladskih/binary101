import { expect, test } from "@playwright/test";
import { createPeWithV12ExceptionCopy } from "../fixtures/pe-debug-file.js";

for (const width of [390, 1280]) {
  test(`v1/v2 unwind summaries preserve semantic operands at width ${width}`, async ({ page }, testInfo) => {
    const file = createPeWithV12ExceptionCopy();
    await page.setViewportSize({ width, height: 960 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
    const panel = page.locator('[data-pe-lazy-section="debug"]');
    await panel.locator(":scope > details > summary").click();
    await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
    await panel.locator("summary").filter({ hasText: /^Exception directory/ }).click();
    const operations = panel.getByRole("table", { name: "AMD64 v1/v2 unwind operations", exact: true });
    await expect(operations).toBeVisible();
    await expect(operations.getByRole("row").filter({ hasText: "ALLOC SMALL" })).toContainText("1");
    await expect(panel.getByRole("table", { name: "Saved registers", exact: true })).toContainText("XMM6");
    await expect(panel.getByRole("table", { name: "Frame registers", exact: true })).toContainText("RBP");
    await expect(panel.locator("dt").filter({ hasText: /^UNWIND_INFO v1\/v2 blocks summarized$/ })
      .locator("+ dd")).toHaveText("1");
    await expect(panel.getByText(/not reconstructed function-frame sizes/)).toBeVisible();
    await expect(panel.getByRole("columnheader", { name: "RVA", exact: true })).toHaveCount(0);
    await page.screenshot({ path: testInfo.outputPath("unwind-v12-statistics.png"), fullPage: true });
  });
}
