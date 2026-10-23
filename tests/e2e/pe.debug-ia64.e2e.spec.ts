import { expect, test } from "@playwright/test";
import { createIa64ExceptionPe } from "../fixtures/pe-ia64-exception.js";

for (const width of [390, 1280]) {
  test(`IA64 exception copies show range statistics and explicit payload scope at width ${width}`, async ({ page }, testInfo) => {
    const file = createIa64ExceptionPe();
    await page.setViewportSize({ width, height: 960 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
    const panel = page.locator('[data-pe-lazy-section="debug"]');
    await panel.locator(":scope > details > summary").click();
    await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
    await panel.locator("summary").filter({ hasText: /^Exception directory \(\.pdata\)/ }).click();
    const references = panel.locator("dt").filter({ hasText: /^Unique mapped unwind references$/ });
    await expect(references).toBeVisible();
    await expect(references.locator("+ dd")).toHaveText("1");
    await expect(panel.getByText(/Recognized Windows unwind records are summarized by operation/)).toBeVisible();
    await expect(panel.locator("dt").filter({ hasText: /^Fixed stack allocations$/ }).locator("+ dd")).toHaveText("1");
    await expect(panel.locator("dt").filter({ hasText: /^Largest fixed stack allocation \(bytes\)$/ })
      .locator("+ dd")).toHaveText("48");
    await expect(panel.getByRole("img", { name: /Histogram of code range lengths/ })).toBeVisible();
    await expect(panel).not.toContainText("Handlers present");
    await expect(panel).not.toContainText("Chained (CHAININFO)");
    await page.screenshot({ path: testInfo.outputPath("ia64-exception-statistics.png"), fullPage: true });
  });
}
