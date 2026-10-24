import { expect, test } from "@playwright/test";
import { createArm64UnwindSummaryPe } from "../fixtures/pe-arm64-unwind-summary.js";

for (const width of [390, 1280]) {
  test(`ARM64 unwind summaries show stack and register semantics at width ${width}`, async ({ page }, testInfo) => {
    const file = createArm64UnwindSummaryPe();
    await page.setViewportSize({ width, height: 960 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
    const panel = page.locator('[data-pe-lazy-section="debug"]');
    await panel.locator(":scope > details > summary").click();
    await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
    await panel.locator("summary").filter({ hasText: /^Exception directory/ }).click();
    const operations = panel.getByRole("table", { name: "ARM64 .xdata unwind operations", exact: true });
    await expect(operations).toBeVisible();
    await expect(operations).toContainText("save next");
    await expect(panel.getByRole("table", { name: "ARM64 .xdata saved registers", exact: true })).toContainText("X21");
    await expect(panel.getByRole("table", { name: "ARM64 packed encoded register saves", exact: true })).toContainText("D9");
    await expect(panel.locator("dt").filter({ hasText: /^ARM64 .xdata blocks decoded$/ }).locator("+ dd")).toHaveText("1");
    await expect(panel.getByText(/Shared prolog\/epilog tails count once/)).toBeVisible();
    await expect(panel).not.toContainText("decode gaps");
    await expect(panel.getByRole("columnheader", { name: "RVA", exact: true })).toHaveCount(0);
    await page.screenshot({ path: testInfo.outputPath("arm64-unwind-statistics.png"), fullPage: true });
  });
}
