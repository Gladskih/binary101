import { expect, test } from "@playwright/test";
import { createCeExceptionPe, ceFunctionWord } from "../fixtures/pe-ce-exception.js";

for (const width of [390, 1280]) {
  test(`CE exception copies show readable instruction and prolog statistics at width ${width}`, async ({ page }, testInfo) => {
    const file = createCeExceptionPe(0x1c2, ceFunctionWord(4, 1, 4, 1));
    await page.setViewportSize({ width, height: 960 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
    const panel = page.locator('[data-pe-lazy-section="debug"]');
    await panel.locator(":scope > details > summary").click();
    await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
    await panel.locator("summary").filter({ hasText: /^Exception directory \(\.pdata\)/ }).click();
    const instructions = panel.locator("dt").filter({ hasText: /^32-bit instruction entries$/ });
    await expect(instructions).toBeVisible();
    await expect(instructions.locator("+ dd")).toHaveText("1");
    await expect(panel.locator("dt").filter({ hasText: /^Unique resolved handlers$/ }).locator("+ dd")).toHaveText("1");
    await expect(panel.locator("dt").filter({ hasText: /^Longest prolog \(bytes\)$/ }).locator("+ dd")).toHaveText("4");
    await expect(panel).not.toContainText("UNWIND_INFO");
    await page.screenshot({ path: testInfo.outputPath("ce-exception-statistics.png"), fullPage: true });
  });
}

test("CE extended lengths remain visibly unresolved without fabricated ranges", async ({ page }) => {
  const file = createCeExceptionPe(0x1c2, ceFunctionWord(0, 0, 4, 1));
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
  const panel = page.locator('[data-pe-lazy-section="debug"]');
  await panel.locator(":scope > details > summary").click();
  await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
  await panel.locator("summary").filter({ hasText: /^Exception directory \(\.pdata\)/ }).click();
  const unknown = panel.locator("dt").filter({ hasText: /^Entries with unresolved extended lengths$/ });
  await expect(unknown).toBeVisible();
  await expect(unknown.locator("+ dd")).toHaveText("1");
  await panel.locator("summary").filter({ hasText: /^Exception directory warnings/ }).click();
  await expect(panel.getByText(/CE extended function-length metadata is not decoded/)).toBeVisible();
});
