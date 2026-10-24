import { expect, test } from "@playwright/test";
import { createNtRiscPe, createNtRiscSecondaryPe, createAlphaRiscPe,
  createPowerPcCodeSignificancePe } from "../fixtures/pe-risc-exception.js";

for (const width of [390, 1280]) {
  test(`NT RISC debug copy shows readable prolog statistics at width ${width}`, async ({ page }, testInfo) => {
    const file = createNtRiscPe();
    await page.setViewportSize({ width, height: 960 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
    const panel = page.locator('[data-pe-lazy-section="debug"]');
    await panel.locator(":scope > details > summary").click();
    await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
    await panel.locator("summary").filter({ hasText: /^Exception directory \(\.pdata\)/ }).click();
    await expect(panel).toContainText("full virtual addresses");
    await expect(panel).toContainText("Inline function descriptions");
    await expect(panel).toContainText("Longest prolog (bytes)");
    await expect(panel.locator("dt").filter({ hasText: /^Longest prolog \(bytes\)$/ }).locator("+ dd")).toHaveText("16");
    await expect(panel.locator("dt").filter({ hasText: /^Longest prolog \(bytes\)$/ })).toBeVisible();
    await expect(panel).not.toContainText("EHANDLER");
    await page.screenshot({ path: testInfo.outputPath("nt-risc-statistics.png"), fullPage: true });
  });
}

test("NT RISC secondary metadata remains visibly unresolved instead of becoming a false handler address", async ({ page }) => {
  const file = createNtRiscSecondaryPe();
  await page.setViewportSize({ width: 390, height: 960 });
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
  const panel = page.locator('[data-pe-lazy-section="debug"]');
  await panel.locator(":scope > details > summary").click();
  await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
  await panel.locator("summary").filter({ hasText: /^Exception directory \(\.pdata\)/ }).click();
  const unresolved = panel.locator("dt").filter({ hasText: /^Ranges with unresolved inline metadata$/ });
  await expect(unresolved).toBeVisible();
  await expect(unresolved.locator("+ dd")).toHaveText("1");
  await panel.locator("summary").filter({ hasText: /^Exception directory warnings/ }).click();
  await expect(panel.getByText(/indirect prolog metadata is not decoded/)).toBeVisible();
  await expect(panel).not.toContainText("handler data VA could not be mapped");
});

test("Alpha debug copy summarizes exception modes and resolved secondary ranges", async ({ page }, testInfo) => {
  const file = createAlphaRiscPe();
  await page.setViewportSize({ width: 390, height: 960 });
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
  const panel = page.locator('[data-pe-lazy-section="debug"]');
  await panel.locator(":scope > details > summary").click();
  await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
  await panel.locator("summary").filter({ hasText: /^Exception directory \(\.pdata\)/ }).click();
  await expect(panel.locator("dt").filter({ hasText: /^Exception mode 7$/ }).locator("+ dd")).toHaveText("1");
  await expect(panel.locator("dt").filter({ hasText: /^Secondary ranges with known primary procedures$/ })
    .locator("+ dd")).toHaveText("1");
  await expect(panel).not.toContainText("indirect prolog metadata is not decoded");
  await expect(panel).not.toContainText("Ranges with unresolved inline metadata");
  await page.screenshot({ path: testInfo.outputPath("alpha-secondary-statistics.png"), fullPage: true });
});

test("PowerPC debug copy summarizes code markers without false handler-data warnings", async ({ page }, testInfo) => {
  const file = createPowerPcCodeSignificancePe();
  await page.setViewportSize({ width: 390, height: 960 });
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
  const panel = page.locator('[data-pe-lazy-section="debug"]');
  await panel.locator(":scope > details > summary").click();
  await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
  await panel.locator("summary").filter({ hasText: /^Exception directory \(\.pdata\)/ }).click();
  await expect(panel.locator("dt").filter({ hasText: /^PowerPC glue-code markers$/ }).locator("+ dd"))
    .toHaveText("1");
  await expect(panel.locator("dt").filter({ hasText: /^PowerPC register-save millicode markers$/ }))
    .toBeVisible();
  await expect(panel).toContainText("PowerPC register-restore millicode markers");
  await expect(panel).not.toContainText("handler data VA could not be mapped");
  await page.screenshot({ path: testInfo.outputPath("powerpc-code-markers.png"), fullPage: true });
});
