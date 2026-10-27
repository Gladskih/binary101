import { expect, test } from "@playwright/test";
import { createEhFixture, addFh4, buildEhPeImage } from "../fixtures/pe-msvc-eh.js";

for (const width of [390, 1280]) {
  test(`verified FH4 records and catch details are visible at width ${width}`, async ({ page }, testInfo) => {
    const subject = createEhFixture();
    addFh4(subject);
    const file = buildEhPeImage(subject);
    await page.setViewportSize({ width, height: 960 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
    const panel = page.locator('[data-pe-lazy-section="msvc-eh"]');
    await panel.locator(":scope > details > summary").click();
    await expect(panel.getByRole("cell", { name: "FH4", exact: true })).toBeVisible();
    await expect(panel.getByRole("cell", { name: /import lookup table/ })).toBeVisible();
    await expect(panel.locator("table").first()).toHaveCSS("min-width", "1120px");
    await expect(panel.getByRole("columnheader", { name: "Handler RVA", exact: true }).first())
      .toHaveCSS("white-space", "nowrap");
    await panel.getByText("Verified catch handlers", { exact: true }).click();
    await expect(panel.getByRole("cell", { name: "catch (...)", exact: true })).toBeVisible();
    await expect(panel.getByText("the absence of exception handling", { exact: false })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath("msvc-eh.png"), fullPage: true });
  });
}
