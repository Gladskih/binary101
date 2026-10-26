import { expect, test } from "@playwright/test";
import { createPeWithCodeViewLocals } from "../fixtures/pe-codeview-locals-file.js";

for (const width of [390, 1280]) {
  test(`CodeView compiler frames and named locals remain readable at width ${width}`, async ({ page }, testInfo) => {
    const file = createPeWithCodeViewLocals();
    await page.setViewportSize({ width, height: 960 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
    const panel = page.locator('[data-pe-lazy-section="debug"]');
    await panel.locator(":scope > details > summary").click();
    await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
    const locals = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-localVariables"]');
    const frames = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-compilerFrames"]');
    await expect(locals).toContainText("<inspect>&amp;");
    await expect(locals.getByRole("row").filter({ hasText: "temporary" })).toContainText("frame base - 8");
    await expect(locals.getByRole("row").filter({ hasText: "gone" })).toContainText("optimized out");
    await expect(frames).toContainText("RSP");
    await expect(locals).toContainText("validated procedure scope");
    expect(await page.locator("body").evaluate(element => element.scrollWidth)).toBeLessThanOrEqual(width);
    await page.screenshot({ path: testInfo.outputPath("codeview-locals.png"), fullPage: true });
  });
}
