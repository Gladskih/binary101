import { expect, test } from "@playwright/test";
import { createPeWithCodeViewContexts } from "../fixtures/pe-codeview-contexts.js";

for (const width of [390, 1280]) {
  test(`CodeView lexical contexts remain readable at width ${width}`, async ({ page }, testInfo) => {
    const file = createPeWithCodeViewContexts();
    await page.setViewportSize({ width, height: 960 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
    const panel = page.locator('[data-pe-lazy-section="debug"]');
    await panel.locator(":scope > details > summary").click();
    await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
    const scopes = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-lexicalScopes"]');
    const locals = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-localVariables"]');
    await expect(scopes).toContainText("thunk: adjustor");
    await expect(scopes).toContainText("with: object.member");
    await expect(scopes).toContainText("12 declared code bytes");
    await expect(locals.getByRole("row").filter({ hasText: "inlined" })).toContainText("inlinee #4100");
    await expect(locals.getByRole("row").filter({ hasText: "thunkLocal" })).toContainText("validated thunk scope");
    expect(await page.locator("body").evaluate(element => element.scrollWidth)).toBeLessThanOrEqual(width);
    await page.screenshot({ path: testInfo.outputPath("codeview-contexts.png"), fullPage: true });
  });
}
