import { expect, test } from "@playwright/test";
import { createPeWithCodeViewComposites } from "../fixtures/pe-codeview-composites.js";

for (const width of [390, 1280]) {
  test(`CodeView composite types keep sizes and field ownership readable at width ${width}`, async ({ page }, testInfo) => {
    const file = createPeWithCodeViewComposites();
    await page.setViewportSize({ width, height: 960 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
    const panel = page.locator('[data-pe-lazy-section="debug"]');
    await panel.locator(":scope > details > summary").click();
    await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
    const types = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-types"]');
    const members = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-members"]');
    await expect(types.getByRole("cell", { name: "<Packet>&amp;", exact: true })).toBeVisible();
    await expect(types.getByRole("cell", { name: ".?AU<Packet>&amp;@@", exact: true })).toBeVisible();
    await expect(types.getByRole("cell", { name: "16", exact: true })).toHaveCSS("white-space", "nowrap");
    await expect(types.getByRole("columnheader", { name: "Sort by Byte size", exact: true })).toHaveClass(/peNumeric/);
    await expect(types.getByRole("cell", { name: "fields: 3 records", exact: true })).toBeVisible();
    await expect(types.getByRole("cell", { name: "fields: 2 records; underlying type: uint32", exact: true })).toBeVisible();
    await expect(members.getByRole("cell", { name: "<Packet>&amp;", exact: true })).toHaveCount(3);
    await expect(members.getByRole("cell", { name: "State", exact: true })).toHaveCount(2);
    await expect(members.getByRole("cell", { name: "array (byte size: 12) of int32", exact: true })).toBeVisible();
    await expect(members.getByRole("cell", { name: "method list (variants: 2)", exact: true })).toBeVisible();
    const functions = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-functions"]');
    await expect(functions.getByRole("cell", { name: "<Packet>&amp;::read", exact: true })).toHaveCount(2);
    await expect(functions.getByRole("cell", { name: "(no parameters)", exact: true })).toBeVisible();
    await expect(functions.getByRole("cell", { name: "int32", exact: true })).toHaveCount(3);
    await expect(panel.getByRole("cell", { name: "Virtual table slots", exact: true })).toBeVisible();
    await expect(panel).not.toContainText("CodeView type record:");
    await page.screenshot({ path: testInfo.outputPath("codeview-composites.png"), fullPage: true });
  });
}

test("CodeView incomplete overload lists retain recovered signatures and display their declared deficit", async ({ page }) => {
  const file = createPeWithCodeViewComposites(3);
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
  const panel = page.locator('[data-pe-lazy-section="debug"]');
  await panel.locator(":scope > details > summary").click();
  await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
  await expect(panel).toContainText("read: declared variants 3; recovered variants 2");
  const members = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-members"]');
  await expect(members.getByRole("cell", { name: "3 declared overloads", exact: true })).toBeVisible();
  const functions = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-functions"]');
  await expect(functions.getByRole("cell", { name: "<Packet>&amp;::read", exact: true })).toHaveCount(2);
});
