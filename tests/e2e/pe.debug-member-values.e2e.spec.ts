import { expect, test } from "@playwright/test";
import { createPeWithCodeViewMemberValues } from "../fixtures/pe-codeview-numeric-values.js";

for (const width of [390, 1280]) {
  test(`CodeView members retain exact values and readable placement at width ${width}`, async ({ page }, testInfo) => {
    const file = createPeWithCodeViewMemberValues();
    await page.setViewportSize({ width, height: 960 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(file.data) });
    const panel = page.locator('[data-pe-lazy-section="debug"]');
    await panel.locator(":scope > details > summary").click();
    await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
    const table = panel.locator('[data-sort-state-key="pe-debug-entry-0-legacy-members"]');
    await expect(table).toBeVisible();
    await expect(table.getByRole("cell", { name: "18446744073709551615", exact: true }))
      .toHaveCSS("white-space", "nowrap");
    await expect(table.getByRole("cell", { name: "18446744073709551615", exact: true })).toBeVisible();
    await expect(table.getByRole("cell", { name: "<count>&amp;", exact: true })).toBeVisible();
    await expect(table.getByRole("cell", { name: "offset: 12 bytes", exact: true })).toBeVisible();
    await expect(table.getByRole("cell", { name: "int32", exact: true })).toBeVisible();
    await expect(table.getByRole("cell", {
      name: "bitfield (bit width: 3, bit offset: 1) of uint32", exact: true
    })).toBeVisible();
    await expect(table.getByRole("cell", { name: "private", exact: true })).toBeVisible();
    await expect(table).not.toContainText("0x");
    await expect(panel).not.toContainText("payload is not decoded");
    await table.getByRole("button", { name: "Sort by Value / placement", exact: true }).click();
    await expect(table.locator("tbody tr").filter({ hasText: /largest|previous/ }).locator("td:nth-child(4)"))
      .toHaveText(["previous", "largest"]);
    await page.screenshot({ path: testInfo.outputPath("codeview-member-values.png"), fullPage: true });
  });
}
