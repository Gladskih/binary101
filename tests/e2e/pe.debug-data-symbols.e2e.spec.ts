import { expect, test } from "@playwright/test";
import { createPeWithCodeViewDataSymbols } from "../fixtures/pe-codeview-data-symbols-file.js";

test("CodeView data and public symbol metadata stay readable in the PE debug tables", async ({ page }) => {
  const file = createPeWithCodeViewDataSymbols();
  await page.setViewportSize({ width: 390, height: 960 });
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type,
    buffer: Buffer.from(file.data) });
  const panel = page.locator('[data-pe-lazy-section="debug"]');
  await panel.locator(":scope > details > summary").click();
  await panel.locator("summary").filter({ hasText: /^Entry #1:/ }).click();
  const table = panel.getByRole("heading", { name: "Data, public, block and label symbols" })
    .locator("xpath=following-sibling::div[1]");
  await expect(table.getByRole("cell", { name: "global_value", exact: true })).toBeVisible();
  await expect(table.getByRole("cell", { name: "Type index 116", exact: true })).toBeVisible();
  await expect(table.getByRole("cell", { name: "1:291", exact: true })).toBeVisible();
  await expect(table.getByRole("cell", { name: "Code, Function", exact: true })).toBeVisible();
  await expect(table.getByRole("cell", { name: "local_block", exact: true })).toBeVisible();
  await expect(table.getByRole("cell", { name: "160", exact: true })).toBeVisible();
});
