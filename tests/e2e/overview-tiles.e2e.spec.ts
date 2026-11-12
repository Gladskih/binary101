import { expect, test } from "@playwright/test";
import { createPeImportNamesFile } from "../fixtures/pe-import-names-file.js";

for (const width of [390, 1258, 2530]) {
  for (const colorScheme of ["dark", "light"] as const) {
    test(`overview uses compact tile buttons at ${width}px in ${colorScheme}`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await page.emulateMedia({ colorScheme });
      await page.goto("/");
      await page.setInputFiles("#fileInput", { name: "imports.exe", mimeType: "application/octet-stream",
        buffer: Buffer.from(createPeImportNamesFile("LastImportedFunction")) });
      const card = page.locator('.workspaceCard[data-workspace-target="analysis-imports"]');
      await expect(card).toHaveRole("button");
      await expect(card).toContainText("eager.dll");
      await expect(card).toContainText("251");
      await expect(card.locator("table,ul,ol,button,a,details,[tabindex]")).toHaveCount(0);
      const size = await card.evaluate(element => ({ height: element.clientHeight,
        scroll: element.scrollHeight, width: element.getBoundingClientRect().width }));
      expect(size.height).toBeLessThanOrEqual(320);
      expect(size.scroll).toBe(size.height);
      expect(size.width).toBeLessThanOrEqual(Math.min(width, 800));

      await card.locator(".workspaceCard__body").click();

      await expect(page.locator("#workspaceTitle")).toHaveText("Import table");
      const module = page.locator('[data-pe-lazy-section="imports"] details details').first();
      await module.locator(":scope > summary").click();
      const table = module.locator("[data-paged-sortable-table-root]");
      await expect(table).toBeVisible();
      await table.getByRole("button", { name: "Last", exact: true }).click();
      await expect(table).toContainText("LastImportedFunction");
    });
  }
}
