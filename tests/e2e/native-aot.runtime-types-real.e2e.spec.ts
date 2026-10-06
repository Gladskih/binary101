import { expect, test } from "@playwright/test";
import { existsSync } from "node:fs";

for (const variable of ["BINARY101_NATIVE_AOT_PE", "BINARY101_NATIVE_AOT_ELF"]) {
  test(`runtime vtables paginate and separate methods from dictionary data in ${variable}`, async ({ page }) => {
    const path = process.env[variable];
    test.skip(!path || !existsSync(path), `Set ${variable} to a NativeAOT binary.`);
    await page.goto("/");
    await page.setInputFiles("#fileInput", path!);
    await page.locator(".peSectionSummary, .elfSectionSummary").filter({ hasText: "NativeAOT" }).click();
    const types = page.locator('[data-paged-sortable-table-id="native-aot-function-map-301"]');
    const slots = page.locator('[data-paged-sortable-table-id="native-aot-function-map-301-slots"]');

    await expect(types).toContainText("MethodTable RVA");
    await expect(types).toContainText("Showing 1-100");
    await types.getByRole("button", { name: "Next", exact: true }).click();
    await expect(types).toContainText("Showing 101-200");
    await slots.getByRole("columnheader", { name: "Kind" }).click();
    await expect(slots.getByRole("row").nth(1)).toContainText("data");
    await expect(slots.getByRole("row").nth(1).getByRole("cell").nth(2))
      .toHaveCSS("text-align", /^(left|start)$/);
    await expect(types.getByRole("row").nth(1).getByRole("cell").nth(0)).toHaveCSS("text-align", "right");
  });
}
