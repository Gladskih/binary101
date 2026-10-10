import { expect, test } from "@playwright/test";
import { existsSync } from "node:fs";

for (const variable of ["BINARY101_NATIVE_AOT_PE", "BINARY101_NATIVE_AOT_ELF"]) {
  test(`runtime type summaries explain finalizers, sealed methods and data slots in ${variable}`, async ({ page }) => {
    const path = process.env[variable];
    test.skip(!path || !existsSync(path), `Set ${variable} to a NativeAOT binary.`);
    await page.goto("/");
    await page.setInputFiles("#fileInput", path!);
    await page.locator(".peSectionSummary, .elfSectionSummary").filter({ hasText: "NativeAOT" }).click();
    const types = page.locator('[data-sort-state-key="native-aot-function-map-301"]');

    await expect(types.locator("tbody tr")).toHaveCount(19);
    await expect(types).toContainText("Dictionary/data slots");
    await expect(types).toContainText("Distinct finalizer methods");
    await expect(types).toContainText("Distinct sealed methods");
    await expect(types).toContainText("Decoded GC layouts");
    await expect(types).toContainText("Object reference regions");
    await expect(types).toContainText("Metadata-only types with reference fields");
    await expect(types).not.toContainText(/0x[0-9a-f]+/i);
    await expect(types.getByRole("row").nth(1).getByRole("cell").nth(0))
      .toHaveCSS("text-align", /^(left|start)$/);
    await expect(types.getByRole("row").nth(1).getByRole("cell").nth(1)).toHaveCSS("text-align", "right");
    await expect(types.locator("th").nth(1)).toHaveCSS("white-space", "nowrap");
    await types.getByRole("button", { name: "Sort by Count", exact: true }).click();
    await expect(types.locator("tbody tr")).toHaveCount(19);
    await expect(page.locator('[data-sort-state-key="native-aot-function-map-301-slots"]')).toHaveCount(0);
  });
}
