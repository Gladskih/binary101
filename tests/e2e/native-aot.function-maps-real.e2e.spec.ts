import { expect, test } from "@playwright/test";
import { existsSync } from "node:fs";

test("interop summaries preserve named fields and replace raw pointer lists with their meaning", async ({ page }) => {
  const path = process.env["BINARY101_NATIVE_AOT_SEED_SAMPLE"];
  test.skip(!path || !existsSync(path), "Publish tests/external/aot-r2r-seed-sample as NativeAOT.");
  await page.goto("/");
  await page.setInputFiles("#fileInput", path!);
  await page.locator(".peSectionSummary").filter({ hasText: "NativeAOT metadata" }).click();

  await expect(page.locator('[data-sort-state-key="native-aot-function-map-316"]')).toContainText("Unmarshal routines");
  await expect(page.locator('[data-sort-state-key="native-aot-function-map-316-fields"]')).toContainText("Number");
  await expect(page.locator('[data-sort-state-key="native-aot-function-map-317"]')).toContainText("Forward-creation stubs");
  await expect(page.locator('[data-sort-state-key="native-aot-function-map-336"]'))
    .toContainText("Generic method instantiations");
});

for (const variable of ["BINARY101_NATIVE_AOT_COMPILER_PE", "BINARY101_NATIVE_AOT_ELF"]) {
  test(`generic templates and constructors show statistics in ${variable}`, async ({ page }) => {
    const path = process.env[variable];
    test.skip(!path || !existsSync(path), "Set the compiler image path.");
    await page.goto("/");
    await page.setInputFiles("#fileInput", path!);
    await page.locator(".peSectionSummary, .elfSectionSummary").filter({ hasText: "NativeAOT" }).click();
    const templates = page.locator('[data-sort-state-key="native-aot-function-map-322"]');
    const constructors = page.locator('[data-sort-state-key="native-aot-function-map-310"]');

    await expect(templates.locator("tbody tr")).toHaveCount(5);
    await expect(constructors.locator("tbody tr")).toHaveCount(2);
    await expect(templates).toContainText("Distinct dictionary methods");
    await expect(templates).not.toContainText(/RVA|0x[0-9a-f]+/i);
    await templates.getByRole("button", { name: "Sort by Count", exact: true }).click();
    await expect(templates.locator("tbody tr").first().locator("td").nth(1)).toHaveCSS("text-align", "right");
  });
}
