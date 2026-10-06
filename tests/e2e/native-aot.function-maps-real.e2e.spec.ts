import { expect, test, type Page } from "@playwright/test";
import { existsSync } from "node:fs";

const openNativeMap = async (page: Page, path: string): Promise<void> => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", path);
  await page.locator(".peSectionSummary").filter({ hasText: "NativeAOT metadata" }).click();
};

test("real NativeAOT marshalling and exact methods expose their code fields", async ({ page }) => {
  const path = process.env["BINARY101_NATIVE_AOT_SEED_SAMPLE"];
  test.skip(!path || !existsSync(path), "Publish tests/external/aot-r2r-seed-sample as NativeAOT.");
  await openNativeMap(page, path!);

  await expect(page.locator('[data-sort-state-key="native-aot-function-map-316"]'))
    .toContainText("Unmarshal RVA");
  await expect(page.locator('[data-sort-state-key="native-aot-function-map-316-fields"]'))
    .toContainText("Number");
  await expect(page.locator('[data-sort-state-key="native-aot-function-map-317"]'))
    .toContainText("Forward creation RVA");
  await expect(page.locator('[data-sort-state-key="native-aot-function-map-336"]'))
    .toContainText("Entry point RVA");
});

for (const variable of ["BINARY101_NATIVE_AOT_COMPILER_PE", "BINARY101_NATIVE_AOT_ELF"]) {
  test(`template and cctor maps support pagination and sorting in ${variable}`, async ({ page }) => {
    const path = process.env[variable];
    test.skip(!path || !existsSync(path), "Set the compiler image path.");
    await openNativeMap(page, path!);
    const templates = page.locator('[data-paged-sortable-table-id="native-aot-function-map-322"]');
    const constructors = page.locator('[data-paged-sortable-table-id="native-aot-function-map-310"]');

    await expect(templates.locator("tbody tr")).toHaveCount(100);
    await expect(templates.locator("tbody tr").first().locator("td").last())
      .toHaveCSS("text-align", "right");
    await templates.getByRole("button", { name: "Next", exact: true }).click();
    await expect(templates).toContainText("Showing 101-200");
    await templates.getByRole("button", { name: "Sort by Entry point RVA", exact: true }).click();
    await expect(templates).toContainText("Showing 1-100");
    await constructors.getByRole("button", { name: "Next", exact: true }).click();
    await expect(constructors).toContainText("Showing 101-200");
  });
}
