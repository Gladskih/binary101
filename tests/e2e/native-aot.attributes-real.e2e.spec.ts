import { expect, test } from "@playwright/test";
import { existsSync } from "node:fs";

for (const variable of ["BINARY101_NATIVE_AOT_PE", "BINARY101_NATIVE_AOT_COMPILER9_PE", "BINARY101_NATIVE_AOT_ELF"]) {
  test(`NativeAOT attributes show owners and meaningful arguments in ${variable}`, async ({ page }) => {
    const path = process.env[variable];
    test.skip(!path || !existsSync(path), `Set ${variable} to a NativeAOT binary.`);
    await page.goto("/");
    await page.setInputFiles("#fileInput", path!);
    await page.locator(".peSectionSummary, .elfSectionSummary").filter({ hasText: "NativeAOT" }).click();
    const attributes = page.locator('[data-paged-sortable-table-id="native-aot-custom-attributes"]');

    await expect(attributes.locator("tbody tr")).toHaveCount(100);
    await expect(attributes).toContainText("TargetFrameworkAttribute");
    await expect(attributes).toContainText("FrameworkDisplayName");
    await expect(attributes.locator("th")).toHaveText([
      "Assembly", "Applied to", "Owner", "Attribute", "Arguments"
    ]);
    await expect(page.locator('[data-sort-state-key="native-aot-invoke-map"]')
      .getByRole("row").filter({ hasText: "Reflection invocation records" }).getByRole("cell").nth(1))
      .not.toHaveText("0");
    await attributes.getByRole("button", { name: "Next", exact: true }).click();
    await expect(attributes).toContainText("Showing 101-200");
    await attributes.getByRole("button", { name: "Sort by Attribute", exact: true }).click();
    await expect(attributes).toContainText("Showing 1-100");
    await expect(attributes.locator("tbody tr").first().locator("td").nth(3)).toHaveCSS("text-align", /^(left|start)$/);
  });
}

test("NativeAOT attribute names remain readable through horizontal scrolling on mobile", async ({ page }) => {
  const path = process.env["BINARY101_NATIVE_AOT_PE"];
  test.skip(!path || !existsSync(path), "Set BINARY101_NATIVE_AOT_PE to the reflection sample.");
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await page.setInputFiles("#fileInput", path!);
  await page.locator(".peSectionSummary").filter({ hasText: "NativeAOT" }).click();
  const attributes = page.locator('[data-paged-sortable-table-id="native-aot-custom-attributes"]');

  await expect(attributes.locator("tbody tr").first().locator("td").nth(2)).toHaveCSS("white-space", "nowrap");
  await expect(attributes.locator(".tableWrap")).toHaveJSProperty("scrollLeft", 0);
  expect(await attributes.locator(".tableWrap").evaluate(element => element.scrollWidth > element.clientWidth)).toBe(true);
});
