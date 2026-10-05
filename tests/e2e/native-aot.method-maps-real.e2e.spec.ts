import { expect, test, type Page } from "@playwright/test";
import { existsSync } from "node:fs";

const verifyMethodMaps = async (page: Page, path: string): Promise<void> => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", path);
  await page.locator(".peSectionSummary").filter({ hasText: "NativeAOT metadata" }).click();
  const invoke = page.locator('[data-paged-sortable-table-id="native-aot-invoke-map"]');
  const stack = page.locator('[data-paged-sortable-table-id="native-aot-stack-trace-map"]');

  await expect(invoke).toContainText("Invoke stub RVA");
  await expect(stack).toContainText("Method RVA");
  await expect(invoke.locator("tbody tr")).toHaveCount(100);
  await expect(stack.locator("tbody tr")).toHaveCount(100);
  await expect(invoke.locator("tbody tr").first().locator("td").nth(3)).toHaveCSS("text-align", "right");
  await invoke.getByRole("button", { name: "Next", exact: true }).click();
  await expect(invoke).toContainText("Showing 101-");
  await invoke.getByRole("button", { name: "Sort by Entry point RVA", exact: true }).click();
  await expect(invoke).toContainText("Showing 1-100");
  await stack.getByRole("button", { name: "Next", exact: true }).click();
  await expect(stack).toContainText("Showing 101-200");
  await stack.getByRole("button", { name: "Sort by Method RVA", exact: true }).click();
  await expect(stack).toContainText("Showing 1-100");
};

test("NativeAOT PE method and stack-trace maps retain paging and sorting", async ({ page }) => {
  const path = process.env["BINARY101_NATIVE_AOT_PE"];
  test.skip(!path || !existsSync(path), "Set BINARY101_NATIVE_AOT_PE to the published Sample.exe.");
  await verifyMethodMaps(page, path!);
});

test("NativeAOT ELF method and stack-trace maps retain paging and sorting", async ({ page }) => {
  const path = process.env["BINARY101_NATIVE_AOT_ELF"];
  test.skip(!path || !existsSync(path), "Set BINARY101_NATIVE_AOT_ELF to a Linux NativeAOT image.");
  await verifyMethodMaps(page, path!);
});
