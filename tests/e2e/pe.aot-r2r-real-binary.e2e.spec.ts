import { expect, test } from "@playwright/test";
import { existsSync } from "node:fs";

// Publish the sample in tests/external/aot-r2r-sample with PublishAot=true.
const nativeAotFile = process.env["BINARY101_NATIVE_AOT_PE"];
const readyToRunFile = process.env["BINARY101_R2R_PE"];

test("renders retained NativeAOT signatures and paginates definition tables", async ({ page }) => {
  test.skip(!nativeAotFile || !existsSync(nativeAotFile), "Set BINARY101_NATIVE_AOT_PE to Sample.exe.");
  await page.goto("/");
  await page.setInputFiles("#fileInput", nativeAotFile!);
  await page.locator(".peSectionSummary").filter({ hasText: "NativeAOT metadata" }).click();
  const members = page.locator('[data-paged-sortable-table-id="native-aot-member-definitions"]');
  const definitions = page.locator('[data-paged-sortable-table-id="native-aot-type-definitions"]');

  await expect(members).toContainText("Convert<U>(!0&, !!0[], System.Int32[rank=2;");
  await expect(members).toContainText("add_Changed");
  await expect(members).toContainText("Property");
  await expect(members).toContainText("Event");
  await expect(definitions).toContainText("Sample`1");
  await expect(definitions).toContainText("System.Object");
  await expect(definitions.locator("tbody tr").first().locator("td").nth(5))
    .toHaveCSS("text-align", "right");
  await definitions.getByRole("button", { name: "Next", exact: true }).click();
  await expect(definitions).toContainText("Showing 101-200");
  await members.getByRole("button", { name: "Next", exact: true }).click();
  await expect(members).toContainText("Showing 101-200");
  await members.getByRole("button", { name: "Sort by Name", exact: true }).click();
  await expect(members).toContainText("Showing 1-100");
});

test("explains ReadyToRun methods and imports without dumping their encoded addresses", async ({ page }) => {
  test.skip(!readyToRunFile || !existsSync(readyToRunFile), "Set BINARY101_R2R_PE to System.Collections.dll.");
  await page.goto("/");
  await page.setInputFiles("#fileInput", readyToRunFile!);
  await page.locator(".peSectionSummary").filter({ hasText: "CLR (.NET) header" }).click();
  const analysis = page.locator("#analysisValue");
  await analysis.locator("summary").filter({ hasText: "ReadyToRun / managed native header" }).click();

  await expect(analysis).toContainText("Crossgen2");
  const statistics = analysis.locator('[data-sort-state-key="pe-r2r-statistics"]');
  await expect(statistics).toContainText("Method-definition entry points");
  await expect(statistics).toContainText("Instantiated method entry points");
  await expect(statistics).toContainText("Import cells with signatures");
  await expect(statistics).toContainText("Methods with GC maps");
  await expect(statistics).toContainText("GC safe points");
  await expect(statistics).not.toContainText(/\bRVA\b|0x[0-9a-f]+/i);
  await expect(analysis.locator('[data-paged-sortable-table-id$="-cells"]')).toHaveCount(0);
});
