import { expect, test } from "@playwright/test";

test("real R2R debug data explains mappings and variable lifetimes without address tables", async ({ page }) => {
  const path = process.env["BINARY101_R2R_PE"];
  test.skip(!path, "Set BINARY101_R2R_PE to a local ReadyToRun assembly.");
  await page.goto("/");
  await page.setInputFiles("#fileInput", path!);
  const panel = page.locator("[data-pe-lazy-section=clr]");
  await panel.locator(":scope > details > summary").click();
  await panel.locator("summary").filter({ hasText: /^ReadyToRun \/ managed native header$/ }).click();

  await expect(panel.getByRole("row").filter({ hasText: "Functions with debug records" }))
    .toContainText("Runtime functions whose compressed IL mappings");
  await expect(panel.getByRole("row").filter({ hasText: "Native/IL mappings" }))
    .toContainText("associate machine code positions with IL");
  await expect(panel.getByRole("row").filter({ hasText: "Variable lifetime records" }))
    .toContainText("move between registers and stack slots");
  await expect(panel.getByRole("columnheader", { name: "Native offset", exact: true })).toHaveCount(0);
  await expect(panel).not.toContainText("DebugInfo payload is truncated");
});
