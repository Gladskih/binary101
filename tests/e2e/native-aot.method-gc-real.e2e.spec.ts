import { expect, test } from "@playwright/test";
import { existsSync } from "node:fs";

for (const variable of ["BINARY101_NATIVE_AOT_PE", "BINARY101_NATIVE_AOT_ELF"]) {
  test(`explains method GC roots and interruptibility in ${variable}`, async ({ page }) => {
    const path = process.env[variable];
    test.skip(!path || !existsSync(path), `Set ${variable} to an x64 NativeAOT binary.`);
    await page.goto("/");
    await page.setInputFiles("#fileInput", path!);
    await page.locator(".peSectionSummary, .elfSectionSummary").filter({ hasText: "NativeAOT" }).click();
    const statistics = page.locator('[data-sort-state-key="native-aot-method-gc"]');

    await expect(statistics.locator("tbody tr")).toHaveCount(10);
    await expect(statistics).toContainText("Register root slots");
    await expect(statistics).toContainText("GC interruptible ranges");
    await expect(statistics).toContainText("Root liveness transitions");
    await expect(statistics).not.toContainText(/0x[0-9a-f]+/i);
    await expect(statistics.getByRole("row").nth(1).getByRole("cell").nth(1))
      .not.toHaveText("0");
    await expect(statistics.getByRole("row").nth(1).getByRole("cell").nth(1))
      .toHaveCSS("text-align", "right");
  });
}
