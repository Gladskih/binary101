import { expect, test } from "@playwright/test";
import { existsSync } from "node:fs";

for (const variable of ["BINARY101_NATIVE_AOT_PE", "BINARY101_NATIVE_AOT_ELF"]) {
  test(`method maps show compact explained counts in ${variable}`, async ({ page }) => {
    const path = process.env[variable];
    test.skip(!path || !existsSync(path), `Set ${variable} to a NativeAOT binary.`);
    await page.goto("/");
    await page.setInputFiles("#fileInput", path!);
    await page.locator(".peSectionSummary, .elfSectionSummary").filter({ hasText: "NativeAOT" }).click();
    const invoke = page.locator('[data-sort-state-key="native-aot-invoke-map"]');
    const stack = page.locator('[data-sort-state-key="native-aot-stack-trace-map"]');

    await expect(invoke.locator("tbody tr")).toHaveCount(4);
    await expect(stack.locator("tbody tr")).toHaveCount(5);
    await expect(invoke).toContainText("Distinct invocation stubs");
    await expect(stack).toContainText("Distinct compiled methods");
    await expect(invoke).not.toContainText(/RVA|0x[0-9a-f]+/i);
    await expect(stack).not.toContainText(/RVA|0x[0-9a-f]+/i);
    await expect(invoke.locator("tbody tr").first().locator("td").nth(1)).toHaveCSS("text-align", "right");
  });
}
