import { toggleInspectionSection } from "./inspection-navigation.js";
import { expect, test } from "@playwright/test";
import { existsSync } from "node:fs";

const ARM64X_FILE =
  "C:\\Windows\\SystemApps\\Microsoft.AIFabric.CBS.1.6_8wekyb3d8bbwe" +
  "\\Microsoft.Windows.Workloads.Resources_ec.dll";

void test("shows ARM64X fixups and the x64 extra runtime table from a real Windows DLL", async ({ page }) => {
  test.skip(process.platform !== "win32" || !existsSync(ARM64X_FILE),
    "The ARM64X Windows DLL is unavailable on this host.");
  await page.goto("/");
  await page.setInputFiles("#fileInput", ARM64X_FILE);
  await expect(page.locator("#fileNameDetail"))
    .toHaveText("Microsoft.Windows.Workloads.Resources_ec.dll");
  const loadConfig = page.locator("#analysisValue > section > details").filter({
    has: page.locator("summary", { hasText: /^Load Config\b/ })
  }).first();
  await toggleInspectionSection(loadConfig.locator(":scope > summary"));
  const fixups = loadConfig.locator(".loadConfigDynamicDetail").filter({
    has: page.getByRole("heading", { name: "ARM64X fixups" })
  });
  await expect(fixups).toBeVisible();
  await expect(fixups).toContainText(/Decoded records: [1-9]\d*/);
  // These bytes come from the first fixup in the Windows DLL named above.
  await expect(fixups.getByRole("row").nth(1))
    .toContainText("0x00000104");
  await expect(fixups.getByRole("row").nth(1))
    .toContainText("0x8664");
  await loadConfig.locator(".loadConfigReferences > summary").click();
  await expect(loadConfig.getByRole("heading", { name: "Extra x64 runtime functions" }))
    .toBeVisible();
  // First x64 runtime record at original ExtraRFETable RVA 0xF4C8, confirmed with llvm-readobj.
  await expect(loadConfig.getByRole("cell", { name: "0x00007010", exact: true })).toBeVisible();
  await expect(loadConfig.getByRole("cell", { name: "0x00007012", exact: true })).toBeVisible();
});
