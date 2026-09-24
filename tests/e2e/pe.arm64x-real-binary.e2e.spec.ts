import { expect, test } from "@playwright/test";
import { existsSync } from "node:fs";

const ARM64X_FILE =
  "C:\\Windows\\SystemApps\\Microsoft.AIFabric.CBS.1.6_8wekyb3d8bbwe" +
  "\\Microsoft.Windows.Workloads.Resources_ec.dll";

void test("shows decoded ARM64X fixups from a real Windows DLL", async ({ page }) => {
  test.skip(process.platform !== "win32" || !existsSync(ARM64X_FILE),
    "The ARM64X Windows DLL is unavailable on this host.");
  await page.goto("/");
  await page.setInputFiles("#fileInput", ARM64X_FILE);
  await expect(page.locator("#fileNameDetail"))
    .toHaveText("Microsoft.Windows.Workloads.Resources_ec.dll");
  const loadConfig = page.locator("#analysisValue > section > details").filter({
    has: page.locator("summary", { hasText: /^Load Config\b/ })
  }).first();
  await loadConfig.locator(":scope > summary").click();
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
});
