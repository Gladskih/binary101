import { expect, test } from "@playwright/test";
import { existsSync } from "node:fs";

const WINDOWS_SYSTEM_PE_PATH = "C:\\Windows\\System32\\notepad.exe";

test.describe("PE entrypoint disassembly on a real C drive binary", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Local File Inspector" })).toBeVisible();
  });

  void test("runs entrypoint disassembly for notepad.exe", async ({ page }) => {
    test.skip(
      process.platform !== "win32" || !existsSync(WINDOWS_SYSTEM_PE_PATH),
      "Real C drive PE fixture is only available on Windows hosts."
    );

    await page.setInputFiles("#fileInput", WINDOWS_SYSTEM_PE_PATH);
    await expect(page.locator("#fileNameDetail")).toHaveText("notepad.exe");
    await expect(page.locator("#fileBinaryTypeDetail")).toContainText("PE32");

    const detailsValue = page.locator("#analysisValue");
    const entrypointSection = detailsValue.locator("details.analysisPanel").filter({
      has: page.locator("summary", { hasText: /^Entrypoint disassembly\b/ })
    }).first();
    await entrypointSection.locator(":scope > summary").click();
    await expect(entrypointSection).toHaveJSProperty("open", true);

    await detailsValue.locator("#peEntrypointDisassembleButton").click();
    await expect(entrypointSection).toContainText("Entrypoint preview:");
    await expect(entrypointSection).toContainText("Instruction");
    await expect(entrypointSection).not.toContainText("Failed to load iced-x86 disassembler");
    await expect(entrypointSection).not.toContainText("Entrypoint disassembly failed");
  });
});
