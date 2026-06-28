import { expect, test } from "@playwright/test";
import { existsSync } from "node:fs";
import { createPePlusLongEntrypointFile } from "../fixtures/pe-long-entrypoint-file.js";

const WINDOWS_SYSTEM_PE_PATHS = [
  "C:\\Windows\\System32\\notepad.exe",
  "C:\\Windows\\System32\\cmd.exe",
  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
];

const fileNameFromWindowsPath = (filePath: string): string =>
  filePath.split("\\").pop() ?? filePath;

test.describe("PE entrypoint disassembly on a real C drive binary", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Local File Inspector" })).toBeVisible();
  });

  for (const windowsSystemPePath of WINDOWS_SYSTEM_PE_PATHS) {
    const fileName = fileNameFromWindowsPath(windowsSystemPePath);

    void test(`runs entrypoint disassembly for ${fileName}`, async ({ page }) => {
      test.skip(
        process.platform !== "win32" || !existsSync(windowsSystemPePath),
        "Real C drive PE fixture is only available on Windows hosts."
      );

      await page.setInputFiles("#fileInput", windowsSystemPePath);
      await expect(page.locator("#fileNameDetail")).toHaveText(fileName);
      await expect(page.locator("#fileBinaryTypeDetail")).toContainText("PE32");

      const detailsValue = page.locator("#analysisValue");
      const entrypointSection = detailsValue.locator("details.analysisPanel").filter({
        has: page.locator("summary", { hasText: /^Entrypoint disassembly\b/ })
      }).first();
      await entrypointSection.locator(":scope > summary").click();
      await expect(entrypointSection).toHaveJSProperty("open", true);

      await detailsValue.locator("#peEntrypointDisassembleButton").click();
      await expect(entrypointSection).toContainText("Entrypoint preview:");
      await expect(entrypointSection.locator(".peEntrypointBlockIndexTable")).toBeVisible();
      await expect(entrypointSection.locator(".peEntrypointInstructionTable")).toBeVisible();
      await expect(entrypointSection).toContainText("Block index");
      await expect(entrypointSection).toContainText("Instruction");
      await expect(entrypointSection).not.toContainText("Failed to load iced-x86 disassembler");
      await expect(entrypointSection).not.toContainText("Entrypoint disassembly failed");
    });
  }

  void test("pages a long synthetic entrypoint block", async ({ page }) => {
    const mockFile = createPePlusLongEntrypointFile();
    await page.setInputFiles("#fileInput", {
      name: mockFile.name,
      mimeType: mockFile.type,
      buffer: Buffer.from(mockFile.data)
    });
    await expect(page.locator("#fileNameDetail")).toHaveText("sample-x64-long-entrypoint.exe");
    const detailsValue = page.locator("#analysisValue");
    const entrypointSection = detailsValue.locator("details.analysisPanel").filter({
      has: page.locator("summary", { hasText: /^Entrypoint disassembly\b/ })
    }).first();
    await entrypointSection.locator(":scope > summary").click();
    await detailsValue.locator("#peEntrypointDisassembleButton").click();
    await expect(entrypointSection).toContainText("Instructions 1-120 of 121");
    await expect(entrypointSection.locator(
      '.peEntrypointInstructionRow[data-pe-entrypoint-rva="4216"]'
    )).toHaveCount(0);
    await entrypointSection.locator(
      '[data-pe-entrypoint-page-target="instructions"][data-pe-entrypoint-page-action="next"]'
    ).click();
    const finalRow = entrypointSection.locator(
      '.peEntrypointInstructionRow[data-pe-entrypoint-rva="4216"]'
    );
    await expect(finalRow).toBeVisible();
    await expect(finalRow).toContainText("ret");
  });
});
