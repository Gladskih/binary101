import { expect, test } from "@playwright/test";
import { createPePlusWithSection } from "../fixtures/sample-files-pe.js";
import { aarch64Code } from "../fixtures/aarch64-code.js";

test("PE ARM64 analyzes with local WASM and displays architecture requirements", async ({ page }) => {
  const bytes = createPePlusWithSection();
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  // PE/COFF: e_lfanew points to the signature, followed by COFF Machine.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
  view.setUint16(view.getUint32(0x3c, true) + 4, 0xaa64, true);
  bytes.set(aarch64Code([0x04a00000, 0xd65f03c0]).data, 0x200);
  const errors: string[] = [];
  const requests: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  page.on("request", request => requests.push(request.url()));
  await page.goto("/");
  await page.setInputFiles("#fileInput", {
    name: "arm64.exe", mimeType: "application/octet-stream", buffer: Buffer.from(bytes)
  });
  const panel = page.locator("#peInstructionSetsPanel");
  await panel.locator(":scope > details > summary").click();
  await expect(panel).toContainText("AArch64 instruction-set requirements");
  expect(requests.filter(url => url.endsWith(".wasm"))).toHaveLength(0);
  await page.locator("#peInstructionSetsAnalyzeButton").click();
  await expect(page.locator("#peInstructionSetsAnalyzeButton"))
    .toHaveText("Re-analyze instruction sets");
  await expect(panel).toContainText("2 instruction(s)");
  await expect(panel).toContainText("FEAT_SVE or FEAT_SME");
  await expect(panel).toContainText("LLVM 21.1.8");
  await expect(panel).not.toContainText("SSE2");
  await page.locator("#peInstructionSetsAnalyzeButton").click();
  await expect(panel).toContainText("2 instruction(s)");
  expect(requests.some(url => /llvm-aarch64.*\.wasm$/.test(url))).toBe(true);
  expect(requests.every(url => new URL(url).origin === "http://127.0.0.1:4173")).toBe(true);
  expect(errors).toEqual([]);
});
