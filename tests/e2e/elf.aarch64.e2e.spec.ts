import { expect, test } from "@playwright/test";
import { createElfFile } from "../fixtures/elf-sample-file.js";
import { aarch64Code } from "../fixtures/aarch64-code.js";

const executable = (): Buffer => {
  const bytes = createElfFile().data;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  // AAELF64 header and ELF64 program-header layout; append aligned executable code.
  const offset = Math.ceil(bytes.length / 4) * 4;
  // SVE add; MRS SCTLR_EL1 twice; MSR DAIFSet; MRS TPIDR_EL0; RET; unreachable HVC.
  // System encodings: https://github.com/qemu/qemu/blob/master/target/arm/tcg/a64.decode
  const code = aarch64Code([
    0x04a00000, 0xd5381000, 0xd5381001, 0xd5034fdf, 0xd53bd040, 0xd65f03c0, 0xd4000002
  ]).data;
  view.setUint16(18, 183, true);
  view.setBigUint64(24, 0x400000n + BigInt(offset), true);
  view.setBigUint64(64 + 32, BigInt(offset + code.length), true);
  view.setBigUint64(64 + 40, BigInt(offset + code.length), true);
  return Buffer.concat([bytes, new Uint8Array(offset - bytes.length), code]);
};

test("ELF AArch64 analyzes using local WASM and displays architecture requirements", async ({ page }) => {
  const errors: string[] = [];
  const requests: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  page.on("request", request => requests.push(request.url()));
  await page.goto("/");
  await page.setInputFiles("#fileInput", {
    name: "aarch64.elf", mimeType: "application/x-elf", buffer: executable()
  });
  await page.locator("#elfInstructionSetsPanel > details > summary").click();
  await expect(page.locator("#elfInstructionSetsPanel")).toContainText("AArch64");
  expect(requests.filter(url => url.endsWith(".wasm"))).toHaveLength(0);
  await page.locator("#elfInstructionSetsAnalyzeButton").click();
  await expect(page.locator("#elfInstructionSetsAnalyzeButton")).toHaveText("Re-analyze instruction sets");
  const panel = page.locator("#elfInstructionSetsPanel");
  await expect(panel).toContainText("6 instruction(s)");
  await expect(panel).toContainText("FEAT_SVE or FEAT_SME");
  await expect(panel).toContainText("LLVM 21.1.8");
  await expect(panel).not.toContainText("SSE2");
  const row = panel.getByRole("row").filter({ hasText: "MRS SCTLR_EL1" });
  await expect(row.getByRole("cell").nth(2)).toHaveText("2");
  // Appended code starts at the next four-byte boundary after the ELF fixture.
  const address = 0x400000 + Math.ceil(createElfFile().data.length / 4) * 4;
  await expect(row.getByRole("cell").nth(3)).toHaveText(
    `0x${(address + 4).toString(16)} 0x${(address + 8).toString(16)}`);
  await row.locator("summary").click();
  await expect(row).toContainText("administrator rights alone do not suffice");
  await expect(panel).toContainText("Configured EL0 access");
  await expect(panel).not.toContainText("MRS TPIDR_EL0");
  await expect(panel).not.toContainText("HVC");
  await page.locator("#elfInstructionSetsAnalyzeButton").click();
  await expect(row.getByRole("cell").nth(2)).toHaveText("2");
  expect(requests.some(url => /llvm-aarch64.*\.wasm$/.test(url))).toBe(true);
  expect(requests.every(url => new URL(url).origin === "http://127.0.0.1:4173")).toBe(true);
  expect(errors).toEqual([]);
});
