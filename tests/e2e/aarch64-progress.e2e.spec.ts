import { expect, test } from "@playwright/test";
import { aarch64Code } from "../fixtures/aarch64-code.js";
import { createElfFile } from "../fixtures/elf-sample-file.js";
import { createPePlusWithSection } from "../fixtures/sample-files-pe.js";

// Enough words for many progress intervals (1024 instructions), followed by ret.
const code = aarch64Code([0x04a00000, ...Array<number>(262144).fill(0xd503201f), 0xd65f03c0]).data;

const elfExecutable = (): Buffer => {
  const header = createElfFile().data;
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
  // AAELF64 ELF header and PT_LOAD layout, as in elf.aarch64.e2e.spec.ts.
  const offset = Math.ceil(header.length / 4) * 4;
  view.setUint16(18, 183, true);
  view.setBigUint64(24, 0x400000n + BigInt(offset), true);
  view.setBigUint64(96, BigInt(offset + code.length), true);
  view.setBigUint64(104, BigInt(offset + code.length), true);
  return Buffer.concat([header, new Uint8Array(offset - header.length), code]);
};

const peExecutable = (): Buffer => {
  const header = createPePlusWithSection().slice(0, 0x200);
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
  // PE/COFF layout: signature, 20-byte COFF header, optional header, then section table.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
  const coff = view.getUint32(0x3c, true) + 4;
  const optional = coff + 20;
  const section = optional + view.getUint16(coff + 16, true);
  view.setUint16(coff, 0xaa64, true);
  view.setUint32(optional + 56, 0x1000 + Math.ceil(code.length / 0x1000) * 0x1000, true);
  view.setUint32(section + 8, code.length, true);
  view.setUint32(section + 16, Math.ceil(code.length / 0x200) * 0x200, true);
  return Buffer.concat([header, code, new Uint8Array((0x200 - code.length % 0x200) % 0x200)]);
};

for (const [format, executable] of [["elf", elfExecutable], ["pe", peExecutable]] as const) {
  test(`${format} AArch64 displays only detected groups while decoding and retains sorting`, async ({ page }) => {
    await page.addInitScript(() => {
      const schedule = globalThis.window.setTimeout.bind(globalThis.window);
      Object.defineProperty(globalThis.window, "setTimeout", {
        value: (handler: TimerHandler, delay?: number, ...args: unknown[]) =>
          schedule(handler, delay === 0 ? 50 : delay, ...args)
      });
    });
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: `live.${format}`,
      mimeType: "application/octet-stream", buffer: executable() });
    const panel = page.locator(`#${format}InstructionSetsPanel`);
    await panel.locator(":scope > details > summary").click();
    const rows = panel.locator(".aarch64IsaTable tbody tr");
    await expect(rows).toHaveCount(0);
    await page.locator(`#${format}InstructionSetsAnalyzeButton`).click();
    await expect(rows).toHaveCount(2);
    await expect(page.locator(`#${format}InstructionSetsAnalyzeButton`)).toBeDisabled();
    const count = rows.filter({ hasText: "No recorded LLVM feature gate" }).locator("td").nth(1);
    await panel.getByRole("button", { name: "Sort by Instr.", exact: true }).click();
    const firstCount = Number(await count.textContent());
    await expect.poll(async () => Number(await count.textContent())).toBeGreaterThan(firstCount);
    await expect(panel.locator('th[aria-sort="ascending"]')).toContainText("Instr.");
    await expect(panel).not.toContainText("FEAT_AES");
    await expect(panel).toContainText("Scalable Matrix Extension");
    await page.locator(`#${format}InstructionSetsCancelButton`).click();
    await expect(page.locator(`#${format}InstructionSetsProgressText`)).toHaveText("Cancelled.");
    await expect(rows).toHaveCount(2);
  });
}
