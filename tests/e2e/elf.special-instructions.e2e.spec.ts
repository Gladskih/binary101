import { expect, test } from "@playwright/test";
import { createElfFile } from "../fixtures/elf-sample-file.js";

const executable = (): Buffer => {
  const bytes = createElfFile().data;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  // Intel SDM Vol. 2: RDMSR x2, CLI, MOV RAX, CR0, RET; unreachable HLT.
  // https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
  const code = Uint8Array.from([0x0f, 0x32, 0x0f, 0x32, 0xfa, 0x0f, 0x20, 0xc0, 0xc3, 0xf4]);
  // ELF gABI: ELF64 e_entry and PT_LOAD p_vaddr/p_paddr/p_filesz/p_memsz.
  // https://gabi.xinuos.com/elf/07-pheader.html
  view.setBigUint64(24, 0xffff800000000000n + BigInt(bytes.length), true);
  view.setBigUint64(64 + 16, 0xffff800000000000n, true);
  view.setBigUint64(64 + 24, 0xffff800000000000n, true);
  view.setBigUint64(64 + 32, BigInt(bytes.length + code.length), true);
  view.setBigUint64(64 + 40, BigInt(bytes.length + code.length), true);
  return Buffer.concat([bytes, code]);
};

test("ELF ISA displays privileges, explanations and exact virtual addresses", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", {
    name: "special.elf", mimeType: "application/x-elf", buffer: executable()
  });
  const panel = page.locator("#elfInstructionSetsPanel");
  await panel.locator(":scope > details > summary").click();
  await panel.getByRole("button", { name: "Analyze instruction sets", exact: true }).click();
  const table = panel.getByRole("table").filter({ has: page.getByRole("columnheader", { name: "Sites" }) });
  await expect(table.getByRole("columnheader"))
    .toHaveText(["Category", "Instruction", "Sites", "Example virtual addresses"]);
  const rdmsr = table.getByRole("row").filter({ has: page.locator("summary", { hasText: /^RDMSR$/ }) });
  await expect(rdmsr.getByRole("cell").nth(2)).toHaveText("2");
  await expect(rdmsr.getByRole("cell").nth(3)).toHaveText(
    `0x${(0xffff800000000000n + BigInt(createElfFile().data.length)).toString(16)} ` +
    `0x${(0xffff800000000002n + BigInt(createElfFile().data.length)).toString(16)}`
  );
  await rdmsr.locator("summary", { hasText: /^Kernel privilege$/ }).click();
  await expect(rdmsr.getByText(/administrator rights alone do not suffice/)).toBeVisible();
  await expect(table.locator("summary", { hasText: /^I\/O privilege$/ })).toBeVisible();
  await expect(table.locator("summary", { hasText: /^MOV CR$/ })).toBeVisible();
  await expect(table.locator("summary", { hasText: /^HLT$/ })).toHaveCount(0);
  await panel.getByRole("button", { name: "Re-analyze instruction sets", exact: true }).click();
  await expect(rdmsr.getByRole("cell").nth(2)).toHaveText("2");
});
