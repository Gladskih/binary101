import { expect, test } from "@playwright/test";
import { createPePlusWithSection } from "../fixtures/sample-files-pe.js";

test("PE ISA explains special instructions and disassembles a selected RVA", async ({ page }) => {
  const bytes = createPePlusWithSection();
  // Entry RVA 0x1000 maps to file offset 0x200. Intel SDM Vol. 2 encodings:
  // SYSCALL x2, RDMSR, CLI, CPUID, RDTSC, CLFLUSH [rax], ENDBR64, XTEST,
  // VMXON [rax], VMCALL, INT3. The fixture is decoded only, never executed.
  bytes.set([
    0x0f, 0x05, 0x0f, 0x05, 0x0f, 0x32, 0xfa, 0x0f, 0xa2, 0x0f, 0x31,
    0x0f, 0xae, 0x38, 0xf3, 0x0f, 0x1e, 0xfa, 0x0f, 0x01, 0xd6,
    0xf3, 0x0f, 0xc7, 0x30, 0x0f, 0x01, 0xc1, 0xcc
  ], 0x200);
  await page.goto("/");
  await page.setInputFiles("#fileInput", {
    name: "special.exe", mimeType: "application/octet-stream", buffer: Buffer.from(bytes)
  });
  const panel = page.locator("#peInstructionSetsPanel");
  await panel.locator(":scope > details > summary").click();
  await panel.getByRole("button", { name: "Analyze instruction sets", exact: true }).click();
  const table = panel.getByRole("table").filter({ has: page.getByRole("columnheader", { name: "Sites" }) });
  await expect(table.getByRole("columnheader"))
    .toHaveText(["Category", "Instruction", "Sites", "Example RVAs"]);
  const syscall = table.getByRole("row").filter({ has: page.locator("summary", { hasText: /^SYSCALL$/ }) });
  await expect(syscall.getByRole("cell").nth(2)).toHaveText("2");
  const vmxon = table.getByRole("row").filter({ has: page.locator("summary", { hasText: /^VMXON$/ }) });
  await expect(vmxon.getByRole("cell").first().locator("summary"))
    .toHaveText(["Virtualization", "Kernel privilege"]);
  await vmxon.locator("summary", { hasText: /^VMXON$/ }).focus();
  await page.keyboard.press("Enter");
  await expect(vmxon.getByText(/identifies hypervisor initialization code/)).toBeVisible();
  await vmxon.locator("summary", { hasText: /^Kernel privilege$/ }).click();
  await expect(vmxon.getByText(/administrator rights alone do not suffice/)).toBeVisible();
  await expect(table.locator("summary", { hasText: /^CPU capabilities$/ })).toBeVisible();
  await expect(table.locator("summary", { hasText: /^Timing \/ counters$/ })).toBeVisible();
  await expect(table.locator("summary", { hasText: /^Cache \/ address translation$/ })).toBeVisible();
  await expect(table.locator("summary", { hasText: /^Hardware security$/ })).toBeVisible();
  await expect(table.locator("summary", { hasText: /^Transactional memory$/ })).toBeVisible();
  await expect(table.locator("summary", { hasText: /^Hypervisor call$/ })).toBeVisible();
  await expect(table.locator("summary", { hasText: /^INT3$/ })).toBeVisible();
  await table.getByRole("button", { name: "Disassemble at RVA 0x00001007", exact: true }).click();
  const disassembly = page.locator("#peEntrypointDisassemblyPanel");
  await expect(disassembly).toContainText("RVA 0x00001007");
  await expect(disassembly.getByText("Disassembly from selected RVA", { exact: true })).toBeVisible();
  await expect(disassembly.locator(":scope > details")).toHaveJSProperty("open", true);
  await expect(disassembly).toContainText("cpuid");
  await panel.getByRole("button", { name: "Re-analyze instruction sets", exact: true }).click();
  await expect(syscall.getByRole("cell").nth(2)).toHaveText("2");
});
