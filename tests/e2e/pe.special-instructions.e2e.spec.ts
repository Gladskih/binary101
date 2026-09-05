import { expect, test } from "@playwright/test";
import { createPePlusWithSection } from "../fixtures/sample-files-pe.js";

test("the existing PE ISA button reports special instructions without addresses", async ({ page }) => {
  const bytes = createPePlusWithSection();
  // Fixture entry RVA 0x1000 maps to file offset 0x200. Intel SDM Vol. 2 encodings:
  // SYSCALL, SYSCALL, RDMSR, CLI, INT3 (which ends this sampled path).
  bytes.set([0x0f, 0x05, 0x0f, 0x05, 0x0f, 0x32, 0xfa, 0xcc], 0x200);
  await page.goto("/");
  await page.setInputFiles("#fileInput", {
    name: "special.exe", mimeType: "application/octet-stream", buffer: Buffer.from(bytes)
  });
  const panel = page.locator("#peInstructionSetsPanel");
  await panel.locator(":scope > details > summary").click();
  await expect(panel.getByRole("heading", { name: "Special instructions" })).toHaveCount(0);
  await panel.getByRole("button", { name: "Analyze instruction sets", exact: true }).click();
  const table = panel.getByRole("table").filter({ has: page.getByRole("columnheader", { name: "Sites" }) });
  await expect(table.getByRole("columnheader")).toHaveText(["Category", "Instruction", "Sites"]);
  await expect(table.getByRole("row").filter({ hasText: "SYSCALL" }).getByRole("cell"))
    .toHaveText(["Direct syscall", "SYSCALL", "2"]);
  await expect(table).toContainText("RDMSR");
  await expect(table).toContainText("CLI");
  await expect(table).toContainText("INT3");
  await panel.getByRole("button", { name: "Re-analyze instruction sets", exact: true }).click();
  await expect(table.getByRole("row").filter({ hasText: "SYSCALL" }).getByRole("cell").last())
    .toHaveText("2");
});
