import { expect, test } from "@playwright/test";
import { createPeReadyToRunSeedFile } from "../fixtures/pe-ready-to-run-seed-file.js";

test("R2R MethodDef seeds reveal code unreachable from the PE entrypoint without an exception directory", async ({ page }) => {
  const file = createPeReadyToRunSeedFile();
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name,
    mimeType: "application/octet-stream", buffer: Buffer.from(file.data) });
  const panel = page.locator("#peInstructionSetsPanel");
  await panel.locator(":scope > details > summary").click();
  await panel.getByRole("button", { name: "Analyze instruction sets", exact: true }).click();

  const syscall = panel.getByRole("row").filter({ has: page.locator("summary", { hasText: /^SYSCALL$/ }) });
  await expect(syscall.getByRole("cell").nth(2)).toHaveText("1");
  await expect(syscall).toContainText("0x00001020");
  await expect(panel).not.toContainText("ReadyToRun disassembly seeds:");
});

test("R2R seed failures remain visible after instruction-set analysis", async ({ page }) => {
  const file = createPeReadyToRunSeedFile(1);
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name,
    mimeType: "application/octet-stream", buffer: Buffer.from(file.data) });
  const panel = page.locator("#peInstructionSetsPanel");
  await panel.locator(":scope > details > summary").click();
  await panel.getByRole("button", { name: "Analyze instruction sets", exact: true }).click();

  await expect(panel).toContainText(
    "ReadyToRun disassembly seeds: method map references a missing runtime-function index.");
  await expect(panel.locator("summary", { hasText: /^SYSCALL$/ })).toHaveCount(0);
});
