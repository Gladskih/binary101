import { expect, test } from "@playwright/test";
import { createPeClrFreeReadyToRunFile, createPeReadyToRunThunkFile } from
  "../fixtures/pe-ready-to-run-thunk-file.js";

test("import thunks appear as instructions without runtime-function or exception roots", async ({ page }) => {
  const file = createPeReadyToRunThunkFile();
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name,
    mimeType: "application/octet-stream", buffer: Buffer.from(file.data) });
  const panel = page.locator("#peInstructionSetsPanel");
  await panel.locator(":scope > details > summary").click();
  await panel.getByRole("button", { name: "Analyze instruction sets", exact: true }).click();

  await expect(panel).toContainText("4 instruction(s) decoded");
  await expect(panel).not.toContainText("ReadyToRun import thunks:");
});

test("CLR-free exported R2R headers explain thunk counts without dumping their addresses", async ({ page }) => {
  const file = createPeClrFreeReadyToRunFile();
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name,
    mimeType: "application/octet-stream", buffer: Buffer.from(file.data) });
  const panel = page.locator("[data-pe-lazy-section=clr]");
  await panel.locator(":scope > details > summary").click();
  await panel.locator("summary").filter({ hasText: /^ReadyToRun \/ managed native header$/ }).click();

  await expect(panel).toContainText("ReadyToRun composite header");
  await expect(panel).toContainText("DelayLoadMethodCallThunks");
  await expect(panel.getByRole("button", { name: "Sort by Why it matters", exact: true })).toBeVisible();
  await expect(panel.getByRole("row").filter({ hasText: "eager thunks" })).toContainText("1");
  await expect(panel.getByRole("columnheader", { name: "Helper cell RVA", exact: true })).toHaveCount(0);
  await expect(panel).not.toContainText("Unrecognized thunk");
});
