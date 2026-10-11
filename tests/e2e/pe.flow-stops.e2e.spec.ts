"use strict";

import { expect, test } from "@playwright/test";
import { createPeFallthroughDataFile, createPeNoReturnFile } from "../fixtures/pe-flow-stop-files.js";

test("PE ISA stops fallthrough before demangled exported data", async ({ page }) => {
  const file = await createPeFallthroughDataFile();
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: "application/octet-stream",
    buffer: Buffer.from(await file.arrayBuffer()) });
  const panel = page.locator("#peInstructionSetsPanel");
  await panel.locator(":scope > details > summary").click();
  await panel.getByRole("button", { name: "Analyze instruction sets", exact: true }).click();

  await expect(panel).toContainText("20 instruction(s) decoded");
  await expect(panel).toContainText("Stopped before known data at RVA 0x1010.");
  await expect(panel.locator('[title="CpuidFeature.AVX"]')).not.toHaveClass(/sel/);
  await expect(panel.locator('[title="CpuidFeature.SSE"]')).not.toHaveClass(/sel/);
});

test("PE ISA uses shipped import metadata to stop after ExitProcess", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: "exit-process.exe", mimeType: "application/octet-stream",
    buffer: Buffer.from(createPeNoReturnFile()) });
  const panel = page.locator("#peInstructionSetsPanel");
  await panel.locator(":scope > details > summary").click();
  await panel.getByRole("button", { name: "Analyze instruction sets", exact: true }).click();

  await expect(panel).toContainText("1 instruction(s) decoded");
  await expect(panel.locator('[title="CpuidFeature.SSE"]')).not.toHaveClass(/sel/);
});
