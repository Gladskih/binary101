"use strict";

import { expect, test } from "@playwright/test";
import { createPePlusDirectIatReferenceFile } from "../fixtures/pe-direct-iat-reference-file.js";

test("updates direct IAT reference counts without losing import table state", async ({ page }) => {
  const mockFile = createPePlusDirectIatReferenceFile();
  await page.goto("/");
  await page.setInputFiles("#fileInput", {
    name: mockFile.name,
    mimeType: mockFile.type,
    buffer: Buffer.from(mockFile.data)
  });
  await expect(page.locator("#fileBinaryTypeDetail"))
    .toHaveText("PE32+ executable for x86-64 (AMD64)");

  const detailsValue = page.locator("#analysisValue");
  const importsSection = detailsValue.locator("#peImportsPanel > details");
  await importsSection.locator(":scope > summary").click();
  const moduleDetails = importsSection.locator("details").filter({
    has: page.locator("summary", { hasText: /KERNEL32\.dll/ })
  });
  await moduleDetails.locator(":scope > summary").click();
  const sortButton = moduleDetails.getByRole("button", { name: "Sort by Direct CALL refs" });
  await sortButton.click();
  await expect(sortButton.locator("..")).toHaveAttribute("aria-sort", "ascending");

  const instructionSection = detailsValue.locator("#peInstructionSetsPanel > details");
  await instructionSection.locator(":scope > summary").click();
  await detailsValue.locator("#peInstructionSetsAnalyzeButton").click();
  await expect(detailsValue).toContainText("Disassembly sample");

  await expect(importsSection).toHaveJSProperty("open", true);
  await expect(moduleDetails).toHaveJSProperty("open", true);
  await expect(sortButton.locator("..")).toHaveAttribute("aria-sort", "ascending");
  await expect(moduleDetails.getByRole("row", { name: /Sleep/ }).locator("td.peNumeric").first())
    .toHaveText("1");
  await expect(moduleDetails.getByRole("row", { name: /Sleep/ }).locator("td.peNumeric").last())
    .toHaveText("—");
  await expect(moduleDetails.getByRole("row", { name: /ExitProcess/ }).locator("td.peNumeric"))
    .toHaveText(["—", "—"]);
});
