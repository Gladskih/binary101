import { expect, test } from "@playwright/test";
import { sframeElf, sframeIsaElf, sframePayload } from "../fixtures/elf-sframe.js";
import { openInspectionSection } from "./inspection-navigation.js";

test("opens sectionless SFrame and pages and sorts its frame rows", async ({ page }) => {
  await page.goto("/");
  const buffer = Buffer.from(sframeElf(sframePayload(3, true, 102).bytes, true, "segment"));
  await page.setInputFiles("#fileInput", { name: "sframe.elf", mimeType: "application/x-elf", buffer });
  await openInspectionSection(page, "SFrame (PT_GNU_SFRAME #0)");
  const rows = page.locator('[data-paged-sortable-table-id="elf-sframe-rows-0"]');
  await expect(rows.locator("tbody tr")).toHaveCount(100);
  await expect(rows.locator("tbody tr").first()).toContainText("SP + 32");
  await rows.getByRole("button", { name: "Next" }).focus();
  await page.keyboard.press("Enter");
  await expect(rows.locator("tbody tr")).toHaveCount(2);
  await rows.getByRole("button", { name: "Sort by FDE" }).click();
  await rows.getByRole("button", { name: "Sort by FDE" }).click();
  await expect(rows.locator("tbody tr").first().getByRole("cell").first()).toHaveText("101");
});

test("uses a sectionless SFrame function as an ISA seed", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", {
    name: "sframe-code.elf", mimeType: "application/x-elf", buffer: Buffer.from(sframeIsaElf())
  });
  await openInspectionSection(page, "Instruction sets");
  const panel = page.locator("#elfInstructionSetsPanel");
  const analyze = panel.locator("#elfInstructionSetsAnalyzeButton");
  await analyze.click();
  await expect(analyze).toHaveText("Instruction sets analyzed");
  await expect(panel).toContainText("2 instruction(s)");
  await expect(panel.getByRole("row", { name: /SFrame function descriptors/ }))
    .toContainText("SFrame function descriptors");
});
