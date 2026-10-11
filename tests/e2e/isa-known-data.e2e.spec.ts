import { expect, test } from "@playwright/test";
import { createElfIsaDataFile } from "../fixtures/elf-isa-data-file.js";
import { createPeDataSeedFixture } from "../fixtures/pe-data-seeds.js";

test("ELF ISA excludes decoded NOTYPE data and a dynamic pointer into its interior", async ({ page }) => {
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: "isa-data.so", mimeType: "application/octet-stream",
    buffer: Buffer.from(createElfIsaDataFile()) });
  await page.locator("#elfInstructionSetsPanel > details > summary").click();
  await page.locator("#elfInstructionSetsAnalyzeButton").click();
  const panel = page.locator("#elfInstructionSetsPanel");
  await expect(panel).toContainText("8 instruction(s) decoded");
  await expect(panel).toContainText("Skipped known-data seed at address 0x114c.");
  await expect(panel).toContainText("Stopped before known data at address 0x1148.");
  await expect(panel.locator('[title="CpuidFeature.AVX"]')).not.toHaveClass(/sel/);
});

test("PE ISA omits Itanium exported data from every seed source", async ({ page }) => {
  const { file } = createPeDataSeedFixture([["_Z1fv"], ["_Z5value"], ["_ZTV1A"],
    ["_ZThn8_N1A1fEv"], ["PlainC"], [], ["_Zbroken"]]);
  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: "application/octet-stream",
    buffer: Buffer.from(await file.arrayBuffer()) });
  const panel = page.locator("#peInstructionSetsPanel");
  await panel.locator(":scope > details > summary").click();
  await panel.getByRole("button", { name: "Analyze instruction sets", exact: true }).click();
  await expect(panel).toContainText("5 instruction(s) decoded");
  await expect(panel.locator('[title="CpuidFeature.AVX"]')).not.toHaveClass(/sel/);
  await expect(panel.locator('[title="CpuidFeature.SSE"]')).not.toHaveClass(/sel/);
});
