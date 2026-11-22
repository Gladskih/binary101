import { expect, test } from "@playwright/test";
import { openInspectionSection } from "./inspection-navigation.js";
import { createElfImportLinkageBytes } from "../fixtures/elf-import-linkage-file.js";

test("shows a missing array size beside the recorded dynamic tag", async ({ page }) => {
  const bytes = createElfImportLinkageBytes();
  // Replace DT_FLAGS with DT_INIT_ARRAY in the fixture's penultimate Elf64_Dyn record.
  // gABI 8.3 requires a corresponding DT_INIT_ARRAYSZ when DT_INIT_ARRAY is present.
  const view = new DataView(bytes.buffer);
  view.setBigUint64(0x3a0, 25n, true);
  view.setBigUint64(0x3a8, 0x1200n, true);

  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: "missing-array-size.elf",
    mimeType: "application/x-elf", buffer: Buffer.from(bytes) });
  await openInspectionSection(page, "Dynamic linking");

  const section = page.locator('[data-elf-lazy-section="linking"]');
  await expect(section.getByText("DT_INIT_ARRAY", { exact: true })).toBeVisible();
  await expect(section.getByText("Dynamic: DT_INIT_ARRAY requires DT_INIT_ARRAYSZ.")).toBeVisible();
});

for (const width of [390, 1280]) {
  test(`ELF linkage enriches in place after ISA at width ${width}`, async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.setViewportSize({ width, height: 800 });
    await page.goto("/");
    await page.setInputFiles("#fileInput", { name: "linkage.elf",
      mimeType: "application/x-elf", buffer: Buffer.from(createElfImportLinkageBytes()) });
    await openInspectionSection(page, "Import linkage");
    const section = page.locator('[data-elf-lazy-section="import-linkage"]');
    const table = section.locator('[data-sort-state-key="elf-import-linkage"]');
    await expect(table).toContainText("puts");
    await expect(table).toContainText("R_X86_64_JUMP_SLOT");
    await expect(section).toContainText("Immediate binding requested");
    await expect(section).toContainText("Run ISA analysis");
    await expect(section).not.toContainText("Analysis contains incomplete");
    await openInspectionSection(page, "Instruction sets");
    await page.locator("#elfInstructionSetsAnalyzeButton").click();
    await expect(page.locator("#elfInstructionSetsAnalyzeButton"))
      .toHaveText("Instruction sets analyzed");
    await openInspectionSection(page, "Import linkage");
    await expect(section).toContainText("ISA results available");
    await expect(table.getByRole("columnheader", { name: "Slot JMP refs" })).toBeVisible();
    await expect(table.getByRole("columnheader", { name: "Stub CALL refs" })).toBeVisible();
    await expect(table.locator("tbody tr").first().locator("td").nth(9)).toHaveText("1");
    await expect(table.locator("tbody tr").first().locator("td").nth(10)).toHaveText("1");
    await expect(table).not.toContainText("0x1120");
    await expect(table).not.toContainText("0x1200");
    for (const theme of ["light", "dark"] as const) {
      await page.emulateMedia({ colorScheme: theme });
      await page.locator("html").evaluate(element => { element.style.zoom = "2"; });
      await expect(table).toBeVisible();
      expect(await table.evaluate(element => {
        for (let parent = element.parentElement; parent; parent = parent.parentElement) {
          if (parent.scrollWidth > parent.clientWidth &&
            element.ownerDocument.defaultView!.getComputedStyle(parent).overflowX === "auto") {
            return true;
          }
        }
        return false;
      })).toBe(true);
      const references = table.getByRole("columnheader", { name: "Stub CALL refs" });
      await references.getByRole("button", { name: "Sort by Stub CALL refs", exact: true }).focus();
      await page.keyboard.press("Enter");
      await expect(references).toHaveAttribute("aria-sort", /ascending|descending/);
      await page.locator("html").evaluate(element => { element.style.zoom = "1"; });
      await page.screenshot({ path: `test-results/elf-linkage-${width}-${theme}.png` });
    }
    expect(errors).toEqual([]);
  });
}
