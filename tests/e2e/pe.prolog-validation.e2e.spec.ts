import { expect, test } from "@playwright/test";
import { createPePrologFile } from "../fixtures/pe-prolog-file.js";
import { toggleInspectionSection } from "./inspection-navigation.js";

for (const [width, theme, zoom] of [
  [390, "light", 1], [1280, "dark", 1], [390, "dark", 2], [1280, "light", 2]
] as const) {
  test(`automatic prolog checks at ${width}px ${theme} ${zoom * 100}%`, async ({ page }, testInfo) => {
    const file = createPePrologFile();
    await page.setViewportSize({ width, height: 960 });
    await page.emulateMedia({ colorScheme: theme });
    await page.goto("/");
    await page.locator("html").evaluate((element, scale) => {
      element.style.setProperty("zoom", String(scale));
    }, zoom);
    await page.setInputFiles("#fileInput", {
      name: file.name, mimeType: file.type, buffer: Buffer.from(await file.arrayBuffer())
    });
    const panel = page.locator('[data-pe-lazy-section="exception"]');
    await toggleInspectionSection(panel.locator(":scope > details > summary"));
    await expect(panel.getByRole("heading", { name: "x64 prolog validation" })).toBeVisible();
    await expect(panel.getByText("Prologs with matching unwind state", { exact: true }).locator("+ dd")).toHaveText("1");
    await expect(panel.getByText("Prologs with discrepancies", { exact: true }).locator("+ dd")).toHaveText("1");
    const summaryFits = await panel.getByText("Prologs with matching unwind state", { exact: true })
      .locator("..").evaluate(summary => {
        const bounds = summary.getBoundingClientRect();
        return [...summary.children].every(child => {
          const cell = child.getBoundingClientRect();
          return cell.left >= bounds.left - 1 && cell.right <= bounds.right + 1;
        });
      });
    expect(summaryFits).toBe(true);
    const table = panel.getByRole("table").filter({ has: page.getByRole("columnheader", { name: "Unwind assertion", exact: true }) });
    await expect(table).toContainText("sub rsp,38h");
    await expect(table.getByRole("button", { name: "Disassemble at RVA 0x00001008" })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath("prolog-validation.png"), fullPage: true });
    await table.getByRole("button", { name: "Disassemble at RVA 0x00001008" }).focus();
    await expect(table.getByRole("button", { name: "Disassemble at RVA 0x00001008" })).toBeFocused();
    await table.getByRole("button", { name: "Disassemble at RVA 0x00001008" }).press("Enter");
    await expect(page.locator("#peEntrypointDisassemblyPanel")).toBeVisible();
    await expect(page.locator("#peEntrypointDisassemblyPanel")).toContainText("RVA 0x00001008");
  });
}

test("prolog findings retain pagination and search after reopening the exception section", async ({ page }) => {
  const file = createPePrologFile(Array<number>(51).fill(56));
  await page.goto("/");
  await page.setInputFiles("#fileInput", {
    name: file.name, mimeType: file.type, buffer: Buffer.from(await file.arrayBuffer())
  });
  const panel = page.locator('[data-pe-lazy-section="exception"]');
  const summary = panel.locator(":scope > details > summary");
  await toggleInspectionSection(summary);
  const table = panel.locator('[data-paged-sortable-table-id="pe-prolog-validation"]');
  await expect(table.locator("tbody tr")).toHaveCount(50);
  await table.getByRole("button", { name: "Next", exact: true }).click();
  await expect(table.locator("tbody tr")).toHaveCount(1);
  await toggleInspectionSection(summary);
  await toggleInspectionSection(summary);
  await expect(table.locator("tbody tr")).toHaveCount(1);
  await table.getByRole("searchbox").fill("0x00001008");
  await expect(table.locator("tbody tr")).toHaveCount(1);
  await expect(table).toContainText("0x00001008");
});
