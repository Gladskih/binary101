import { expect, test, type Locator } from "@playwright/test";
import { parseElfUnwind } from "../../analyzers/elf/unwind.js";
import { renderElfUnwind } from "../../renderers/elf/unwind.js";
import { renderElfImportLinkage } from "../../renderers/elf/import-linkage.js";
import { elfUnwindFixture } from "../fixtures/elf-unwind.js";
import { dynamicRelocationFixture } from "../fixtures/elf-dynamic-relocations.js";
import { relocationTable } from "../fixtures/elf-relocations.js";

const unwindMarkup = async (): Promise<string> => {
  const fixture = elfUnwindFixture();
  fixture.elf.unwind = await parseElfUnwind(fixture.file(), fixture.elf);
  fixture.elf.unwind[0]!.cies[0]!.instructions = [
    { offset: 0, operation: "def_cfa", operands: [6n, 16n] },
    ...Array.from({ length: 18 }, (_, index) => ({ offset: index + 1,
      operation: "offset", operands: [BigInt(index), BigInt(index + 1)] }))
  ];
  fixture.elf.unwind[0]!.fdes[0]!.instructions = [];
  fixture.elf.unwind[0]!.fdes = Array.from({ length: 101 }, (_, index) => ({
    ...fixture.elf.unwind![0]!.fdes[0]!, offset: 32 + index * 32
  }));
  const out: string[] = [];
  renderElfUnwind(fixture.elf, out);
  return out.join("");
};

const linkageMarkup = (): string => {
  const { elf } = dynamicRelocationFixture();
  elf.relocations = { tables: [relocationTable()], issues: [], entries: [{
    tableIndex: 0, recordOffset: 0, offset: 0x1200n, type: 7, symbolIndex: 1,
    // Deliberately exceed the reading measure without any whitespace.
    symbol: { name: `_ZN4Json${"LongTemplateArgument".repeat(18)}C1Ev`, value: 0n,
      sectionIndex: 0 }, addend: 0n, target: null }] };
  elf.importLinkage = { binding: "Immediate binding requested", issues: [], links: [{
    relocationIndex: 0, kind: "PLT slot", loadSegments: [0], sections: [],
    relroSegments: [], issues: [] }] };
  const out: string[] = [];
  renderElfImportLinkage(elf, out);
  return out.join("");
};

const textOverflowsCell = async (cell: Locator): Promise<boolean> => cell.evaluate(element => {
  const bounds = element.getBoundingClientRect();
  const range = element.ownerDocument.createRange();
  range.selectNodeContents(element);
  return [...range.getClientRects()].some(rect =>
    rect.left < bounds.left - 0.5 || rect.right > bounds.right + 0.5);
});

for (const width of [390, 1440]) {
  for (const theme of ["light", "dark"] as const) {
    test(`nested CFI rules and ELF symbols stay within cells at ${width}px in ${theme}`,
      async ({ page }) => {
        await page.setViewportSize({ width, height: 900 });
        await page.emulateMedia({ colorScheme: theme });
        await page.goto("/");
        const styles = await page.locator('link[rel="stylesheet"]').evaluateAll(links =>
          links.map(link => link.outerHTML).join(""));
        expect(styles).not.toBe("");
        await page.setContent(`<!doctype html><html><head>${styles}</head><body>` +
          `<main class="workspaceContent"><article id="unwind">${await unwindMarkup()}</article>` +
          `<article id="linkage">${linkageMarkup()}</article>` +
          `<table class="table"><tbody><tr><td class="peNumeric">` +
          `<table class="table"><tbody><tr><td id="nestedText">` +
          `${"Nested text must not inherit numeric formatting. ".repeat(20)}</td>` +
          `<td id="nestedNumber" class="peNumeric">42</td></tr></tbody></table>` +
          `</td></tr></tbody></table></main></body></html>`);
        await page.locator("details").evaluateAll(elements => elements.forEach(element => {
          element.setAttribute("open", "");
        }));
        const rules = page.getByRole("cell", { name: /^r0: offset:/ }).first();
        const symbol = page.locator(".elfImportLinkage tbody td").first();
        await expect(rules).toBeVisible();
        await expect(symbol).toBeVisible();
        expect(await textOverflowsCell(rules)).toBe(false);
        expect(await textOverflowsCell(symbol)).toBe(false);
        expect(await textOverflowsCell(page.locator("#nestedText"))).toBe(false);
        expect(await page.locator("#nestedText").evaluate(element => element.ownerDocument
          .defaultView!.getComputedStyle(element).textAlign)).toBe("left");
        expect(await page.locator("#nestedNumber").evaluate(element => element.ownerDocument
          .defaultView!.getComputedStyle(element).textAlign)).toBe("right");
        await page.locator("html").evaluate(element => { element.style.zoom = "2"; });
        expect(await textOverflowsCell(rules)).toBe(false);
        expect(await textOverflowsCell(symbol)).toBe(false);
        await rules.locator("..").screenshot({
          path: `test-results/table-cfi-${width}-${theme}.png` });
        await symbol.locator("..").screenshot({
          path: `test-results/table-symbol-${width}-${theme}.png` });
      });
  }
}
