import { expect, test } from "@playwright/test";
import { parseElf } from "../../analyzers/elf/index.js";
import { createElfMetadataFile } from "../fixtures/elf-metadata-file.js";
import { expandInspectionCollection, openInspectionSection } from "./inspection-navigation.js";

const dynamicReportBytes = async (): Promise<Uint8Array> => {
  const { file } = createElfMetadataFile();
  const elf = (await parseElf(file))!;
  const offset = Number(elf.programHeaders.find(header => header.type === 2)!.offset);
  const bytes = new Uint8Array(await file.arrayBuffer());
  const view = new DataView(bytes.buffer);
  // gABI 8.3 and glibc elf/elf.h; deliberately include zero presence flags and repeats.
  const entries = [
    ...elf.dynamic!.entries.filter(entry => entry.tag === 5 || entry.tag === 10),
    // LLVM DynamicTags.def: DT_CREL; also recognized as a DT_PLTREL encoding.
    { tag: 0x40000026, value: 0x400000n }, { tag: 20, value: 0x40000026n },
    { tag: 22, value: 0n }, { tag: 24, value: 0n },
    { tag: 0x6ffffefc, value: 1n }, { tag: 0x7fffffff, value: 1n },
    { tag: 30, value: (1n << 60n) | 8n }, { tag: 0x6ffffffb, value: 0n },
    { tag: 1n << 60n, value: 1n << 63n }, { tag: 3, value: 0n },
    { tag: 0, value: 0n }
  ];
  entries.forEach((entry, index) => {
    view.setBigUint64(offset + index * 16, BigInt(entry.tag), true);
    view.setBigUint64(offset + index * 16 + 8, entry.value, true);
  });
  return bytes;
};

for (const width of [390, 1280]) {
  for (const colorScheme of ["dark", "light"] as const) {
    test(`all dynamic entries remain readable at ${width}px in ${colorScheme}`, async ({ page }) => {
      const errors: string[] = [];
      page.on("pageerror", error => errors.push(error.message));
      await page.setViewportSize({ width, height: 900 });
      await page.emulateMedia({ colorScheme });
      await page.goto("/");
      await page.setInputFiles("#fileInput", {
        name: "dynamic-report.elf", mimeType: "application/x-elf",
        buffer: Buffer.from(await dynamicReportBytes())
      });
      await openInspectionSection(page, "Dynamic linking");
      const fields = page.locator("[data-elf-dynamic-entries]");
      await expect(fields.locator("dt")).toHaveCount(12);
      await expect(fields).toContainText("libc.so.6");
      await expect(fields).toContainText("0x8000000000000000");
      await expect(fields.locator("dt").filter({ hasText: /^DT_CREL$/ })).toHaveCount(1);
      await expect(fields.locator(".opt.sel").filter({ hasText: /^DT_CREL/ })).toHaveCount(1);
      await expect(fields).not.toContainText("Unknown relocation encoding");
      const coverage = page.locator("[data-elf-dynamic-coverage]");
      await expect(coverage.locator("dl")).toHaveCount(1);
      await expect(coverage.locator("details")).toHaveCount(0);
      await expect(coverage).toContainText("checked through DT_NULL");
      await expect(coverage.locator("dt").filter({ hasText: /^DT_NEEDED$/ })
        .locator("+ dd")).toHaveText("Absent");
      await expect(coverage.locator("dt").filter({ hasText: /^DT_FLAGS$/ })).toHaveCount(0);
      const help = fields.locator("dt").filter({ hasText: /^DT_BIND_NOW$/ })
        .getByRole("button");
      await help.focus();
      await page.keyboard.press("Enter");
      await expect(help).toHaveAttribute("aria-expanded", "true");
      await page.keyboard.press("Escape");
      await expect(help).toHaveAttribute("aria-expanded", "false");
      await page.locator("html").evaluate(element => { element.style.zoom = "2"; });
      await expect(fields).toBeVisible();
      expect(await page.locator("html").evaluate(element =>
        element.scrollWidth <= element.ownerDocument.defaultView!.innerWidth)).toBe(true);
      await page.locator("html").evaluate(element => { element.style.zoom = "1"; });
      await page.screenshot({ path: `test-results/elf-dynamic-${width}-${colorScheme}.png` });
      await coverage.locator("dt").filter({ hasText: /^DT_NEEDED$/ }).scrollIntoViewIfNeeded();
      await page.screenshot({ path: `test-results/elf-coverage-${width}-${colorScheme}.png` });
      expect(errors).toEqual([]);
    });
  }
}

test("an unterminated table does not produce confirmed absence claims", async ({ page }) => {
  const bytes = await dynamicReportBytes();
  const elf = (await parseElf(new File([Uint8Array.from(bytes)], "unterminated.elf")))!;
  const segment = elf.programHeaders.find(header => header.type === 2)!;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  // Elf64_Ehdr.e_phoff/e_phentsize and Elf64_Phdr.p_filesz; omit the final Elf64_Dyn.
  // https://gabi.xinuos.com/elf/07-pheader.html
  view.setBigUint64(Number(view.getBigUint64(32, true)) +
    segment.index * view.getUint16(54, true) + 32, BigInt(elf.dynamic!.entries.length) * 16n, true);
  await page.goto("/");
  await page.setInputFiles("#fileInput", {
    name: "unterminated.elf", mimeType: "application/x-elf", buffer: Buffer.from(bytes)
  });
  await openInspectionSection(page, "Dynamic linking");
  const coverage = page.locator("[data-elf-dynamic-coverage]");
  await expect(coverage).not.toContainText("Absent");
  await expect(coverage.locator("dt").filter({ hasText: /^DT_NEEDED$/ })
    .locator("+ dd")).toContainText("Not determined");
  await expect(page.locator("[data-elf-dynamic-entries] dt")).toHaveCount(12);
});

test("reports conflicting dynamic string bounds and keeps names inside the runtime table", async ({ page }) => {
  const { file, expected } = createElfMetadataFile();
  const elf = (await parseElf(file))!;
  const dynamic = elf.sections.find(section => section.type === 6)!;
  const strings = elf.sections[dynamic.link]!;
  const bytes = await file.arrayBuffer();
  // The second Elf64_Dyn is DT_STRSZ. Stop just before the final export name.
  new DataView(bytes).setBigUint64(Number(dynamic.offset) + 24,
    strings.size - BigInt(expected.exportSymbol.length + 1), true);

  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(bytes) });
  await openInspectionSection(page, "Dynamic linking");

  const section = page.locator('[data-elf-lazy-section="linking"]');
  await expandInspectionCollection(section.locator("summary").filter({ hasText: /^Notes$/ }).locator(".."));
  await expect(section.getByText(/DT_STRSZ.*disagrees.*sh_size/)).toBeVisible();
  await openInspectionSection(page, "Imports / exports");
  const symbols = page.locator('[data-elf-lazy-section="symbols"]');
  await expect(symbols.getByText(expected.importSymbol, { exact: true })).toBeVisible();
  await expect(symbols.getByText(expected.exportSymbol, { exact: true })).toHaveCount(0);
});

test("shows runtime mapping and symbol stride inconsistencies while preserving file evidence", async ({ page }) => {
  const { file, expected } = createElfMetadataFile();
  const elf = (await parseElf(file))!;
  const dynamic = elf.programHeaders.find(header => header.type === 2)!;
  const bytes = await file.arrayBuffer();
  const view = new DataView(bytes);
  const headerOffset = Number(elf.header.phoff) + dynamic.index * elf.header.phentsize;
  view.setBigUint64(headerOffset + 16, dynamic.vaddr + BigInt(file.size), true); // Elf64_Phdr.p_vaddr.
  const symbolStride = elf.dynamic!.entries.findIndex(({ tag }) => tag === 11); // DT_SYMENT.
  view.setBigUint64(Number(dynamic.offset) + symbolStride * 16 + 8, 8n, true);

  await page.goto("/");
  await page.setInputFiles("#fileInput", { name: file.name, mimeType: file.type, buffer: Buffer.from(bytes) });
  await openInspectionSection(page, "Dynamic linking");
  const linking = page.locator('[data-elf-lazy-section="linking"]');
  await expandInspectionCollection(linking.locator("summary").filter({ hasText: /^Notes$/ }).locator(".."));
  await expect(linking.getByText(/PT_DYNAMIC.*lacks file-backed PT_LOAD coverage/)).toBeVisible();
  await expect(linking.locator("[data-elf-dynamic-entries]")).toContainText(expected.needed[0]!);
  await openInspectionSection(page, "Imports / exports");
  const symbols = page.locator('[data-elf-lazy-section="symbols"]');
  await expect(symbols.getByText("DT_SYMENT is 8 bytes. Expected 24 bytes.", { exact: true })).toBeVisible();
  await expect(symbols.getByText(expected.importSymbol, { exact: true })).toBeVisible();
});
