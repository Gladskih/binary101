import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../../../analyzers/elf/index.js";
import { renderElf } from "../../../../renderers/elf/index.js";
import { renderElfLazy, getElfLazySections } from "../../../../renderers/elf/lazy-sections.js";
import { getElfPagedTableModel } from "../../../../renderers/elf/paged-tables.js";
import { sframeElf, sframePayload } from "../../../fixtures/elf-sframe.js";

void test("renders SFrame metadata and resolves both paged tables", async () => {
  const elf = await parseElf(new File([sframeElf(sframePayload(3).bytes)], "sframe.elf"));
  assert.ok(elf);
  const html = renderElf(elf);
  assert.match(html, /SFrame \(section #1\)/);
  assert.match(html, /PT_GNU_SFRAME/);
  assert.match(html, /SHT_GNU_SFRAME/);
  assert.match(html, /0x401000/);
  assert.match(html, /SP \+ 32/);
  assert.match(html, /\[CFA − 8\]/);
  assert.match(renderElfLazy(elf), /data-elf-lazy-section="sframe-0"/);
  assert.match(getElfLazySections(elf).find(section => section.key === "sframe-0")!.render(),
    /Frame rows/);
  assert.equal(getElfPagedTableModel(elf, "elf-sframe-functions-0")?.sortValueAt(0, 2), "0x401000");
  assert.equal(getElfPagedTableModel(elf, "elf-sframe-rows-0")?.sortValueAt(0, 1), "4");
});

void test("uses the section VMA for v2 descriptors with the PC-relative flag clear", async () => {
  const payload = sframePayload(2);
  payload.bytes[3] = 1; // Only sorted; v2 Errata 1 defines the absent-PCREL case.
  payload.view.setInt32(payload.descriptorStart, -0x1000, true);
  const elf = await parseElf(new File([sframeElf(payload.bytes)], "section-relative.elf"));
  assert.ok(elf);
  assert.match(renderElf(elf), /0x401000/);
});

void test("shows encoded PCs and the relocation notice for an object file", async () => {
  const bytes = sframeElf(sframePayload(3).bytes, true, "object");
  const elf = await parseElf(new File([bytes], "sframe.o"));
  assert.ok(elf);
  assert.match(renderElf(elf), /Function PCs in relocatable objects require relocation/);
  const table = getElfPagedTableModel(elf, "elf-sframe-functions-0");
  assert.equal(table?.sortValueAt(0, 2), "—");
  assert.equal(table?.sortValueAt(0, 3), "-4128");
  assert.equal(table?.rowAt(1), null);
});

void test("renders notices for an unknown version without descriptors", async () => {
  const payload = sframePayload(3);
  payload.bytes[2] = 255;
  const elf = await parseElf(new File([sframeElf(payload.bytes)], "unknown-sframe.elf"));
  assert.ok(elf);
  assert.match(renderElf(elf), /Unsupported SFrame version 255/);
  assert.doesNotMatch(renderElf(elf), /Function descriptors/);
});
