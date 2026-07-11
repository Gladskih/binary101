"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import { createFileRangeReader } from "../../../../../analyzers/file-range-reader.js";
import type { PeBaseRelocationResult } from "../../../../../analyzers/pe/directories/reloc.js";
import { createMsvcRttiImage } from "../../../../../analyzers/pe/msvc-rtti/image.js";
import { indexMsvcRttiDir64Sites } from "../../../../../analyzers/pe/msvc-rtti/relocation-index.js";
import type { MsvcRttiImage } from "../../../../../analyzers/pe/msvc-rtti/image.js";
import { createSimpleMsvcRttiFixture } from "../../../../fixtures/pe-msvc-rtti-fixture.js";

const relocationSubject = () => {
  const subject = createSimpleMsvcRttiFixture(2);
  const fixture = subject.builder.build();
  const image = createMsvcRttiImage(
    createFileRangeReader(fixture.file, 0, fixture.file.size),
    fixture.core.sections,
    fixture.core.opt.ImageBase,
    fixture.core.opt.SizeOfImage
  );
  return { ...subject, fixture, image };
};

const cloneRelocations = (value: PeBaseRelocationResult): PeBaseRelocationResult => ({
  ...value,
  blocks: value.blocks.map(block => ({
    ...block,
    entries: block.entries.map(entry => ({ ...entry }))
  }))
});

void test("indexMsvcRttiDir64Sites indexes aligned file-backed DIR64 sites", () => {
  const { fixture, image, type, vftable } = relocationSubject();

  const sites = indexMsvcRttiDir64Sites(fixture.relocations, image);

  assert.ok(sites);
  assert.equal(sites.has(type.rva), true);
  assert.equal(sites.has(vftable.locatorSlotRva), true);
  assert.equal(sites.has(vftable.rva), true);
  assert.equal(sites.has(vftable.rva + 8), true);
});

void test("indexMsvcRttiDir64Sites rejects missing and warned relocation results", () => {
  const { fixture, image } = relocationSubject();
  assert.ok(fixture.relocations);
  const warned = { ...fixture.relocations, warnings: ["damaged"] };

  assert.equal(indexMsvcRttiDir64Sites(null, image), null);
  assert.equal(indexMsvcRttiDir64Sites(warned, image), null);
});

void test("indexMsvcRttiDir64Sites rejects inconsistent totals and block counts", () => {
  const { fixture, image } = relocationSubject();
  assert.ok(fixture.relocations);
  const wrongTotal = cloneRelocations(fixture.relocations);
  wrongTotal.totalEntries += 1;
  const wrongCount = cloneRelocations(fixture.relocations);
  wrongCount.blocks[0]!.count += 1;

  assert.equal(indexMsvcRttiDir64Sites(wrongTotal, image), null);
  assert.equal(indexMsvcRttiDir64Sites(wrongCount, image), null);
});

void test("indexMsvcRttiDir64Sites rejects structurally invalid blocks", () => {
  const { fixture, image } = relocationSubject();
  assert.ok(fixture.relocations);
  const badPage = cloneRelocations(fixture.relocations);
  badPage.blocks[0]!.pageRva += 1;
  const badSize = cloneRelocations(fixture.relocations);
  badSize.blocks[0]!.size = 10;

  assert.equal(indexMsvcRttiDir64Sites(badPage, image), null);
  assert.equal(indexMsvcRttiDir64Sites(badSize, image), null);
});

void test("indexMsvcRttiDir64Sites filters invalid and non-DIR64 sites", () => {
  const { fixture, image } = relocationSubject();
  assert.ok(fixture.relocations);
  const filtered = cloneRelocations(fixture.relocations);
  filtered.blocks[0]!.entries.forEach(entry => {
    entry.type = 0;
  });

  const sites = indexMsvcRttiDir64Sites(filtered, image);

  assert.equal(sites, null);
});

void test("indexMsvcRttiDir64Sites skips an unaligned DIR64 site", () => {
  const { fixture, image, vftable } = relocationSubject();
  assert.ok(fixture.relocations);
  const filtered = cloneRelocations(fixture.relocations);
  const block = filtered.blocks[0]!;
  block.entries = [{ type: 10, offset: (vftable.locatorSlotRva & 0xfff) + 1 }];
  block.count = 1;
  filtered.totalEntries = 1;

  const sites = indexMsvcRttiDir64Sites(filtered, image);

  assert.equal(sites, null);
});

const acceptingImage = (): MsvcRttiImage => ({
  availableDataSize: () => 0,
  isDataRange: () => true,
  isExecutableRva: () => false,
  preferredVaToRva: () => null,
  readData: async () => null,
  readPreferredVaRva: async () => null
});

for (const [name, mutate] of [
  ["non-finite page RVA", (value: PeBaseRelocationResult) => {
    value.blocks[0]!.pageRva = Number.NaN;
  }],
  ["negative page RVA", (value: PeBaseRelocationResult) => {
    value.blocks[0]!.pageRva = -0x1000;
  }],
  ["out-of-range page RVA", (value: PeBaseRelocationResult) => {
    value.blocks[0]!.pageRva = 0x1_0000_0000;
  }],
  ["undersized block", (value: PeBaseRelocationResult) => {
    value.blocks[0]!.size = 4;
  }],
  ["non-finite block size", (value: PeBaseRelocationResult) => {
    value.blocks[0]!.size = Number.NaN;
  }]
] as const) {
  void test(`indexMsvcRttiDir64Sites rejects ${name}`, () => {
    const { fixture } = relocationSubject();
    assert.ok(fixture.relocations);
    const relocations = cloneRelocations(fixture.relocations);
    mutate(relocations);

    assert.equal(indexMsvcRttiDir64Sites(relocations, acceptingImage()), null);
  });
}

for (const [name, offset] of [
  ["non-finite", Number.NaN],
  ["negative", -1],
  ["outside its 4 KiB page", 0x1000]
] as const) {
  void test(`indexMsvcRttiDir64Sites skips ${name} entry offset`, () => {
    const { fixture } = relocationSubject();
    assert.ok(fixture.relocations);
    const relocations = cloneRelocations(fixture.relocations);
    relocations.blocks[0]!.entries = [{ type: 10, offset }];
    relocations.blocks[0]!.count = 1;
    relocations.totalEntries = 1;

    assert.equal(indexMsvcRttiDir64Sites(relocations, acceptingImage()), null);
  });
}
