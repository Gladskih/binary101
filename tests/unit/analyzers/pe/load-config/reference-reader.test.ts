"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { FileRangeReader } from "../../../../../analyzers/file-range-reader.js";
import {
  addReferenceMessage,
  createPeRvaMapping,
  mappedRawSpan,
  PE32_POINTER_BYTES,
  PE32_PLUS_POINTER_BYTES,
  readMappedReferenceTable,
  readMappedReferenceView,
  readReferencePointer,
  readReferencePointerValue,
  referencedTableByteLength,
  referencePointerRva
} from "../../../../../analyzers/pe/load-config/reference-reader.js";
import { inlinePeSectionName } from "../../../../../analyzers/pe/sections/name.js";
import type { PeSection } from "../../../../../analyzers/pe/types.js";
import { MockFile } from "../../../../helpers/mock-file.js";

const IMAGE_BASE = 0x140000000n;
const rawMapping = (size: number) => createPeRvaMapping(size, [], size, value => value);

const createSplitShortReader = (): FileRangeReader => ({
  size: 3,
  read: async offset => new DataView(new Uint8Array(offset === 0 ? [1] : []).buffer),
  readBytes: async offset => new Uint8Array(offset === 0 ? [1] : [])
});

// Section/RVA fixtures follow Microsoft PE "Section Table" mapping semantics.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
const createTestSection = (
  virtualAddress: number,
  virtualSize: number,
  sizeOfRawData: number,
  pointerToRawData = 0x20
): PeSection => ({
  name: inlinePeSectionName(".data"),
  virtualAddress,
  virtualSize,
  sizeOfRawData,
  pointerToRawData,
  characteristics: 0
});

const adjacentSectionRvaToOffset = (rva: number): number | null => {
  if (rva >= 0x1000 && rva < 0x1004) return 0x20 + rva - 0x1000;
  if (rva >= 0x1004 && rva < 0x1008) return 0x30 + rva - 0x1004;
  return null;
};

void test("readMappedReferenceView rejects invalid, unmapped, and truncated ranges", async () => {
  const reader = new MockFile(new Uint8Array(0x40), "references.bin");
  const warnings: string[] = [];
  const notes: string[] = [];

  const invalid = await readMappedReferenceView(reader, rawMapping(reader.size), warnings, notes, "invalid", -1, 4);
  const unmapped = await readMappedReferenceView(
    reader, createPeRvaMapping(reader.size, [], 0, () => null), warnings, notes, "unmapped", 4, 4
  );
  const truncated = await readMappedReferenceView(
    reader, rawMapping(reader.size), warnings, notes, "truncated", 0x3e, 4
  );

  assert.equal(invalid, null);
  assert.equal(unmapped, null);
  assert.equal(truncated, null);
  assert.ok(warnings.some(warning => warning.includes("invalid RVA")));
  assert.ok(warnings.some(warning => warning.includes("truncated is truncated")));
  assert.ok(notes.some(note => note.includes("unmapped RVA")));
});

void test("readMappedReferenceView enforces exact RVA limits and detects short chunk reads", async () => {
  const boundaryMapping = {
    offset: () => 0,
    rawSpan: () => [0, 1] as const,
    rawChunks: () => [[0, 1]] as const
  };
  const splitMapping = {
    offset: () => 0,
    rawSpan: () => [0, 3] as const,
    rawChunks: () => [[0, 1], [2, 1]] as const
  };
  const warnings: string[] = [];
  const notes: string[] = [];
  const boundaryReader = new MockFile(new Uint8Array([7]), "rva-boundary.bin");
  const exactEnd = await readMappedReferenceView(
    boundaryReader, boundaryMapping, warnings, notes, "exact", 0xffff_ffff, 1
  );
  const overflowing = await readMappedReferenceView(
    boundaryReader, boundaryMapping, warnings, notes, "overflow", 0xffff_ffff, 2
  );
  const pastRva = await readMappedReferenceView(
    boundaryReader, boundaryMapping, warnings, notes, "past", 0x1_0000_0000, 1
  );
  const empty = await readMappedReferenceView(
    boundaryReader, boundaryMapping, warnings, notes, "empty", 0, 0
  );
  const short = await readMappedReferenceView(
    createSplitShortReader(), splitMapping, warnings, notes, "short chunks", 1, 2
  );
  const zeroRva = await readMappedReferenceView(
    boundaryReader, boundaryMapping, warnings, notes, "zero RVA", 0, 1
  );

  assert.equal(exactEnd?.getUint8(0), 7);
  assert.equal(overflowing, null);
  assert.equal(pastRva, null);
  assert.equal(empty, null);
  assert.equal(short, null);
  assert.equal(zeroRva?.getUint8(0), 7);
  assert.ok(warnings.some(warning => warning === "LOAD_CONFIG: short chunks is truncated."));
});

void test("addReferenceMessage deduplicates diagnostics", () => {
  const messages: string[] = [];

  addReferenceMessage(messages, "same");
  addReferenceMessage(messages, "same");

  assert.deepEqual(messages, ["same"]);
});

void test("readMappedReferenceTable uses the declared count without an artificial entry cap", async () => {
  // One entry beyond the removed 65,536-entry implementation cap proves file data is authoritative.
  const count = 0x10001;
  const entrySize = Uint32Array.BYTES_PER_ELEMENT;
  const bytes = new Uint8Array(0x100 + count * entrySize).fill(0);
  const warnings: string[] = [];
  const notes: string[] = [];

  const view = await readMappedReferenceTable(
    new MockFile(bytes, "large-reference-table.bin"),
    rawMapping(bytes.length),
    warnings,
    notes,
    "large table",
    0x100,
    count,
    entrySize
  );

  assert.equal(view?.byteLength, count * entrySize);
  assert.deepEqual(warnings, []);
});

void test("referencedTableByteLength rejects invalid counts, missing RVAs, and RVA overflow", () => {
  const warnings: string[] = [];

  const invalid = referencedTableByteLength(warnings, "invalid", 0x100, -1, 4);
  const missing = referencedTableByteLength(warnings, "missing", 0, 1, 4);
  const overflow = referencedTableByteLength(warnings, "overflow", 0xfffffff8, 2, 8);
  const empty = referencedTableByteLength(warnings, "empty", 0, 0, 4);
  const invalidEntrySize = referencedTableByteLength(warnings, "invalid size", 0x100, 1, 0);
  const exactEnd = referencedTableByteLength(warnings, "exact end", 0xfffffff8, 1, 8);

  assert.equal(invalid, null);
  assert.equal(missing, null);
  assert.equal(overflow, null);
  assert.equal(empty, 0);
  assert.equal(invalidEntrySize, null);
  assert.equal(exactEnd, 8);
  assert.equal(warnings.length, 4);
  assert.ok(warnings.some(warning => warning ===
    "LOAD_CONFIG: invalid size has an invalid count or entry size."));
  assert.ok(warnings.some(warning => warning ===
    "LOAD_CONFIG: missing has entries but no valid table RVA."));
  assert.ok(warnings.some(warning => warning ===
    "LOAD_CONFIG: overflow exceeds the 32-bit RVA address space."));
});

void test("reference pointer readers support PE32 and PE32+ slots", async () => {
  const bytes = new Uint8Array(0x40).fill(0);
  const view = new DataView(bytes.buffer);
  view.setUint32(0x10, 0x12345678, true);
  view.setBigUint64(0x20, 0x140001000n, true);
  const warnings: string[] = [];
  const notes: string[] = [];

  const pe32 = readReferencePointer(new DataView(bytes.buffer, 0x10, 4), PE32_POINTER_BYTES);
  const pe32Plus = await readReferencePointerValue(
    new MockFile(bytes, "pointer-slots.bin"), rawMapping(bytes.length), IMAGE_BASE,
    PE32_PLUS_POINTER_BYTES, warnings, notes, "slot", IMAGE_BASE + 0x20n
  );

  assert.equal(pe32, 0x12345678n);
  assert.equal(pe32Plus?.value, 0x140001000n);
  assert.equal(referencePointerRva(IMAGE_BASE, warnings, "bad", IMAGE_BASE - 1n), null);
  assert.equal(referencePointerRva(IMAGE_BASE, warnings, "zero", 0n), null);
  assert.ok(warnings.some(warning => warning.includes("bad pointer")));
  assert.ok(!warnings.some(warning => warning.includes("zero pointer")));
  const validWarnings: string[] = [];
  assert.equal(referencePointerRva(IMAGE_BASE, validWarnings, "valid", IMAGE_BASE + 1n), 1);
  assert.deepEqual(validWarnings, []);
});

void test("mappedRawSpan returns natural header and section-backed boundaries", () => {
  const section: PeSection = {
    name: inlinePeSectionName(".rdata"),
    virtualSize: 0x80,
    virtualAddress: 0x1000,
    sizeOfRawData: 0x60,
    pointerToRawData: 0x200,
    characteristics: 0
  };
  const rvaToOff = (rva: number): number | null => {
    if (rva < 0x100) return rva;
    if (rva >= 0x1000 && rva < 0x1060) return 0x200 + rva - 0x1000;
    return null;
  };

  const header = mappedRawSpan(0x300, [section], 0x100, rvaToOff, 0x40);
  const sectionSpan = mappedRawSpan(0x300, [section], 0x100, rvaToOff, 0x1020);
  const virtualTail = mappedRawSpan(0x300, [section], 0x100, rvaToOff, 0x1060);

  assert.deepEqual(header, [0x40, 0xc0]);
  assert.deepEqual(sectionSpan, [0x220, 0x40]);
  assert.equal(virtualTail, null);
});

void test("readMappedReferenceView follows contiguous RVAs across noncontiguous section data", async () => {
  const bytes = new Uint8Array(0x40).fill(0);
  bytes.set([1, 2], 0x22);
  bytes.set([3, 4], 0x30);
  const sections = [createTestSection(0x1000, 4, 4), createTestSection(0x1004, 4, 4, 0x30)];
  const view = await readMappedReferenceView(
    new MockFile(bytes, "split-rva-range.bin"),
    createPeRvaMapping(bytes.length, sections, 0, adjacentSectionRvaToOffset),
    [],
    [],
    "split range",
    0x1002,
    4
  );

  assert.deepEqual(Array.from(new Uint8Array(view?.buffer ?? new ArrayBuffer(0))), [1, 2, 3, 4]);
});

void test("mappedRawSpan rejects every header and section boundary failure mode", () => {
  const beforeSection = mappedRawSpan(0x100, [createTestSection(0x1000, 0x80, 0x60)], 0, () => 0, 0x0fff);
  const virtualEnd = mappedRawSpan(0x100, [createTestSection(0x1000, 0x20, 0x40)], 0, () => 0x40, 0x1030);
  const rawEnd = mappedRawSpan(0x100, [createTestSection(0x1000, 0x80, 0x40)], 0, () => 0x70, 0x1050);
  const exactVirtualEnd = mappedRawSpan(0x100, [createTestSection(0x1000, 0x20, 0x40)], 0, () => 0x40, 0x1020);
  const exactRawEnd = mappedRawSpan(0x100, [createTestSection(0x1000, 0x80, 0x40)], 0, () => 0x60, 0x1040);
  const rawFallback = mappedRawSpan(0x100, [createTestSection(0x1000, 0, 0x40)], 0, () => 0x30, 0x1010);
  const fileClamp = mappedRawSpan(0x30, [createTestSection(0x1000, 0x40, 0x40)], 0, () => 0x28, 0x1008);
  const shiftedHeader = mappedRawSpan(0x100, [], 0x80, () => 1, 0);
  const headerEnd = mappedRawSpan(0x100, [], 0x80, value => value, 0x80);
  const negativeOffset = mappedRawSpan(0x100, [], 0x80, () => -1, 0);
  const nonIntegerOffset = mappedRawSpan(0x100, [], 0x80, () => Number.NaN, 0);
  const endOffset = mappedRawSpan(0x100, [], 0x80, () => 0x100, 0);
  const zeroOffset = mappedRawSpan(0x100, [], 0x80, () => 0, 0);
  const negativeSectionOffset = mappedRawSpan(
    0x100, [createTestSection(0x1000, 0x20, 0x20)], 0, () => -1, 0x1000
  );
  const sectionEndOffset = mappedRawSpan(
    0x100, [createTestSection(0x1000, 0x20, 0x20)], 0, () => 0x100, 0x1000
  );

  assert.equal(beforeSection, null);
  assert.equal(virtualEnd, null);
  assert.equal(rawEnd, null);
  assert.equal(exactVirtualEnd, null);
  assert.equal(exactRawEnd, null);
  assert.deepEqual(rawFallback, [0x30, 0x30]);
  assert.deepEqual(fileClamp, [0x28, 8]);
  assert.equal(shiftedHeader, null);
  assert.equal(headerEnd, null);
  assert.equal(negativeOffset, null);
  assert.equal(nonIntegerOffset, null);
  assert.equal(endOffset, null);
  assert.deepEqual(zeroOffset, [0, 0x80]);
  assert.equal(negativeSectionOffset, null);
  assert.equal(sectionEndOffset, null);
});
